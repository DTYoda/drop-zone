// A reliable byte stream over UDP, for the hole-punched tier.
//
// Once two peers have punched a UDP path to each other they have datagrams, which
// may be lost, duplicated or reordered. The data plane wants a stream. This is the
// layer in between.
//
// It is not QUIC and does not pretend to be. What it implements, and why:
//
//   Sequencing and a reorder buffer. Packets carry a sequence number; the
//   receiver delivers them in order and holds early arrivals until the gap fills.
//
//   Selective acknowledgement. Every ACK carries the highest contiguous sequence
//   received plus a 64-bit bitmap of what arrived after the gap. One lost packet
//   in the middle of a full window therefore costs one retransmission rather than
//   a whole window's worth, which a cumulative-only ACK would force.
//
//   Retransmission on a smoothed-RTT timer, following RFC 6298's estimator, plus
//   fast retransmit when the bitmap shows three later packets have arrived. The
//   fast path is what keeps a single loss from costing a whole RTO.
//
//   NewReno congestion control: slow start to a threshold, then additive
//   increase, halving on loss. Without it, a sender on a fast machine simply
//   overruns a slower path and spends the transfer retransmitting.
//
//   Paced sending. Releasing a whole window at line rate is what makes a router
//   drop a burst of it; spreading the window over the RTT avoids that.
//
// On Linux, sendmmsg and recvmmsg move up to 64 datagrams per syscall. At a
// 1200-byte MTU a gigabyte is roughly 890,000 packets, so batching is the
// difference between 890,000 syscalls per gigabyte and 14,000.

#pragma once

#include <sys/socket.h>
#include <sys/uio.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "dz/client/channel.hpp"
#include "dz/crypto.hpp"
#include "dz/socket.hpp"

namespace dz::client {

/// Total datagram size, headers included.
///
/// 1200 bytes is the figure QUIC settled on: small enough to cross essentially
/// every path without fragmentation, including tunnels that eat into the usual
/// 1500-byte Ethernet MTU, and large enough that the per-packet overhead is
/// under 2%.
constexpr std::size_t kUdpDatagramSize = 1200;

/// Wire header on every packet.
///
///   offset size field
///   0      2    magic 'D','Q'
///   2      1    type
///   3      1    flags
///   4      4    seq       sequence number of this data packet
///   8      4    ack       the next sequence the sender of this packet wants
///   12     8    ack_bits  bitmap of sequences received beyond `ack`
///   20     2    length    payload bytes that follow
constexpr std::size_t kUdpHeaderSize = 22;

constexpr std::size_t kUdpMaxPayload = kUdpDatagramSize - kUdpHeaderSize;

enum class UdpPacketType : std::uint8_t {
    Punch = 1,     ///< Hole-punching probe, carrying a proof of the session key.
    PunchAck = 2,  ///< Confirms a probe was seen and understood.
    Data = 3,
    Ack = 4,
    Fin = 5,     ///< No more data will be sent in this direction.
    FinAck = 6,
};

/// Congestion and timing constants, gathered so the behaviour is inspectable in
/// one place.
struct UdpTuning {
    /// Initial window in packets. Larger than TCP's usual ten because a drop-zone
    /// transfer is bulk data over a path the peers have just probed, and ten
    /// 1200-byte packets is only 12 KB of a window that will need to be thousands.
    double initial_cwnd = 32.0;
    double min_cwnd = 4.0;
    /// Ceiling on the window, which also bounds the retransmission buffer:
    /// 2048 * 1200 bytes is about 2.4 MiB in flight, enough to keep a 400 Mb/s path
    /// with a 50 ms round trip busy. Raising it further mostly buys overshoot: the
    /// window has to be refilled from a socket buffer the kernel will not usually
    /// grow past a couple of hundred kilobytes.
    double max_cwnd = 2048.0;

    /// Packets the pacer will release in one go.
    ///
    /// Pacing spreads a window over the round trip, and the point of a burst limit is
    /// that the receiving kernel's socket buffer is small -- typically 208 KB on Linux,
    /// which is about 170 datagrams. Dumping more than that between two of the
    /// receiver's drains overruns it, and the resulting loss lands on the tail of the
    /// window where selective acknowledgement cannot see it, so it costs a full
    /// retransmission timeout to recover.
    double max_burst = 48.0;

    /// Floor on the retransmission timer.
    ///
    /// RFC 6298 recommends a one-second minimum, which exists to keep TCP from
    /// treating a slow path as a lossy one and competing unfairly with other flows.
    /// That reasoning is weaker here: both ends are this program, selective
    /// acknowledgement recovers most losses without ever reaching the timer, and a
    /// floor far above the actual round trip turns each loss the bitmap cannot see
    /// into a visible stall. 5 ms is still an order of magnitude above a
    /// same-datacentre round trip.
    std::uint64_t min_rto_us = 5'000;
    std::uint64_t max_rto_us = 2'000'000;
    std::uint64_t initial_rto_us = 200'000;

    /// Later packets that must be acknowledged before a gap counts as a loss.
    unsigned fast_retransmit_threshold = 3;

    /// Consecutive retransmission timeouts before the path is declared dead.
    unsigned max_timeouts = 12;

    /// Datagrams per sendmmsg or recvmmsg call.
    unsigned batch_size = 64;
};

/// Statistics for the transfer summary and for the tests.
struct UdpStatistics {
    std::uint64_t packets_sent = 0;
    std::uint64_t packets_received = 0;
    std::uint64_t packets_retransmitted = 0;
    std::uint64_t duplicates_received = 0;
    std::uint64_t reordered_received = 0;
    std::uint64_t timeouts = 0;
    std::uint64_t smoothed_rtt_us = 0;
};

/// Punch a UDP path to one of `candidates`.
///
/// Sends authenticated probes to every candidate repeatedly for up to
/// `budget_ms`, and returns the address that answered. Repetition is the point:
/// the two peers start at slightly different moments, and each side's outbound
/// probe is what teaches its own NAT to accept the other's.
bool punch_udp_path(int socket_fd, const std::vector<Endpoint>& candidates, const Key& handshake_key,
                    bool is_sender, std::uint32_t budget_ms, Endpoint& chosen);

/// The reliable stream. Constructed after punch_udp_path has agreed an address.
class ReliableUdpChannel : public Channel {
public:
    ReliableUdpChannel(Fd socket, Endpoint peer, UdpTuning tuning = UdpTuning{});
    ~ReliableUdpChannel() override;

    TransportKind kind() const override { return TransportKind::HolePunchUdp; }
    std::string describe() const override;

    void read_exactly(void* data, std::size_t len) override;
    void write_bytes(const void* data, std::size_t len) override;
    void flush() override;
    void close_gracefully() override;

    const UdpStatistics& statistics() const { return stats_; }

    /// Drop a fraction of outgoing packets on purpose, so the tests can watch
    /// retransmission and congestion control actually work. Zero in normal use.
    void set_test_loss_rate(double rate) { test_loss_rate_ = rate; }

private:
    /// One packet still awaiting acknowledgement.
    struct SentPacket {
        std::uint32_t sequence = 0;
        std::vector<std::uint8_t> datagram;  ///< Header and payload, ready to resend.
        std::uint64_t sent_us = 0;
        unsigned transmissions = 1;
        bool acknowledged = false;
    };

    /// What the caller of pump is waiting for.
    ///
    /// pump does the same work whatever the intent; the intent decides only whether it
    /// is worth sleeping at the end. Without it, pump cannot tell "the caller has
    /// nothing left to send, let it return" from "the caller is blocked and should
    /// wait" -- and getting that wrong is expensive in both directions: sleeping
    /// needlessly stalls a transfer for the whole timeout, and not sleeping when
    /// blocked spins a core.
    enum class PumpIntent {
        SendOnly,   ///< write_bytes: wait only while the window or the pacer blocks it.
        AwaitData,  ///< read_exactly: wait until something has been delivered.
        AwaitAcks,  ///< flush: wait until everything sent has been acknowledged.
    };

    /// Move the protocol forward: send what the window allows, retransmit what has
    /// timed out, take in whatever has arrived, and acknowledge it.
    ///
    /// Everything happens here rather than on a background thread, because
    /// read_exactly and write_bytes are both blocking calls that can afford to
    /// drive the protocol themselves -- and a single-threaded protocol needs no
    /// locking on the hot path.
    void pump(PumpIntent intent, int max_wait_ms);

    void fill_window();
    void retransmit_timed_out(std::uint64_t now_us);
    void receive_batch();
    void process_packet(const std::uint8_t* data, std::size_t len);
    void process_ack(std::uint32_t ack, std::uint64_t ack_bits, std::uint64_t now_us);
    void deliver_in_order();
    void send_ack();
    void send_control(UdpPacketType type);
    void transmit(const std::uint8_t* datagram, std::size_t len);
    void flush_send_batch();
    void update_rtt(std::uint64_t sample_us);
    void on_loss();

    /// Packets the pacer currently authorises. Accrues tokens for the time elapsed
    /// since the last call.
    double refill_pacing_tokens(std::uint64_t now_us);

    /// Microseconds until the pacer will authorise another packet.
    std::uint64_t time_until_token_us() const;

    /// Microseconds until the oldest unacknowledged packet needs resending.
    std::uint64_t time_until_rto_us(std::uint64_t now_us) const;

    Fd socket_;
    Endpoint peer_;
    UdpTuning tuning_;
    UdpStatistics stats_;

    // -- Send side ----------------------------------------------------------
    std::vector<std::uint8_t> outgoing_;   ///< Application bytes not yet packetised.
    std::size_t outgoing_consumed_ = 0;
    std::deque<SentPacket> unacknowledged_; ///< Ordered by sequence.
    std::uint32_t next_sequence_ = 0;
    std::uint32_t send_base_ = 0;           ///< Lowest unacknowledged sequence.

    double cwnd_ = 0.0;
    double ssthresh_ = 0.0;
    /// Fractional carry for congestion avoidance, where the window grows by
    /// 1/cwnd per acknowledgement rather than by whole packets.
    double cwnd_fraction_ = 0.0;
    unsigned consecutive_timeouts_ = 0;

    std::uint64_t srtt_us_ = 0;
    std::uint64_t rttvar_us_ = 0;
    std::uint64_t rto_us_ = 0;

    /// Pacing, as a token bucket measured in packets.
    ///
    /// Tokens accrue at cwnd packets per round trip, which is the rate the congestion
    /// window authorises, and are capped at tuning_.max_burst so a sender that has
    /// been waiting cannot release the whole window at once. A deadline-based pacer
    /// would do the same job, but a bucket makes "how much may I send right now" a
    /// single number and the burst limit an explicit cap rather than an emergent
    /// property of the clock's resolution.
    double send_tokens_ = 0.0;
    std::uint64_t last_token_us_ = 0;

    // -- Receive side -------------------------------------------------------
    std::uint32_t receive_next_ = 0;  ///< Next sequence to deliver.
    std::map<std::uint32_t, std::vector<std::uint8_t>> reorder_buffer_;
    std::vector<std::uint8_t> delivered_;
    std::size_t delivered_consumed_ = 0;
    bool ack_pending_ = false;
    bool peer_finished_ = false;
    bool fin_acknowledged_ = false;
    bool sent_fin_ = false;

    // -- Batching -----------------------------------------------------------
    //
    // Everything a batch needs is allocated once, in the constructor, and reused for
    // the life of the channel. This is not premature: the buffers for one recvmmsg
    // call are batch_size times the datagram size, so allocating and zeroing them per
    // call -- which the obvious implementation does -- costs more than the syscall it
    // is preparing. Measured on loopback, hoisting them out roughly tripled the
    // transport's throughput.

    /// One datagram queued for sending, as a view rather than a copy.
    ///
    /// Data packets point at the datagram already held in unacknowledged_ for
    /// retransmission, so a packet is built once instead of being copied into a
    /// staging buffer on its way to the kernel. Control packets are staged in
    /// control_staging_, which is fixed size so the views into it stay valid.
    struct PendingSend {
        const std::uint8_t* data = nullptr;
        std::size_t length = 0;
    };

    void queue_send(const std::uint8_t* data, std::size_t length);

    std::vector<PendingSend> send_batch_;

    /// Room for the acknowledgements and control packets of one batch.
    std::vector<std::uint8_t> control_staging_;
    std::size_t control_used_ = 0;

    /// Preallocated scratch for the batched syscalls.
    std::vector<std::uint8_t> receive_storage_;
    std::vector<std::size_t> receive_lengths_;
#if defined(DZ_PLATFORM_LINUX)
    std::vector<struct mmsghdr> receive_messages_;
    std::vector<struct iovec> receive_vectors_;
    std::vector<sockaddr_storage> receive_addresses_;
    std::vector<struct mmsghdr> send_messages_;
    std::vector<struct iovec> send_vectors_;
#endif

    double test_loss_rate_ = 0.0;
    std::uint64_t test_loss_counter_ = 0;
};

}  // namespace dz::client
