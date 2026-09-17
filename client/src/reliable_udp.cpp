#include "dz/client/reliable_udp.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>

#include "dz/endian.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

constexpr std::uint8_t kMagic[2] = {'D', 'Q'};

/// Tags separating the two directions of the punch handshake, so a probe cannot
/// be reflected back as its own answer.
constexpr const char* kPunchSenderTag = "drop-zone/v1 udp punch sender";
constexpr const char* kPunchReceiverTag = "drop-zone/v1 udp punch receiver";

/// How often to repeat probes while punching. Frequent enough that a mapping
/// created by the peer's first probe is still open when ours arrives, and sparse
/// enough not to look like a flood.
constexpr int kPunchIntervalMs = 50;

/// Deliver at most this much before the reorder buffer is considered abusive.
/// Bounds what a peer can make us hold by sending a window with a permanent hole.
constexpr std::size_t kMaxReorderPackets = 16384;

/// Bytes that may sit delivered but unread before delivery pauses.
///
/// This is the receive window, and it is enforced by simply not draining the reorder
/// buffer: the acknowledged sequence stops advancing, the sender's congestion window
/// fills, and it stops sending. No window field in the header is needed, and a
/// receiver whose application has stopped reading cannot be made to buffer without
/// limit.
constexpr std::size_t kMaxDeliveredBacklog = 8u * 1024 * 1024;

/// Assumed round trip before any measurement exists, for sizing the pacing rate.
constexpr double kAssumedRttUs = 1000.0;

void write_header(std::uint8_t* out, UdpPacketType type, std::uint32_t sequence, std::uint32_t ack,
                  std::uint64_t ack_bits, std::uint16_t length) {
    out[0] = kMagic[0];
    out[1] = kMagic[1];
    out[2] = static_cast<std::uint8_t>(type);
    out[3] = 0;
    store_u32(out + 4, sequence);
    store_u32(out + 8, ack);
    store_u64(out + 12, ack_bits);
    store_u16(out + 20, length);
}

struct ParsedHeader {
    UdpPacketType type;
    std::uint32_t sequence;
    std::uint32_t ack;
    std::uint64_t ack_bits;
    std::uint16_t length;
};

bool parse_header(const std::uint8_t* data, std::size_t len, ParsedHeader& out) {
    if (len < kUdpHeaderSize) return false;
    if (data[0] != kMagic[0] || data[1] != kMagic[1]) return false;

    out.type = static_cast<UdpPacketType>(data[2]);
    out.sequence = load_u32(data + 4);
    out.ack = load_u32(data + 8);
    out.ack_bits = load_u64(data + 12);
    out.length = load_u16(data + 20);

    if (out.length > kUdpMaxPayload) return false;
    if (len < kUdpHeaderSize + out.length) return false;
    return true;
}

void punch_proof(const Key& key, const char* tag, std::uint8_t out[kSha256Size]) {
    hmac_sha256(key.data(), key.size(), tag, std::strlen(tag), out);
}

}  // namespace

// ---------------------------------------------------------------------------
// Hole punching
// ---------------------------------------------------------------------------

bool punch_udp_path(int socket_fd, const std::vector<Endpoint>& raw_candidates,
                    const Key& handshake_key, bool is_sender, std::uint32_t budget_ms,
                    Endpoint& chosen) {
    // The receive loop below drains the socket until it reports EAGAIN, which only
    // happens on a non-blocking socket. On a blocking one, a datagram that fails its
    // proof check -- a stray packet, or a peer with the wrong key -- would leave the
    // loop waiting forever for a second one that never comes.
    set_nonblocking(socket_fd, true);

    // The socket has one address family for its whole life while the candidate list
    // mixes both, so every target is converted into a form this socket can reach
    // and anything that cannot be reconciled is dropped here rather than failing
    // once per probe round.
    int family = local_endpoint(socket_fd).family();

    std::vector<Endpoint> candidates;
    candidates.reserve(raw_candidates.size());
    for (const Endpoint& candidate : raw_candidates) {
        Endpoint adapted;
        if (adapt_endpoint_for_socket(candidate, family, adapted)) candidates.push_back(adapted);
    }

    std::uint8_t own_proof[kSha256Size];
    std::uint8_t expected_proof[kSha256Size];
    punch_proof(handshake_key, is_sender ? kPunchSenderTag : kPunchReceiverTag, own_proof);
    punch_proof(handshake_key, is_sender ? kPunchReceiverTag : kPunchSenderTag, expected_proof);

    std::uint8_t probe[kUdpHeaderSize + kSha256Size];
    write_header(probe, UdpPacketType::Punch, 0, 0, 0, kSha256Size);
    std::memcpy(probe + kUdpHeaderSize, own_proof, kSha256Size);

    std::uint8_t reply[kUdpHeaderSize + kSha256Size];
    write_header(reply, UdpPacketType::PunchAck, 0, 0, 0, kSha256Size);
    std::memcpy(reply + kUdpHeaderSize, own_proof, kSha256Size);

    std::uint64_t deadline = monotonic_millis() + budget_ms;
    std::uint64_t next_probe = 0;

    // A candidate that answered a probe but has not yet answered our own probe.
    // Waiting for both directions means neither peer commits to a path the other
    // cannot use.
    bool peer_seen = false;
    Endpoint peer_address;

    while (monotonic_millis() < deadline) {
        std::uint64_t now = monotonic_millis();

        if (now >= next_probe) {
            // Probe every candidate on every round rather than trying them in
            // turn: a NAT mapping opened by one round has to still be open when
            // the peer's probe arrives, so spreading the attempts out would work
            // against us.
            for (const Endpoint& candidate : candidates) {
                (void)::sendto(socket_fd, probe, sizeof(probe), 0, candidate.sockaddr_ptr(),
                               candidate.sockaddr_len());
            }
            if (peer_seen) {
                (void)::sendto(socket_fd, reply, sizeof(reply), 0, peer_address.sockaddr_ptr(),
                               peer_address.sockaddr_len());
            }
            next_probe = now + kPunchIntervalMs;
        }

        if (!wait_readable(socket_fd, kPunchIntervalMs)) continue;

        for (;;) {
            std::uint8_t datagram[kUdpDatagramSize];
            sockaddr_storage storage{};
            socklen_t length = sizeof(storage);

            ssize_t got = ::recvfrom(socket_fd, datagram, sizeof(datagram), 0,
                                     reinterpret_cast<sockaddr*>(&storage), &length);
            if (got < 0) {
                if (errno == EINTR) continue;
                break;  // EAGAIN.
            }

            ParsedHeader header;
            if (!parse_header(datagram, static_cast<std::size_t>(got), header)) continue;
            if (header.type != UdpPacketType::Punch && header.type != UdpPacketType::PunchAck) {
                continue;
            }
            if (header.length != kSha256Size) continue;

            // Only a peer holding the session's handshake key can produce this,
            // so a stray packet -- or a scanner -- cannot be adopted as the peer.
            if (!constant_time_equal(datagram + kUdpHeaderSize, expected_proof, kSha256Size)) {
                continue;
            }

            Endpoint from = Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), length);

            if (header.type == UdpPacketType::PunchAck) {
                // The peer has seen our probe, so the path works in both
                // directions.
                chosen = from;
                log::debug("UDP punch: path confirmed with " + from.to_string());
                return true;
            }

            // A probe. Answer it, and remember where from so later rounds keep
            // answering until one of our answers gets through.
            peer_seen = true;
            peer_address = from;
            std::memcpy(reply + kUdpHeaderSize, own_proof, kSha256Size);
            (void)::sendto(socket_fd, reply, sizeof(reply), 0, from.sockaddr_ptr(),
                           from.sockaddr_len());
        }
    }

    if (peer_seen) {
        // Probes arrived but none of our answers were confirmed. The inbound
        // direction demonstrably works, which is enough to proceed: the reliable
        // layer's own retransmission will establish whether the outbound one does.
        chosen = peer_address;
        log::debug("UDP punch: heard from " + peer_address.to_string() +
                   " without confirmation, trying it anyway");
        return true;
    }

    log::debug("UDP punch: no candidate answered");
    return false;
}

// ---------------------------------------------------------------------------
// ReliableUdpChannel
// ---------------------------------------------------------------------------

ReliableUdpChannel::ReliableUdpChannel(Fd socket, Endpoint peer, UdpTuning tuning)
    : socket_(std::move(socket)), peer_(std::move(peer)), tuning_(tuning) {
    cwnd_ = tuning_.initial_cwnd;
    ssthresh_ = tuning_.max_cwnd;
    rto_us_ = tuning_.initial_rto_us;

    set_nonblocking(socket_.get(), true);

    // A generous receive buffer is what stops the kernel dropping a burst while
    // this thread is busy decrypting; the send buffer matters less because pacing
    // already spreads the window out.
    set_socket_buffers(socket_.get(), 8 * 1024 * 1024);

    // Everything the batched syscalls need, allocated once.
    std::size_t batch = tuning_.batch_size;
    send_batch_.reserve(batch);
    control_staging_.resize(kUdpHeaderSize * batch);
    receive_storage_.resize(kUdpDatagramSize * batch);
    receive_lengths_.resize(batch);

#if defined(DZ_PLATFORM_LINUX)
    receive_messages_.resize(batch);
    receive_vectors_.resize(batch);
    receive_addresses_.resize(batch);
    send_messages_.resize(batch);
    send_vectors_.resize(batch);
#endif

    // The delivered-bytes buffer is sized for the flow-control limit up front, so a
    // transfer never pauses to reallocate and copy several megabytes -- which stalls
    // acknowledgements long enough to trigger spurious retransmission timeouts.
    delivered_.reserve(kMaxDeliveredBacklog + kUdpMaxPayload);
}

ReliableUdpChannel::~ReliableUdpChannel() = default;

std::string ReliableUdpChannel::describe() const {
    return "hole-punched UDP to " + peer_.to_string();
}

// -- Public byte interface --------------------------------------------------

void ReliableUdpChannel::write_bytes(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    outgoing_.insert(outgoing_.end(), bytes, bytes + len);

    // Drive the protocol until everything handed in has at least been put on the
    // wire. This is what applies back-pressure to the data plane: a caller cannot
    // outrun the congestion window because its write does not return until the
    // window has carried the bytes away.
    while (outgoing_consumed_ < outgoing_.size()) {
        pump(PumpIntent::SendOnly, 50);
    }

    // Reclaim the buffer now that it is drained, rather than letting it grow to
    // the size of the largest chunk ever written and stay there.
    outgoing_.clear();
    outgoing_consumed_ = 0;
}

void ReliableUdpChannel::read_exactly(void* data, std::size_t len) {
    // Drain the socket and acknowledge before serving anything out of the buffer.
    //
    // Without this a receiver that already holds what the caller asked for returns
    // without touching the socket at all, so it stops acknowledging for as long as its
    // backlog lasts. The sender's window fills, it hears nothing, and it waits out a
    // retransmission timeout -- which measured as the majority of a transfer's
    // duration. The pump is non-blocking, so the cost when there is nothing to do is
    // two syscalls.
    pump(PumpIntent::AwaitData, 0);

    auto* out = static_cast<std::uint8_t*>(data);
    std::size_t copied = 0;

    while (copied < len) {
        std::size_t available = delivered_.size() - delivered_consumed_;
        if (available > 0) {
            std::size_t take = std::min(available, len - copied);
            std::memcpy(out + copied, delivered_.data() + delivered_consumed_, take);
            delivered_consumed_ += take;
            copied += take;

            if (delivered_consumed_ == delivered_.size()) {
                delivered_.clear();
                delivered_consumed_ = 0;
            }
            continue;
        }

        if (peer_finished_ && reorder_buffer_.empty()) throw PeerClosed();

        pump(PumpIntent::AwaitData, 200);
    }
}

void ReliableUdpChannel::flush() {
    // Everything queued has to be acknowledged, not merely sent, before this
    // returns: the caller is about to treat the data as delivered.
    while (outgoing_consumed_ < outgoing_.size() || !unacknowledged_.empty()) {
        pump(PumpIntent::AwaitAcks, 200);
    }
    flush_send_batch();
}

void ReliableUdpChannel::close_gracefully() {
    try {
        flush();

        sent_fin_ = true;
        std::uint64_t deadline = monotonic_millis() + 2000;
        while (!fin_acknowledged_ && monotonic_millis() < deadline) {
            send_control(UdpPacketType::Fin);
            flush_send_batch();
            pump(PumpIntent::AwaitAcks, 100);
        }
    } catch (const Error&) {
        // A failure while closing is not worth propagating: the transfer itself
        // has already succeeded or failed on its own terms.
    }
}

// -- Protocol engine --------------------------------------------------------

void ReliableUdpChannel::pump(PumpIntent intent, int max_wait_ms) {
    std::uint64_t now_us = monotonic_micros();

    retransmit_timed_out(now_us);
    fill_window();
    flush_send_batch();

    receive_batch();
    deliver_in_order();

    if (ack_pending_) {
        send_ack();
        flush_send_batch();
        ack_pending_ = false;
    }

    // Decide whether sleeping is the right thing to do, which depends entirely on
    // what the caller is waiting for.
    now_us = monotonic_micros();

    bool has_more_to_send = outgoing_consumed_ < outgoing_.size();
    bool paced_out = send_tokens_ < 1.0;
    bool window_full = static_cast<double>(unacknowledged_.size()) >= cwnd_;

    bool should_wait = false;
    switch (intent) {
        case PumpIntent::SendOnly:
            // Only worth waiting if something is actually holding the sender back.
            // Waiting because there is nothing left to send would add the whole
            // timeout to every write -- measured as most of a transfer's duration,
            // since the data plane writes a megabyte at a time and each write ended
            // in a needless sleep.
            should_wait = has_more_to_send && (window_full || paced_out);
            break;
        case PumpIntent::AwaitData:
            should_wait = delivered_consumed_ >= delivered_.size() && !peer_finished_;
            break;
        case PumpIntent::AwaitAcks:
            should_wait = has_more_to_send || !unacknowledged_.empty();
            break;
    }

    if (!should_wait || max_wait_ms <= 0) return;

    std::uint64_t wait_us = static_cast<std::uint64_t>(max_wait_ms) * 1000;

    if (!unacknowledged_.empty()) {
        wait_us = std::min(wait_us, time_until_rto_us(now_us));
    }
    if (paced_out && has_more_to_send && !window_full) {
        wait_us = std::min(wait_us, time_until_token_us());
    }

    // Microsecond resolution matters here: a pacing wait is often tens of
    // microseconds, and rounding it up to poll()'s one-millisecond granularity would
    // cap the transport at roughly the burst size per millisecond.
    if (wait_us < 1) wait_us = 1;
    (void)wait_readable_micros(socket_.get(), wait_us);
}

double ReliableUdpChannel::refill_pacing_tokens(std::uint64_t now_us) {
    if (last_token_us_ == 0) {
        last_token_us_ = now_us;
        send_tokens_ = tuning_.max_burst;
        return send_tokens_;
    }

    double elapsed_us = static_cast<double>(now_us - last_token_us_);
    last_token_us_ = now_us;

    // cwnd packets per round trip is the rate the congestion window authorises.
    double rtt_us = (srtt_us_ > 0) ? static_cast<double>(srtt_us_) : kAssumedRttUs;
    double packets_per_us = cwnd_ / rtt_us;

    send_tokens_ += elapsed_us * packets_per_us;
    if (send_tokens_ > tuning_.max_burst) send_tokens_ = tuning_.max_burst;
    return send_tokens_;
}

std::uint64_t ReliableUdpChannel::time_until_token_us() const {
    if (send_tokens_ >= 1.0) return 0;

    double rtt_us = (srtt_us_ > 0) ? static_cast<double>(srtt_us_) : kAssumedRttUs;
    double packets_per_us = cwnd_ / rtt_us;
    if (packets_per_us <= 0.0) return 1000;

    return static_cast<std::uint64_t>((1.0 - send_tokens_) / packets_per_us) + 1;
}

void ReliableUdpChannel::fill_window() {
    std::uint64_t now_us = monotonic_micros();
    refill_pacing_tokens(now_us);

    while (outgoing_consumed_ < outgoing_.size()) {
        if (static_cast<double>(unacknowledged_.size()) >= cwnd_) break;

        // Pacing. Releasing a whole window at line rate is what overruns the
        // receiver's socket buffer, so a packet only goes out if the bucket has a
        // token for it.
        if (send_tokens_ < 1.0) break;
        send_tokens_ -= 1.0;

        std::size_t remaining = outgoing_.size() - outgoing_consumed_;
        std::size_t payload = std::min(remaining, kUdpMaxPayload);

        SentPacket packet;
        packet.sequence = next_sequence_++;
        packet.datagram.resize(kUdpHeaderSize + payload);
        write_header(packet.datagram.data(), UdpPacketType::Data, packet.sequence, receive_next_, 0,
                     static_cast<std::uint16_t>(payload));
        std::memcpy(packet.datagram.data() + kUdpHeaderSize, outgoing_.data() + outgoing_consumed_,
                    payload);
        packet.sent_us = now_us;

        outgoing_consumed_ += payload;

        // Stored first, then queued by reference: the datagram the kernel reads is
        // the same one kept for retransmission, so a packet is built once rather
        // than copied into a staging buffer on its way out.
        unacknowledged_.push_back(std::move(packet));
        const SentPacket& stored = unacknowledged_.back();
        queue_send(stored.datagram.data(), stored.datagram.size());
    }
}

void ReliableUdpChannel::retransmit_timed_out(std::uint64_t now_us) {
    if (unacknowledged_.empty()) return;

    SentPacket& oldest = unacknowledged_.front();
    if (now_us - oldest.sent_us < rto_us_) return;

    ++consecutive_timeouts_;
    ++stats_.timeouts;

    if (consecutive_timeouts_ > tuning_.max_timeouts) {
        fail("the peer stopped responding after " + std::to_string(consecutive_timeouts_) +
             " retransmission timeouts");
    }

    // Standard response to a timeout: assume the path is much worse than
    // believed, drop to the minimum window, and double the timer so a genuinely
    // slow path is not hammered.
    ssthresh_ = std::max(tuning_.min_cwnd, cwnd_ / 2.0);
    cwnd_ = tuning_.min_cwnd;
    cwnd_fraction_ = 0.0;
    rto_us_ = std::min(tuning_.max_rto_us, rto_us_ * 2);

    // Drop any accumulated allowance too: releasing a burst immediately after
    // deciding the path is congested defeats the point of shrinking the window.
    send_tokens_ = 0.0;

    // Resend the oldest packet only. If more are lost, the next timeout or the
    // selective acknowledgements will find them, and resending the whole window
    // would repeat the burst that caused the loss.
    oldest.sent_us = now_us;
    ++oldest.transmissions;
    ++stats_.packets_retransmitted;

    // Refresh the piggybacked acknowledgement so a retransmission also carries
    // current receive state.
    write_header(oldest.datagram.data(), UdpPacketType::Data, oldest.sequence, receive_next_, 0,
                 static_cast<std::uint16_t>(oldest.datagram.size() - kUdpHeaderSize));
    queue_send(oldest.datagram.data(), oldest.datagram.size());
}

void ReliableUdpChannel::receive_batch() {
    const std::size_t batch = tuning_.batch_size;

#if defined(DZ_PLATFORM_LINUX)
    // One recvmmsg replaces up to batch_size recvfrom calls. At 1200 bytes per
    // datagram that is the difference between a syscall every 1.2 KB and one every
    // 76 KB.
    for (;;) {
        for (std::size_t i = 0; i < batch; ++i) {
            receive_vectors_[i].iov_base = receive_storage_.data() + i * kUdpDatagramSize;
            receive_vectors_[i].iov_len = kUdpDatagramSize;

            std::memset(&receive_messages_[i], 0, sizeof(receive_messages_[i]));
            receive_messages_[i].msg_hdr.msg_iov = &receive_vectors_[i];
            receive_messages_[i].msg_hdr.msg_iovlen = 1;
            receive_messages_[i].msg_hdr.msg_name = &receive_addresses_[i];
            receive_messages_[i].msg_hdr.msg_namelen = sizeof(receive_addresses_[i]);
        }

        int count = ::recvmmsg(socket_.get(), receive_messages_.data(),
                               static_cast<unsigned>(batch), 0, nullptr);
        if (count < 0) {
            if (errno == EINTR) continue;
            return;  // EAGAIN: nothing left to read.
        }
        if (count == 0) return;

        for (int i = 0; i < count; ++i) {
            auto index = static_cast<std::size_t>(i);
            process_packet(receive_storage_.data() + index * kUdpDatagramSize,
                           receive_messages_[index].msg_len);
        }

        // A partly filled batch means the queue is drained.
        if (static_cast<std::size_t>(count) < batch) return;

        // Stop after one full batch if the application is not keeping up, so a fast
        // peer cannot hold this loop indefinitely.
        if (delivered_.size() - delivered_consumed_ >= kMaxDeliveredBacklog) return;
    }
#else
    for (;;) {
        std::size_t received = 0;
        for (; received < batch; ++received) {
            std::uint8_t* slot = receive_storage_.data() + received * kUdpDatagramSize;
            ssize_t got = ::recv(socket_.get(), slot, kUdpDatagramSize, 0);
            if (got < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (got == 0) break;
            receive_lengths_[received] = static_cast<std::size_t>(got);
        }

        for (std::size_t i = 0; i < received; ++i) {
            process_packet(receive_storage_.data() + i * kUdpDatagramSize, receive_lengths_[i]);
        }

        if (received < batch) return;
        if (delivered_.size() - delivered_consumed_ >= kMaxDeliveredBacklog) return;
    }
#endif
}

void ReliableUdpChannel::process_packet(const std::uint8_t* data, std::size_t len) {
    ParsedHeader header;
    if (!parse_header(data, len, header)) return;

    ++stats_.packets_received;
    std::uint64_t now_us = monotonic_micros();

    // Every packet carries acknowledgement state, so a data packet flowing the
    // other way also advances this side's send window without a separate ACK.
    process_ack(header.ack, header.ack_bits, now_us);

    switch (header.type) {
        case UdpPacketType::Data: {
            // Sequence numbers are compared as signed differences so the
            // comparison stays correct when the 32-bit counter wraps.
            auto distance = static_cast<std::int32_t>(header.sequence - receive_next_);

            if (distance < 0) {
                // Already delivered; the peer retransmitted unnecessarily. Ack so
                // it stops.
                ++stats_.duplicates_received;
                ack_pending_ = true;
                return;
            }

            if (reorder_buffer_.size() >= kMaxReorderPackets) {
                fail("the peer sent more out-of-order data than the reorder buffer allows");
            }

            if (distance > 0) ++stats_.reordered_received;

            auto inserted = reorder_buffer_.emplace(
                header.sequence,
                std::vector<std::uint8_t>(data + kUdpHeaderSize,
                                          data + kUdpHeaderSize + header.length));
            if (!inserted.second) ++stats_.duplicates_received;

            ack_pending_ = true;
            return;
        }

        case UdpPacketType::Ack:
            return;  // Already handled by process_ack above.

        case UdpPacketType::Fin:
            peer_finished_ = true;
            send_control(UdpPacketType::FinAck);
            return;

        case UdpPacketType::FinAck:
            fin_acknowledged_ = true;
            return;

        case UdpPacketType::Punch:
        case UdpPacketType::PunchAck:
            // A probe that arrived after punching finished. Harmless.
            return;
    }
}

void ReliableUdpChannel::process_ack(std::uint32_t ack, std::uint64_t ack_bits,
                                     std::uint64_t now_us) {
    bool progressed = false;
    unsigned newly_acknowledged = 0;

    // Everything below `ack` is confirmed delivered.
    while (!unacknowledged_.empty()) {
        SentPacket& front = unacknowledged_.front();
        if (static_cast<std::int32_t>(front.sequence - ack) >= 0) break;

        // Only a packet sent once gives a usable RTT sample: for a retransmitted
        // one there is no way to tell which copy was acknowledged, and taking the
        // sample anyway is how an estimator gets fooled into shrinking.
        if (front.transmissions == 1) update_rtt(now_us - front.sent_us);

        unacknowledged_.pop_front();
        ++newly_acknowledged;
        progressed = true;
    }

    send_base_ = ack;

    // The bitmap covers the 64 sequences after the gap. Marking them lets a
    // single loss be retransmitted without waiting for a timeout.
    unsigned acknowledged_beyond_gap = 0;
    for (SentPacket& packet : unacknowledged_) {
        auto offset = static_cast<std::int32_t>(packet.sequence - ack);
        if (offset < 1 || offset > 64) continue;

        if ((ack_bits >> (offset - 1)) & 1u) {
            if (!packet.acknowledged) {
                packet.acknowledged = true;
                ++newly_acknowledged;
            }
            ++acknowledged_beyond_gap;
        }
    }

    if (newly_acknowledged > 0) consecutive_timeouts_ = 0;

    // Grow the window. Slow start doubles per RTT; past the threshold the growth
    // becomes one packet per RTT, which is what keeps a long-lived flow from
    // repeatedly overshooting.
    for (unsigned i = 0; i < newly_acknowledged; ++i) {
        if (cwnd_ < ssthresh_) {
            cwnd_ += 1.0;
        } else {
            cwnd_fraction_ += 1.0 / cwnd_;
            if (cwnd_fraction_ >= 1.0) {
                cwnd_ += 1.0;
                cwnd_fraction_ -= 1.0;
            }
        }
    }
    if (cwnd_ > tuning_.max_cwnd) cwnd_ = tuning_.max_cwnd;

    // Three packets acknowledged beyond the gap is the classic signal that the
    // one at the gap was lost rather than merely delayed.
    if (acknowledged_beyond_gap >= tuning_.fast_retransmit_threshold && !unacknowledged_.empty()) {
        SentPacket& missing = unacknowledged_.front();
        if (!missing.acknowledged && now_us - missing.sent_us > srtt_us_ / 2) {
            on_loss();

            missing.sent_us = now_us;
            ++missing.transmissions;
            ++stats_.packets_retransmitted;
            write_header(missing.datagram.data(), UdpPacketType::Data, missing.sequence,
                         receive_next_, 0,
                         static_cast<std::uint16_t>(missing.datagram.size() - kUdpHeaderSize));
            queue_send(missing.datagram.data(), missing.datagram.size());
        }
    }

    (void)progressed;
}

void ReliableUdpChannel::deliver_in_order() {
    // Hand over every packet that has become contiguous, stopping at the first
    // gap. This is where datagrams become a stream.
    for (;;) {
        // Flow control: stop draining once the application is this far behind.
        // Because the acknowledged sequence stops advancing with it, the sender's
        // window fills and it stops sending, without the header needing a window
        // field.
        if (delivered_.size() - delivered_consumed_ >= kMaxDeliveredBacklog) break;

        auto next = reorder_buffer_.find(receive_next_);
        if (next == reorder_buffer_.end()) break;

        delivered_.insert(delivered_.end(), next->second.begin(), next->second.end());
        reorder_buffer_.erase(next);
        ++receive_next_;
    }

    // Compact once the read cursor has passed most of the buffer.
    if (delivered_consumed_ > 0 && delivered_consumed_ >= delivered_.size() / 2) {
        delivered_.erase(delivered_.begin(),
                         delivered_.begin() + static_cast<std::ptrdiff_t>(delivered_consumed_));
        delivered_consumed_ = 0;
    }
}

void ReliableUdpChannel::send_ack() {
    // Build the selective-acknowledgement bitmap from what is sitting past the
    // gap in the reorder buffer.
    std::uint64_t bits = 0;
    for (const auto& entry : reorder_buffer_) {
        auto offset = static_cast<std::int32_t>(entry.first - receive_next_);
        if (offset >= 1 && offset <= 64) bits |= (1ull << (offset - 1));
    }

    std::uint8_t datagram[kUdpHeaderSize];
    write_header(datagram, UdpPacketType::Ack, 0, receive_next_, bits, 0);
    transmit(datagram, sizeof(datagram));
}

void ReliableUdpChannel::send_control(UdpPacketType type) {
    std::uint8_t datagram[kUdpHeaderSize];
    write_header(datagram, type, 0, receive_next_, 0, 0);
    transmit(datagram, sizeof(datagram));
}

void ReliableUdpChannel::transmit(const std::uint8_t* datagram, std::size_t len) {
    // Control packets are copied into the fixed staging area, because the caller's
    // buffer is on its stack and will be gone before the batch is flushed. Data
    // packets are already stored in unacknowledged_ and are queued by reference
    // through queue_send.
    if (control_used_ + len > control_staging_.size()) flush_send_batch();

    std::uint8_t* slot = control_staging_.data() + control_used_;
    std::memcpy(slot, datagram, len);
    control_used_ += len;

    queue_send(slot, len);
}

void ReliableUdpChannel::queue_send(const std::uint8_t* data, std::size_t length) {
    if (test_loss_rate_ > 0.0) {
        // Deterministic thinning rather than a random draw, so a test that fails
        // fails the same way every time.
        ++test_loss_counter_;
        auto every = static_cast<std::uint64_t>(1.0 / test_loss_rate_);
        if (every > 0 && test_loss_counter_ % every == 0) {
            ++stats_.packets_sent;
            return;
        }
    }

    send_batch_.push_back(PendingSend{data, length});

    if (send_batch_.size() >= tuning_.batch_size) flush_send_batch();
}

void ReliableUdpChannel::flush_send_batch() {
    if (send_batch_.empty()) return;

    // A full kernel send buffer must not become a dropped packet.
    //
    // Discarding the rest of the batch on EAGAIN looks harmless -- this is an
    // unreliable transport and the retransmission timer would eventually recover --
    // but it is loss this side inflicted on itself, and it lands on the tail of the
    // window where there are no later packets to acknowledge. Selective
    // acknowledgement cannot see it, so recovery costs a full retransmission timeout
    // per drop. Measured on loopback, that alone held the transport to about four
    // megabytes a second.
    //
    // So the buffer being full is treated as back-pressure: wait briefly for room,
    // and if there is still none, keep the unsent datagrams for the next flush.
    std::size_t sent = 0;
    int stalls = 0;

    while (sent < send_batch_.size()) {
#if defined(DZ_PLATFORM_LINUX)
        std::size_t batch = send_batch_.size() - sent;

        for (std::size_t i = 0; i < batch; ++i) {
            const PendingSend& pending = send_batch_[sent + i];
            send_vectors_[i].iov_base = const_cast<std::uint8_t*>(pending.data);
            send_vectors_[i].iov_len = pending.length;

            std::memset(&send_messages_[i], 0, sizeof(send_messages_[i]));
            send_messages_[i].msg_hdr.msg_iov = &send_vectors_[i];
            send_messages_[i].msg_hdr.msg_iovlen = 1;
            send_messages_[i].msg_hdr.msg_name = const_cast<sockaddr*>(peer_.sockaddr_ptr());
            send_messages_[i].msg_hdr.msg_namelen = peer_.sockaddr_len();
        }

        int count =
            ::sendmmsg(socket_.get(), send_messages_.data(), static_cast<unsigned>(batch), 0);
#else
        const PendingSend& pending = send_batch_[sent];
        ssize_t written = ::sendto(socket_.get(), pending.data, pending.length, 0,
                                   peer_.sockaddr_ptr(), peer_.sockaddr_len());
        int count = (written < 0) ? -1 : 1;
#endif

        if (count > 0) {
            sent += static_cast<std::size_t>(count);
            stats_.packets_sent += static_cast<std::uint64_t>(count);
            continue;
        }

        if (errno == EINTR) continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Two short waits, then give up for this round. Holding on longer would
            // stop the receive path from running, and the acknowledgements arriving
            // there are what will free the window anyway.
            if (++stalls > 2) break;
            (void)wait_writable(socket_.get(), 1);
            continue;
        }

        // ECONNREFUSED here is an ICMP port-unreachable from an earlier datagram,
        // which is informational on an unconnected socket: the peer may simply not
        // have finished binding yet.
        if (errno == ECONNREFUSED) {
            ++sent;
            continue;
        }

        fail_errno("sending to the peer failed");
    }

    // Keep whatever did not go out, so it is retried rather than lost.
    send_batch_.erase(send_batch_.begin(), send_batch_.begin() + static_cast<std::ptrdiff_t>(sent));

    // The staging area can only be reused once nothing still points into it.
    if (send_batch_.empty()) control_used_ = 0;
}

void ReliableUdpChannel::update_rtt(std::uint64_t sample_us) {
    // RFC 6298's estimator. The variance term is what keeps the timer above the
    // noise on a jittery path instead of firing spuriously.
    if (srtt_us_ == 0) {
        srtt_us_ = sample_us;
        rttvar_us_ = sample_us / 2;
    } else {
        std::uint64_t difference =
            (sample_us > srtt_us_) ? (sample_us - srtt_us_) : (srtt_us_ - sample_us);
        rttvar_us_ = (3 * rttvar_us_ + difference) / 4;
        srtt_us_ = (7 * srtt_us_ + sample_us) / 8;
    }

    rto_us_ = srtt_us_ + 4 * rttvar_us_;
    rto_us_ = std::clamp(rto_us_, tuning_.min_rto_us, tuning_.max_rto_us);
    stats_.smoothed_rtt_us = srtt_us_;
}

void ReliableUdpChannel::on_loss() {
    // Multiplicative decrease. Halving rather than collapsing, because a loss
    // detected by selective acknowledgement means packets are still getting
    // through.
    ssthresh_ = std::max(tuning_.min_cwnd, cwnd_ / 2.0);
    cwnd_ = ssthresh_;
    cwnd_fraction_ = 0.0;
}

std::uint64_t ReliableUdpChannel::time_until_rto_us(std::uint64_t now_us) const {
    if (unacknowledged_.empty()) return rto_us_;

    std::uint64_t elapsed = now_us - unacknowledged_.front().sent_us;
    return (elapsed >= rto_us_) ? 0 : (rto_us_ - elapsed);
}

}  // namespace dz::client
