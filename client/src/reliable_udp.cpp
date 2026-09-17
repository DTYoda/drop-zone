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

bool punch_udp_path(int socket_fd, const std::vector<Endpoint>& candidates,
                    const Key& handshake_key, bool is_sender, std::uint32_t budget_ms,
                    Endpoint& chosen) {
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

    send_batch_.reserve(tuning_.batch_size);
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
        pump(50);
    }

    // Reclaim the buffer now that it is drained, rather than letting it grow to
    // the size of the largest chunk ever written and stay there.
    outgoing_.clear();
    outgoing_consumed_ = 0;
}

void ReliableUdpChannel::read_exactly(void* data, std::size_t len) {
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

        pump(200);
    }
}

void ReliableUdpChannel::flush() {
    // Everything queued has to be acknowledged, not merely sent, before this
    // returns: the caller is about to treat the data as delivered.
    while (outgoing_consumed_ < outgoing_.size() || !unacknowledged_.empty()) {
        pump(200);
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
            pump(100);
        }
    } catch (const Error&) {
        // A failure while closing is not worth propagating: the transfer itself
        // has already succeeded or failed on its own terms.
    }
}

// -- Protocol engine --------------------------------------------------------

void ReliableUdpChannel::pump(int max_wait_ms) {
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

    // Nothing more to do until either a packet arrives or a timer fires. Sleep
    // until the sooner of the two rather than spinning.
    bool can_send_more = outgoing_consumed_ < outgoing_.size() &&
                         static_cast<double>(unacknowledged_.size()) < cwnd_;
    if (can_send_more || max_wait_ms <= 0) return;

    now_us = monotonic_micros();
    std::uint64_t wait_us = static_cast<std::uint64_t>(max_wait_ms) * 1000;

    if (!unacknowledged_.empty()) {
        wait_us = std::min(wait_us, time_until_rto_us(now_us));
    }
    if (next_send_us_ > now_us) {
        wait_us = std::min(wait_us, next_send_us_ - now_us);
    }

    int wait_ms = static_cast<int>(wait_us / 1000);
    if (wait_ms < 1) wait_ms = 1;
    (void)wait_readable(socket_.get(), wait_ms);
}

void ReliableUdpChannel::fill_window() {
    std::uint64_t now_us = monotonic_micros();

    while (outgoing_consumed_ < outgoing_.size()) {
        if (static_cast<double>(unacknowledged_.size()) >= cwnd_) break;

        // Pacing. Releasing a whole window at once is what makes a router drop a
        // burst of it, so packets are spread evenly across the estimated RTT.
        if (now_us < next_send_us_) break;

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

        transmit(packet.datagram.data(), packet.datagram.size());
        unacknowledged_.push_back(std::move(packet));

        // Spread the current window across one RTT. Before any RTT sample exists,
        // fall back to a rate that a slow link can survive.
        std::uint64_t interval_us =
            (srtt_us_ > 0 && cwnd_ > 0.0)
                ? static_cast<std::uint64_t>(static_cast<double>(srtt_us_) / cwnd_)
                : 0;
        next_send_us_ = now_us + interval_us;
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
    transmit(oldest.datagram.data(), oldest.datagram.size());
}

void ReliableUdpChannel::receive_batch() {
#if defined(DZ_PLATFORM_LINUX)
    // One recvmmsg replaces up to batch_size recvfrom calls. At 1200 bytes per
    // datagram this is the difference between a syscall every 1.2 KB and one
    // every 76 KB.
    const unsigned batch = tuning_.batch_size;

    std::vector<mmsghdr> messages(batch);
    std::vector<iovec> vectors(batch);
    std::vector<std::array<std::uint8_t, kUdpDatagramSize>> buffers(batch);
    std::vector<sockaddr_storage> addresses(batch);

    for (;;) {
        for (unsigned i = 0; i < batch; ++i) {
            vectors[i].iov_base = buffers[i].data();
            vectors[i].iov_len = buffers[i].size();

            std::memset(&messages[i], 0, sizeof(messages[i]));
            messages[i].msg_hdr.msg_iov = &vectors[i];
            messages[i].msg_hdr.msg_iovlen = 1;
            messages[i].msg_hdr.msg_name = &addresses[i];
            messages[i].msg_hdr.msg_namelen = sizeof(addresses[i]);
        }

        int count = ::recvmmsg(socket_.get(), messages.data(), batch, 0, nullptr);
        if (count < 0) {
            if (errno == EINTR) continue;
            return;  // EAGAIN: nothing left to read.
        }
        if (count == 0) return;

        for (int i = 0; i < count; ++i) {
            process_packet(buffers[static_cast<std::size_t>(i)].data(), messages[static_cast<std::size_t>(i)].msg_len);
        }

        // A partly filled batch means the queue is drained.
        if (static_cast<unsigned>(count) < batch) return;
    }
#else
    for (;;) {
        std::uint8_t datagram[kUdpDatagramSize];
        ssize_t got = ::recv(socket_.get(), datagram, sizeof(datagram), 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (got == 0) return;
        process_packet(datagram, static_cast<std::size_t>(got));
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
            transmit(missing.datagram.data(), missing.datagram.size());
        }
    }

    (void)progressed;
}

void ReliableUdpChannel::deliver_in_order() {
    // Hand over every packet that has become contiguous, stopping at the first
    // gap. This is where datagrams become a stream.
    for (;;) {
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

    send_batch_.emplace_back(datagram, datagram + len);
    ++stats_.packets_sent;

    if (send_batch_.size() >= tuning_.batch_size) flush_send_batch();
}

void ReliableUdpChannel::flush_send_batch() {
    if (send_batch_.empty()) return;

#if defined(DZ_PLATFORM_LINUX)
    std::vector<mmsghdr> messages(send_batch_.size());
    std::vector<iovec> vectors(send_batch_.size());

    for (std::size_t i = 0; i < send_batch_.size(); ++i) {
        vectors[i].iov_base = send_batch_[i].data();
        vectors[i].iov_len = send_batch_[i].size();

        std::memset(&messages[i], 0, sizeof(messages[i]));
        messages[i].msg_hdr.msg_iov = &vectors[i];
        messages[i].msg_hdr.msg_iovlen = 1;
        messages[i].msg_hdr.msg_name = const_cast<sockaddr*>(peer_.sockaddr_ptr());
        messages[i].msg_hdr.msg_namelen = peer_.sockaddr_len();
    }

    std::size_t sent = 0;
    while (sent < messages.size()) {
        int count = ::sendmmsg(socket_.get(), messages.data() + sent,
                               static_cast<unsigned>(messages.size() - sent), 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // The kernel's send buffer is full. Dropping the rest is
                // acceptable: this is an unreliable transport underneath, and the
                // retransmission timer exists for exactly this.
                break;
            }
            if (errno == ECONNREFUSED) break;  // An ICMP error from an earlier packet.
            fail_errno("sendmmsg to the peer failed");
        }
        if (count == 0) break;
        sent += static_cast<std::size_t>(count);
    }
#else
    for (const std::vector<std::uint8_t>& datagram : send_batch_) {
        ssize_t written = ::sendto(socket_.get(), datagram.data(), datagram.size(), 0,
                                   peer_.sockaddr_ptr(), peer_.sockaddr_len());
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
            errno != ECONNREFUSED) {
            fail_errno("sendto the peer failed");
        }
    }
#endif

    send_batch_.clear();
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
