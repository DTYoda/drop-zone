#include "dz/server/connection.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "dz/error.hpp"
#include "dz/log.hpp"
#include "dz/secure.hpp"

namespace dz::server {
namespace {

/// How much to read from a socket in one go.
constexpr std::size_t kReadBatch = 64 * 1024;

/// Largest the input buffer may grow to. Bounded so a peer cannot make the
/// server buffer without limit by sending a frame header and then stalling: one
/// oversized frame plus a batch is all that is ever legitimately in flight.
constexpr std::size_t kMaxInputBuffer = kMaxFrameLength + kFrameHeaderSize + kReadBatch;

}  // namespace

const char* connection_state_name(ConnectionState state) {
    switch (state) {
        case ConnectionState::AwaitingHello: return "awaiting-hello";
        case ConnectionState::ReceiverIdle: return "receiver-idle";
        case ConnectionState::ReceiverMatched: return "receiver-matched";
        case ConnectionState::SenderIdle: return "sender-idle";
        case ConnectionState::SenderWaiting: return "sender-waiting";
        case ConnectionState::Relaying: return "relaying";
        case ConnectionState::Closing: return "closing";
    }
    return "unknown";
}

Connection::Connection(Fd fd, std::uint64_t id, unsigned shard_index)
    : fd_(std::move(fd)), id_(id), shard_index_(shard_index), label_(log::describe_peer(id)) {}

void Connection::attach_relay_peer(const ConnectionPtr& peer) {
    std::lock_guard<std::mutex> guard(relay_mutex_);
    relay_peer_ = peer;
}

ConnectionPtr Connection::relay_peer() const {
    std::lock_guard<std::mutex> guard(relay_mutex_);
    return relay_peer_.lock();
}

Connection::~Connection() {
    // Both buffers can hold a peer's public keys and candidate addresses, and
    // the relay buffers hold their ciphertext. Wiping on the way out means a
    // later heap allocation cannot hand another part of the process a window
    // into a session that has ended.
    secure_zero(input_.data(), input_.size());
    secure_zero(output_.data(), output_.size());
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

bool Connection::read_available() {
    for (;;) {
        // Reclaim the front of the buffer once enough has been consumed that
        // the memmove is worth it, rather than on every frame.
        if (input_consumed_ > 0 && input_consumed_ >= input_.size() / 2) {
            input_.erase(input_.begin(),
                         input_.begin() + static_cast<std::ptrdiff_t>(input_consumed_));
            input_consumed_ = 0;
        }

        if (input_.size() >= kMaxInputBuffer) {
            // The peer is ahead of what the protocol allows in flight. Stop
            // reading; the frame handler will either consume it or close.
            return true;
        }

        std::size_t previous = input_.size();
        input_.resize(previous + kReadBatch);

        ssize_t got = ::recv(fd_.get(), input_.data() + previous, kReadBatch, 0);
        if (got > 0) {
            input_.resize(previous + static_cast<std::size_t>(got));
            // Edge-triggered polling means the loop keeps reading until EAGAIN;
            // stopping early would leave data the kernel will not report again.
            continue;
        }

        input_.resize(previous);

        if (got == 0) {
            peer_closed_ = true;
            return false;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;

        // Any other error means the connection is unusable.
        peer_closed_ = true;
        return false;
    }
}

bool Connection::next_frame(Frame& out) {
    std::size_t available = input_.size() - input_consumed_;
    if (available < kFrameHeaderSize) return false;

    const std::uint8_t* cursor = input_.data() + input_consumed_;
    FrameHeader header = decode_frame_header(cursor);

    if (available < kFrameHeaderSize + header.length) return false;

    out.header = header;
    out.payload.assign(cursor + kFrameHeaderSize, cursor + kFrameHeaderSize + header.length);
    input_consumed_ += kFrameHeaderSize + header.length;
    return true;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

void Connection::enqueue_frame(MessageType type, const void* payload, std::size_t length,
                               std::uint16_t flags) {
    if (length > kMaxFrameLength) fail("refusing to enqueue an oversized frame");

    FrameHeader header;
    header.type = type;
    header.flags = flags;
    header.length = static_cast<std::uint32_t>(length);

    std::uint8_t header_bytes[kFrameHeaderSize];
    encode_frame_header(header, header_bytes);

    std::lock_guard<std::mutex> guard(output_mutex_);

    // Compact before appending so a long-lived relay connection does not grow a
    // buffer whose front is entirely already-sent bytes.
    if (output_sent_ > 0 && output_sent_ == output_.size()) {
        output_.clear();
        output_sent_ = 0;
    } else if (output_sent_ > 64 * 1024) {
        output_.erase(output_.begin(), output_.begin() + static_cast<std::ptrdiff_t>(output_sent_));
        output_sent_ = 0;
    }

    output_.insert(output_.end(), header_bytes, header_bytes + sizeof(header_bytes));
    if (length > 0) {
        const auto* bytes = static_cast<const std::uint8_t*>(payload);
        output_.insert(output_.end(), bytes, bytes + length);
    }
}

std::size_t Connection::pending_output() const {
    std::lock_guard<std::mutex> guard(output_mutex_);
    return output_.size() - output_sent_;
}

bool Connection::wants_write() const { return pending_output() > 0; }

bool Connection::flush_output() {
    // send() is called with the lock held. Releasing it around the call would
    // let another thread's enqueue_frame() reallocate the vector while the
    // kernel is reading out of it. The socket is non-blocking, so the call
    // returns as soon as the kernel's send buffer is full rather than waiting,
    // and the pause threshold bounds how much a relay ever has queued -- so the
    // critical section stays short.
    std::lock_guard<std::mutex> guard(output_mutex_);

    for (;;) {
        std::size_t remaining = output_.size() - output_sent_;
        if (remaining == 0) {
            output_.clear();
            output_sent_ = 0;
            return true;
        }
        const std::uint8_t* cursor = output_.data() + output_sent_;

#ifdef MSG_NOSIGNAL
        ssize_t written = ::send(fd_.get(), cursor, remaining, MSG_NOSIGNAL);
#else
        ssize_t written = ::send(fd_.get(), cursor, remaining, 0);
#endif
        if (written > 0) {
            output_sent_ += static_cast<std::size_t>(written);
            if (output_sent_ == output_.size()) {
                output_.clear();
                output_sent_ = 0;
                return true;
            }
            continue;
        }

        if (written < 0 && errno == EINTR) continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        return false;
    }
}

void Connection::request_close(std::string_view reason) {
    // The reason is written before the flag is published, so a shard that sees
    // close_requested() can read close_reason() without racing the assignment.
    std::lock_guard<std::mutex> guard(close_mutex_);
    if (close_requested_.load(std::memory_order_relaxed)) return;
    close_reason_.assign(reason);
    close_requested_.store(true, std::memory_order_release);
}

std::string Connection::close_reason() const {
    std::lock_guard<std::mutex> guard(close_mutex_);
    return close_reason_;
}

}  // namespace dz::server
