// One client's control connection, buffered for a non-blocking event loop.
//
// The awkward part of the design is that frames have to be written to a
// connection by a thread other than the one that owns it: when a sender's
// SendRequest is matched, the reply goes to a receiver that some other shard is
// polling. Rather than move descriptors between shards, a connection has a
// mutex-protected output buffer that anybody may append to, plus a wake
// mechanism that asks the owning shard to re-examine the connection. Reading,
// polling and closing stay on the owning thread.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "dz/frame.hpp"
#include "dz/protocol.hpp"
#include "dz/socket.hpp"

namespace dz::server {

/// Where a connection is in the rendezvous conversation.
enum class ConnectionState : std::uint8_t {
    AwaitingHello,   ///< Nothing received yet.
    ReceiverIdle,    ///< Claimed a username, waiting for a sender.
    ReceiverMatched, ///< Introduced to a sender, waiting for its decision.
    SenderIdle,      ///< Said hello, has not asked for anybody yet.
    SenderWaiting,   ///< Asked for a username, waiting for the receiver.
    Relaying,        ///< Forwarding opaque bytes to its paired peer.
    Closing,         ///< Being torn down.
};

const char* connection_state_name(ConnectionState state);

class Connection;
using ConnectionPtr = std::shared_ptr<Connection>;

class Connection {
public:
    Connection(Fd fd, std::uint64_t id, unsigned shard_index);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    int fd() const { return fd_.get(); }
    std::uint64_t id() const { return id_; }
    unsigned shard_index() const { return shard_index_; }

    /// A log-safe label for this connection. See dz::log::describe_peer.
    const std::string& label() const { return label_; }

    /// Where this connection is in the conversation.
    ///
    /// Atomic because a shard other than the owner writes it. Matching a sender
    /// sets the receiver's state to ReceiverMatched from the sender's shard;
    /// opening a relay sets both sides to Relaying from whichever shard handled
    /// the second RelayOpen. A plain enum would be a data race, and a race that
    /// lost the Relaying store would reject the first RelayData and RST the
    /// transfer.
    std::atomic<ConnectionState> state{ConnectionState::AwaitingHello};

    /// The hello this peer sent, kept only while the connection is open.
    ClientHello hello;
    bool hello_received = false;

    /// Username this connection has claimed in the session table, empty if none.
    std::string claimed_username;

    /// Pairing this connection belongs to, 0 if none. Atomic for the same reason
    /// as `state`: the sender's shard stamps the id onto the receiver.
    std::atomic<std::uint64_t> pairing_id{0};

    /// Record that this connection forwards to `peer`. Must be called on both
    /// sides before either is marked Relaying, so a RelayData that observes
    /// Relaying is guaranteed to find a peer rather than closing the connection.
    void attach_relay_peer(const ConnectionPtr& peer);

    /// The peer this connection is relaying to, or nullptr.
    ConnectionPtr relay_peer() const;

    /// Address the server observed for this connection.
    ///
    /// Held for exactly as long as the socket is open, because the candidate
    /// list it feeds is the whole point of the introduction, and discarded with
    /// the connection object. It is never logged and never written anywhere.
    Endpoint observed_endpoint;

    /// Rate-limit bucket key for this peer: a keyed hash of its address under a
    /// salt that exists only in this process's memory.
    std::uint64_t rate_limit_key = 0;

    std::uint64_t last_activity_ms = 0;

    // -- Reading, owning shard only -----------------------------------------

    /// Drain the socket into the input buffer. Returns false when the peer has
    /// closed and no more data will arrive.
    bool read_available();

    /// Take the next complete frame out of the input buffer, if there is one.
    bool next_frame(Frame& out);

    // -- Writing, any thread ------------------------------------------------

    /// Append a frame to the output buffer. Safe to call from any thread.
    void enqueue_frame(MessageType type, const void* payload, std::size_t length,
                       std::uint16_t flags = 0);
    void enqueue_frame(MessageType type, const std::vector<std::uint8_t>& payload,
                       std::uint16_t flags = 0) {
        enqueue_frame(type, payload.data(), payload.size(), flags);
    }
    void enqueue_empty(MessageType type, std::uint16_t flags = 0) {
        enqueue_frame(type, nullptr, 0, flags);
    }

    /// Bytes waiting to be written. Used for relay back-pressure.
    std::size_t pending_output() const;

    /// Push as much of the output buffer as the socket will take. Owning shard
    /// only. Returns false if the connection died.
    bool flush_output();

    /// True when the output buffer still holds data, so the shard should ask to
    /// be told when the socket is writable again.
    bool wants_write() const;

    /// Ask the shard to stop reading from this connection, because its relay
    /// peer's output buffer is full.
    void set_read_paused(bool paused) { read_paused_.store(paused, std::memory_order_relaxed); }
    bool read_paused() const { return read_paused_.load(std::memory_order_relaxed); }

    /// Request an orderly shutdown, from any thread. The owning shard performs
    /// it once it has flushed whatever is already queued.
    void request_close(std::string_view reason);
    bool close_requested() const { return close_requested_.load(std::memory_order_acquire); }
    std::string close_reason() const;

    /// True once the peer has closed its half and the input buffer is drained.
    bool peer_closed() const { return peer_closed_; }

    /// Unconsumed input has reached the cap, so the caller must process frames
    /// before reading again. Edge-triggered polling will not wake us for data
    /// already in the kernel, so the shard loop has to come back of its own
    /// accord rather than waiting for another Readable event.
    bool input_at_cap() const;

private:
    Fd fd_;
    std::uint64_t id_;
    unsigned shard_index_;
    std::string label_;

    std::vector<std::uint8_t> input_;
    std::size_t input_consumed_ = 0;
    bool peer_closed_ = false;

    mutable std::mutex output_mutex_;
    std::vector<std::uint8_t> output_;
    std::size_t output_sent_ = 0;

    std::atomic<bool> read_paused_{false};
    std::atomic<bool> close_requested_{false};

    mutable std::mutex relay_mutex_;
    std::weak_ptr<Connection> relay_peer_;

    mutable std::mutex close_mutex_;
    std::string close_reason_;
};

/// Bytes of queued output at which a relay stops reading from the other side,
/// and the level it must fall back to before reading resumes.
///
/// The gap between the two is deliberate: resuming the instant a single byte
/// drains would toggle the source's poll registration on almost every event.
constexpr std::size_t kRelayPauseThreshold = 4u * 1024 * 1024;
constexpr std::size_t kRelayResumeThreshold = 1u * 1024 * 1024;

}  // namespace dz::server
