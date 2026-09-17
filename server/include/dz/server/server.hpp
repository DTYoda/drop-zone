// The rendezvous server.
//
// Its whole job is to be a switchboard for peers that cannot find each other:
//
//   1. A receiver in accept mode connects and claims a username.
//   2. A sender connects, names that username, and attaches a proof that it
//      knows the receiver's public password.
//   3. The server hands each peer the other's public keys and candidate
//      addresses, and gets out of the way.
//   4. If both peers fail to build a direct path, the server forwards opaque
//      bytes between them as a last resort.
//
// What it deliberately never has: a database, an account registry, a log line
// containing an address, a filename, a password, or a plaintext file byte. Step
// 4 forwards ciphertext the server holds no key for.
//
// Threading. N shards, each a thread with its own poller and its own listening
// socket over SO_REUSEPORT, so accept() work spreads across cores instead of
// funnelling through one thread. A connection belongs to the shard that accepted
// it and only that shard reads from, polls or closes it. The session table is
// shared, so matching a sender to a receiver on another shard means queueing a
// frame on the receiver's connection and waking its shard through a self-pipe.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "dz/server/connection.hpp"
#include "dz/server/poller.hpp"
#include "dz/server/rate_limiter.hpp"
#include "dz/server/session_table.hpp"

namespace dz::server {

struct ServerOptions {
    std::string bind_address = "::";
    std::uint16_t port = kDefaultServerPort;
    /// 0 means one shard per hardware thread.
    unsigned shards = 0;
    /// Idle control connections are dropped after this long. Receivers send
    /// keep-alives well inside it, both to stay in the table and to keep their
    /// NAT mapping alive.
    std::uint32_t idle_timeout_seconds = 300;
    /// A pairing that never completes is discarded after this long.
    std::uint32_t pairing_timeout_seconds = 120;
    RateLimits rate_limits;
    /// Refuse to relay, forcing peers onto a direct path. For an operator who
    /// wants to provide introductions without carrying anybody's traffic.
    bool allow_relay = true;
};

class Server {
public:
    explicit Server(ServerOptions options);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    /// Bind the listening sockets and start the shards. Returns once every shard
    /// is running.
    void start();

    /// Block until stop() is called.
    void run_until_stopped();

    /// Ask every shard to finish. Safe to call from a signal handler context via
    /// a flag, and safe to call more than once.
    void stop();

    /// The port actually bound, which differs from the requested one when the
    /// options asked for port 0.
    std::uint16_t bound_port() const { return bound_port_; }

private:
    /// One event-loop thread and the connections it owns.
    struct Shard {
        unsigned index = 0;
        Poller poller;
        /// This shard's own listening socket for the shared port.
        Fd listener;
        /// UDP socket answering reflexive probes. Only shard 0 has one, because
        /// a single socket handles the trickle of stateless probes easily.
        Fd reflexive_socket;
        /// Written to in order to wake this shard out of poller.wait().
        Fd wake_read;
        Fd wake_write;

        std::unordered_map<int, ConnectionPtr> connections;

        /// Descriptors another thread has asked this shard to re-examine.
        std::mutex wake_mutex;
        std::vector<int> wake_queue;

        std::thread thread;
    };

    // -- Setup --------------------------------------------------------------

    Fd open_listener();
    Fd open_reflexive_socket();
    void create_wake_pipe(Shard& shard);

    // -- Shard loop ---------------------------------------------------------

    void run_shard(Shard& shard);
    void accept_connections(Shard& shard);
    void handle_reflexive_probes(Shard& shard);
    void drain_wake_queue(Shard& shard);
    void service_connection(Shard& shard, const ConnectionPtr& connection, const ReadyEvent& event);
    void update_interest(Shard& shard, const ConnectionPtr& connection);
    void close_connection(Shard& shard, const ConnectionPtr& connection);
    void run_maintenance(Shard& shard, std::uint64_t now_ms);

    /// Ask the shard owning `connection` to flush it and re-evaluate its poll
    /// registration. Safe from any thread.
    void wake_for(const ConnectionPtr& connection);

    // -- Protocol -----------------------------------------------------------

    void handle_frame(Shard& shard, const ConnectionPtr& connection, const Frame& frame);
    void handle_client_hello(const ConnectionPtr& connection, const Frame& frame);
    void handle_send_request(const ConnectionPtr& connection, const Frame& frame);
    void handle_accept(const ConnectionPtr& connection, const Frame& frame);
    void handle_reject(const ConnectionPtr& connection, const Frame& frame);
    void handle_relay_open(const ConnectionPtr& connection, const Frame& frame);
    void handle_relay_data(const ConnectionPtr& connection, const Frame& frame);
    void handle_relay_close(const ConnectionPtr& connection, const Frame& frame);

    /// Send a Reject carrying `reason` and mark the connection for closing.
    void reject_and_close(const ConnectionPtr& connection, const std::string& reason);

    ServerOptions options_;
    SessionTable sessions_;
    RateLimiter rate_limiter_;

    std::vector<std::unique_ptr<Shard>> shards_;
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> next_connection_id_{1};
    std::uint16_t bound_port_ = 0;

    /// Aggregate counters. Deliberately aggregate: a per-peer counter would be
    /// retention of exactly the sort the design rules out.
    std::atomic<std::uint64_t> total_connections_{0};
    std::atomic<std::uint64_t> total_introductions_{0};
    std::atomic<std::uint64_t> total_relayed_bytes_{0};
};

}  // namespace dz::server
