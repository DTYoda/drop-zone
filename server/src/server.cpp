#include "dz/server/server.hpp"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "dz/cpu.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"

namespace dz::server {
namespace {

/// Backlog for listen(). Generous because a burst of receivers coming back after
/// a network blip all reconnect at once.
constexpr int kListenBacklog = 512;

/// How long a shard waits in the poller before running its maintenance pass.
constexpr int kPollTimeoutMs = 1000;

/// Nudge a shard's wake pipe so it returns from the poller and re-examines the
/// connections other threads have touched.
///
/// A failed write means the pipe is already full, which means a wake is already
/// pending -- exactly the outcome the caller wanted -- so there is nothing to do
/// with the result beyond satisfying the compiler's warn_unused_result.
void poke(int fd) {
    char byte = 'x';
    ssize_t ignored = ::write(fd, &byte, 1);
    (void)ignored;
}

}  // namespace

Server::Server(ServerOptions options)
    : options_(std::move(options)), rate_limiter_(options_.rate_limits) {
    if (options_.shards == 0) options_.shards = hardware_threads();
}

Server::~Server() {
    stop();
    for (std::unique_ptr<Shard>& shard : shards_) {
        if (shard->thread.joinable()) shard->thread.join();
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

Fd Server::open_listener() {
    // Once the first socket is bound, every other shard must bind the same port
    // explicitly -- asking for port 0 again would hand each shard a different
    // one instead of sharing.
    std::uint16_t port = (bound_port_ != 0) ? bound_port_ : options_.port;

    std::vector<Endpoint> candidates = Endpoint::resolve(options_.bind_address, port);
    const Endpoint& address = candidates.front();

    Fd listener(::socket(address.family(), SOCK_STREAM, 0));
    if (!listener.valid()) fail_errno("cannot create the listening socket");

    set_close_on_exec(listener.get());
    set_reuse_addr(listener.get());

    // Every shard binds the same port. Without SO_REUSEPORT only one could, and
    // all accept() work would land on a single thread.
    if (!set_reuse_port(listener.get())) {
        if (shards_.size() > 0) {
            fail("this platform has no SO_REUSEPORT, so only one shard can listen; "
                 "start the server with --shards=1");
        }
    }

    if (address.family() == AF_INET6) {
        // Accept IPv4 clients on the same socket as IPv6 ones, so one bind
        // covers both. Some systems default this the other way.
        int off = 0;
        (void)::setsockopt(listener.get(), IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }

    if (::bind(listener.get(), address.sockaddr_ptr(), address.sockaddr_len()) != 0) {
        fail_errno("cannot bind " + address.to_string());
    }
    if (::listen(listener.get(), kListenBacklog) != 0) fail_errno("cannot listen");

    set_nonblocking(listener.get(), true);
    return listener;
}

Fd Server::open_reflexive_socket() {
    std::vector<Endpoint> candidates = Endpoint::resolve(options_.bind_address, bound_port_);
    const Endpoint& address = candidates.front();

    Fd socket_fd(::socket(address.family(), SOCK_DGRAM, 0));
    if (!socket_fd.valid()) fail_errno("cannot create the reflexive probe socket");

    set_close_on_exec(socket_fd.get());
    set_reuse_addr(socket_fd.get());

    if (address.family() == AF_INET6) {
        int off = 0;
        (void)::setsockopt(socket_fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }

    if (::bind(socket_fd.get(), address.sockaddr_ptr(), address.sockaddr_len()) != 0) {
        fail_errno("cannot bind the reflexive probe socket");
    }

    set_nonblocking(socket_fd.get(), true);
    return socket_fd;
}

void Server::create_wake_pipe(Shard& shard) {
    int ends[2];
    if (::pipe(ends) != 0) fail_errno("cannot create a shard wake pipe");

    shard.wake_read.reset(ends[0]);
    shard.wake_write.reset(ends[1]);

    set_close_on_exec(shard.wake_read.get());
    set_close_on_exec(shard.wake_write.get());
    set_nonblocking(shard.wake_read.get(), true);
    // The write end is non-blocking too: a wake byte that cannot be queued
    // because the pipe is already full is a wake that is already pending.
    set_nonblocking(shard.wake_write.get(), true);
}

void Server::start() {
    ignore_sigpipe();

    // A crash must not be able to write the session table -- which holds live
    // peer addresses and public keys -- into a core file on the operator's disk.
    disable_core_dumps();

    for (unsigned i = 0; i < options_.shards; ++i) {
        auto shard = std::make_unique<Shard>();
        shard->index = i;
        shard->listener = open_listener();

        if (bound_port_ == 0) {
            bound_port_ = local_endpoint(shard->listener.get()).port();
        }

        create_wake_pipe(*shard);

        shard->poller.add(shard->listener.get(), Interest::Readable);
        shard->poller.add(shard->wake_read.get(), Interest::Readable);

        if (i == 0) {
            // Reflexive probes are stateless four-byte datagrams, so one socket
            // on one shard keeps up with any realistic load.
            shard->reflexive_socket = open_reflexive_socket();
            shard->poller.add(shard->reflexive_socket.get(), Interest::Readable);
        }

        shards_.push_back(std::move(shard));
    }

    for (std::unique_ptr<Shard>& shard : shards_) {
        Shard* raw = shard.get();
        shard->thread = std::thread([this, raw] {
            try {
                run_shard(*raw);
            } catch (const std::exception& error) {
                log::error(std::string("shard stopped: ") + error.what());
                stop();
            }
        });
    }

    log::info("listening on " + options_.bind_address + " port " + std::to_string(bound_port_) +
              " across " + std::to_string(options_.shards) + " shards");
}

void Server::run_until_stopped() {
    for (std::unique_ptr<Shard>& shard : shards_) {
        if (shard->thread.joinable()) shard->thread.join();
    }

    log::info("served " + std::to_string(total_connections_.load()) + " connections, " +
              std::to_string(total_introductions_.load()) + " introductions, relayed " +
              std::to_string(total_relayed_bytes_.load()) + " bytes");
}

void Server::stop() {
    bool expected = false;
    if (!stopping_.compare_exchange_strong(expected, true)) return;

    // Nudge every shard out of its poller so it notices the flag.
    for (std::unique_ptr<Shard>& shard : shards_) poke(shard->wake_write.get());
}

// ---------------------------------------------------------------------------
// Shard loop
// ---------------------------------------------------------------------------

void Server::run_shard(Shard& shard) {
    std::vector<ReadyEvent> events;
    std::uint64_t last_maintenance_ms = monotonic_millis();

    while (!stopping_.load(std::memory_order_relaxed)) {
        shard.poller.wait(events, kPollTimeoutMs);

        for (const ReadyEvent& event : events) {
            if (event.fd == shard.listener.get()) {
                accept_connections(shard);
                continue;
            }
            if (shard.reflexive_socket.valid() && event.fd == shard.reflexive_socket.get()) {
                handle_reflexive_probes(shard);
                continue;
            }
            if (event.fd == shard.wake_read.get()) {
                drain_wake_queue(shard);
                continue;
            }

            auto found = shard.connections.find(event.fd);
            if (found == shard.connections.end()) continue;

            // Copied out of the map because service_connection may close the
            // connection and erase the entry.
            ConnectionPtr connection = found->second;
            service_connection(shard, connection, event);
        }

        std::uint64_t now_ms = monotonic_millis();
        if (now_ms - last_maintenance_ms >= 1000) {
            run_maintenance(shard, now_ms);
            last_maintenance_ms = now_ms;
        }
    }

    // Tear down whatever this shard still owns, releasing its username claims.
    std::vector<ConnectionPtr> remaining;
    remaining.reserve(shard.connections.size());
    for (auto& entry : shard.connections) remaining.push_back(entry.second);
    for (const ConnectionPtr& connection : remaining) close_connection(shard, connection);
}

void Server::accept_connections(Shard& shard) {
    // Edge-triggered: keep accepting until the queue is empty, or the kernel
    // will not report the listener again.
    for (;;) {
        sockaddr_storage storage{};
        socklen_t length = sizeof(storage);

#if defined(DZ_PLATFORM_LINUX)
        int raw = ::accept4(shard.listener.get(), reinterpret_cast<sockaddr*>(&storage), &length,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        int raw = ::accept(shard.listener.get(), reinterpret_cast<sockaddr*>(&storage), &length);
#endif
        if (raw < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EMFILE || errno == ENFILE) {
                log::warn("out of file descriptors, refusing connections for now");
                return;
            }
            // ECONNABORTED and friends concern one connection, not the listener.
            continue;
        }

        Fd client(raw);
#if !defined(DZ_PLATFORM_LINUX)
        set_nonblocking(client.get(), true);
        set_close_on_exec(client.get());
#endif
        set_tcp_nodelay(client.get());
        set_no_sigpipe(client.get());

        Endpoint observed = Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), length);
        std::uint64_t key = rate_limiter_.key_for(observed);
        std::uint64_t now_ms = monotonic_millis();

        if (!rate_limiter_.allow_connection(key, now_ms)) {
            // Dropped without a reply. Sending one would cost more than the
            // refusal saves, and a client being throttled is not owed an
            // explanation it could use to tune its rate.
            continue;
        }

        std::uint64_t id = next_connection_id_.fetch_add(1);
        auto connection = std::make_shared<Connection>(std::move(client), id, shard.index);
        connection->observed_endpoint = observed;
        connection->rate_limit_key = key;
        connection->last_activity_ms = now_ms;

        int fd = connection->fd();
        shard.poller.add(fd, Interest::Readable);
        shard.connections.emplace(fd, connection);

        total_connections_.fetch_add(1);
        log::debug(connection->label() + " connected");
    }
}

void Server::handle_reflexive_probes(Shard& shard) {
    std::uint8_t request[64];
    std::uint8_t reply[kMaxReflexiveReplySize];

    for (;;) {
        sockaddr_storage storage{};
        socklen_t length = sizeof(storage);

        ssize_t got = ::recvfrom(shard.reflexive_socket.get(), request, sizeof(request), 0,
                                 reinterpret_cast<sockaddr*>(&storage), &length);
        if (got < 0) {
            if (errno == EINTR) continue;
            return;  // EAGAIN: the queue is drained.
        }

        if (static_cast<std::size_t>(got) < kReflexiveProbeSize) continue;
        if (std::memcmp(request, kReflexiveProbeMagic, sizeof(kReflexiveProbeMagic)) != 0) continue;

        Endpoint observed = Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), length);
        std::size_t reply_length = encode_reflexive_reply(observed, reply, sizeof(reply));

        // Fire and forget. The address is read out of the datagram, written back
        // into the reply and never stored, which is what makes this exchange add
        // nothing to the server's memory.
        (void)::sendto(shard.reflexive_socket.get(), reply, reply_length, 0,
                       reinterpret_cast<sockaddr*>(&storage), length);
    }
}

void Server::drain_wake_queue(Shard& shard) {
    char scratch[256];
    while (::read(shard.wake_read.get(), scratch, sizeof(scratch)) > 0) {
    }

    std::vector<int> pending;
    {
        std::lock_guard<std::mutex> guard(shard.wake_mutex);
        pending.swap(shard.wake_queue);
    }

    for (int fd : pending) {
        auto found = shard.connections.find(fd);
        if (found == shard.connections.end()) continue;

        ConnectionPtr connection = found->second;
        if (!connection->flush_output()) {
            close_connection(shard, connection);
            continue;
        }
        if (connection->close_requested() && !connection->wants_write()) {
            close_connection(shard, connection);
            continue;
        }
        update_interest(shard, connection);
    }
}

void Server::service_connection(Shard& shard, const ConnectionPtr& connection,
                                const ReadyEvent& event) {
    connection->last_activity_ms = monotonic_millis();

    if (event.writable) {
        if (!connection->flush_output()) {
            close_connection(shard, connection);
            return;
        }

        // Draining this connection's queue may be what a paused relay source is
        // waiting for.
        if (connection->state == ConnectionState::Relaying &&
            connection->pending_output() <= kRelayResumeThreshold) {
            if (ConnectionPtr peer = connection->relay_peer()) {
                if (peer->read_paused()) {
                    peer->set_read_paused(false);
                    wake_for(peer);
                }
            }
        }
    }

    if (event.readable && !connection->read_paused()) {
        bool still_open = connection->read_available();

        // Frames already buffered are handled even when the peer has closed:
        // a client that sends Bye and shuts down immediately still deserves to
        // have its last frame processed.
        Frame frame;
        try {
            while (connection->next_frame(frame)) {
                handle_frame(shard, connection, frame);
                if (connection->close_requested()) break;
            }
        } catch (const Error& error) {
            log::debug(connection->label() + " protocol error: " + error.what());
            connection->request_close(error.what());
        }

        if (!still_open) {
            if (!connection->flush_output()) {
                close_connection(shard, connection);
                return;
            }
            close_connection(shard, connection);
            return;
        }
    }

    if (!connection->flush_output()) {
        close_connection(shard, connection);
        return;
    }

    if (connection->close_requested() && !connection->wants_write()) {
        close_connection(shard, connection);
        return;
    }
    if (event.closed && !connection->wants_write()) {
        close_connection(shard, connection);
        return;
    }

    update_interest(shard, connection);
}

void Server::update_interest(Shard& shard, const ConnectionPtr& connection) {
    Interest interest = Interest::None;
    if (!connection->read_paused() && !connection->close_requested()) {
        interest = interest | Interest::Readable;
    }
    if (connection->wants_write()) interest = interest | Interest::Writable;

    shard.poller.modify(connection->fd(), interest);
}

void Server::close_connection(Shard& shard, const ConnectionPtr& connection) {
    if (connection->state == ConnectionState::Closing) return;
    connection->state = ConnectionState::Closing;

    // Free the username straight away so the same person can re-enter accept
    // mode without waiting for anything to time out.
    if (!connection->claimed_username.empty()) {
        sessions_.release(connection->claimed_username, connection.get());
    }

    // Tell the other half of a pairing, so a peer waiting on an introduction
    // learns immediately instead of after a timeout.
    if (connection->pairing_id != 0) {
        Pairing pairing;
        if (sessions_.find_pairing(connection->pairing_id, pairing)) {
            ConnectionPtr sender = pairing.sender.lock();
            ConnectionPtr receiver = pairing.receiver.lock();
            ConnectionPtr other = (sender == connection) ? receiver : sender;

            if (other != nullptr && other != connection) {
                static const std::string kReason = "the other peer disconnected";
                other->enqueue_frame(MessageType::RelayClose, kReason.data(), kReason.size());
                other->request_close(kReason);
                wake_for(other);
            }
        }
        sessions_.destroy_pairing(connection->pairing_id);
    }

    shard.poller.remove(connection->fd());
    shard.connections.erase(connection->fd());

    log::debug(connection->label() + " disconnected");
    // The Connection destructor wipes its buffers, so the peer's keys and any
    // relayed ciphertext leave memory here rather than lingering in freed pages.
}

void Server::run_maintenance(Shard& shard, std::uint64_t now_ms) {
    std::uint64_t idle_limit_ms = static_cast<std::uint64_t>(options_.idle_timeout_seconds) * 1000;

    std::vector<ConnectionPtr> stale;
    for (auto& entry : shard.connections) {
        const ConnectionPtr& connection = entry.second;
        if (now_ms - connection->last_activity_ms > idle_limit_ms) stale.push_back(connection);
    }
    for (const ConnectionPtr& connection : stale) {
        log::debug(connection->label() + " timed out");
        close_connection(shard, connection);
    }

    // One shard does the shared-table housekeeping; doing it on all of them
    // would just contend on the same mutex to no purpose.
    if (shard.index == 0) {
        std::uint64_t pairing_limit_ms =
            static_cast<std::uint64_t>(options_.pairing_timeout_seconds) * 1000;
        sessions_.expire_pairings(now_ms, pairing_limit_ms);
        rate_limiter_.evict_idle(now_ms, 10 * 60 * 1000);
    }
}

void Server::wake_for(const ConnectionPtr& connection) {
    unsigned index = connection->shard_index();
    if (index >= shards_.size()) return;

    Shard& shard = *shards_[index];
    {
        std::lock_guard<std::mutex> guard(shard.wake_mutex);
        shard.wake_queue.push_back(connection->fd());
    }

    poke(shard.wake_write.get());
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

void Server::handle_frame(Shard& shard, const ConnectionPtr& connection, const Frame& frame) {
    (void)shard;

    switch (frame.header.type) {
        case MessageType::ClientHello:
            handle_client_hello(connection, frame);
            return;
        case MessageType::SendRequest:
            handle_send_request(connection, frame);
            return;
        case MessageType::Accept:
            handle_accept(connection, frame);
            return;
        case MessageType::Reject:
            handle_reject(connection, frame);
            return;
        case MessageType::RelayOpen:
            handle_relay_open(connection, frame);
            return;
        case MessageType::RelayData:
            handle_relay_data(connection, frame);
            return;
        case MessageType::RelayClose:
            handle_relay_close(connection, frame);
            return;
        case MessageType::KeepAlive:
            // Nothing to do: last_activity_ms was already refreshed. Receivers
            // send these to hold both their table entry and their NAT mapping.
            return;
        case MessageType::Bye:
            connection->request_close("peer said goodbye");
            return;
        default:
            reject_and_close(connection, std::string("a ") +
                                            message_type_name(frame.header.type) +
                                            " frame is not valid here");
            return;
    }
}

void Server::handle_client_hello(const ConnectionPtr& connection, const Frame& frame) {
    ClientHello hello = ClientHello::decode(frame.payload);

    // A receiver between transfers sends a fresh hello to publish its new ports
    // and ephemeral key, because the sockets from the last transfer were consumed
    // by it. Refreshing keeps the username claimed throughout, so a sender
    // arriving in the gap is not told the user is offline.
    bool refreshing = connection->hello_received &&
                      connection->state == ConnectionState::ReceiverIdle &&
                      hello.role == ClientRole::Receiver &&
                      hello.username == connection->claimed_username;

    if (connection->hello_received && !refreshing) {
        reject_and_close(connection, "hello sent twice");
        return;
    }

    connection->hello = std::move(hello);
    connection->hello_received = true;

    ServerHello reply;
    reply.idle_timeout_seconds = options_.idle_timeout_seconds;
    reply.reflexive_tcp = connection->observed_endpoint;

    // A guess at the peer's UDP mapping: its observed address with the port it
    // says it will punch from. Correct whenever the NAT preserves ports, and the
    // peer's own stateless probe gives it the authoritative answer either way.
    reply.reflexive_udp = connection->observed_endpoint;
    reply.reflexive_udp.set_port(connection->hello.udp_port);

    if (refreshing) {
        reply.claim_accepted = true;
        reply.message = "still accepting as " + connection->claimed_username;
        connection->enqueue_frame(MessageType::ServerHello, reply.encode());
        return;
    }

    if (connection->hello.role == ClientRole::Receiver) {
        ClaimResult result = sessions_.claim(connection->hello.username, connection);
        switch (result) {
            case ClaimResult::Granted:
                connection->claimed_username = connection->hello.username;
                connection->state = ConnectionState::ReceiverIdle;
                reply.claim_accepted = true;
                reply.message = "accepting as " + connection->hello.username;
                break;
            case ClaimResult::AlreadyClaimed:
                reply.claim_accepted = false;
                reply.message = "someone is already accepting as '" + connection->hello.username +
                                "'";
                break;
            case ClaimResult::InvalidUsername:
                reply.claim_accepted = false;
                reply.message = "'" + connection->hello.username + "' is not a usable username";
                break;
        }
    } else {
        // Senders do not claim anything: they are here for one introduction and
        // their username is only a label the receiver will see.
        connection->state = ConnectionState::SenderIdle;
        reply.claim_accepted = true;
    }

    connection->enqueue_frame(MessageType::ServerHello, reply.encode());

    if (!reply.claim_accepted) connection->request_close(reply.message);
}

void Server::handle_send_request(const ConnectionPtr& connection, const Frame& frame) {
    if (connection->state != ConnectionState::SenderIdle) {
        reject_and_close(connection, "only a sender that has said hello may request an introduction");
        return;
    }

    if (!rate_limiter_.allow_request(connection->rate_limit_key, monotonic_millis())) {
        // This is the limit that matters for password guessing: only the
        // receiver can tell a wrong public password from a right one, so the
        // server slows the attempts down rather than judging them.
        reject_and_close(connection, "too many requests, try again in a minute");
        return;
    }

    SendRequest request = SendRequest::decode(frame.payload);

    ConnectionPtr receiver = sessions_.lookup(request.target_username);
    if (receiver == nullptr) {
        reject_and_close(connection,
                         "'" + request.target_username + "' is not accepting files right now");
        return;
    }
    if (receiver->state != ConnectionState::ReceiverIdle) {
        reject_and_close(connection,
                         "'" + request.target_username + "' is busy with another transfer");
        return;
    }

    std::uint64_t pairing_id = sessions_.create_pairing(connection, receiver);
    connection->pairing_id = pairing_id;
    receiver->pairing_id = pairing_id;
    connection->state = ConnectionState::SenderWaiting;
    receiver->state = ConnectionState::ReceiverMatched;

    // Copy the sender's half of the introduction across. Everything here came
    // from the sender's own hello; the server neither interprets the keys nor
    // checks the proof -- it cannot, since it has never seen the password.
    PeerIntroduction introduction;
    introduction.username = connection->hello.username;
    std::memcpy(introduction.identity_key, connection->hello.identity_key,
                sizeof(introduction.identity_key));
    std::memcpy(introduction.session_key, connection->hello.session_key,
                sizeof(introduction.session_key));
    std::memcpy(introduction.proof, request.proof, sizeof(introduction.proof));
    std::memcpy(introduction.signature, request.signature, sizeof(introduction.signature));
    introduction.pairing_id = pairing_id;
    introduction.transport_hint = request.transport_hint;

    // The candidate list is the sender's own addresses plus the one only the
    // server can supply: how the sender looks from outside its NAT.
    introduction.candidates = connection->hello.local_candidates;
    Endpoint reflexive = connection->observed_endpoint;
    reflexive.set_port(connection->hello.tcp_port);
    introduction.candidates.push_back(reflexive);

    receiver->enqueue_frame(MessageType::Incoming, introduction.encode());
    wake_for(receiver);

    total_introductions_.fetch_add(1);
    log::debug(connection->label() + " introduced to " + receiver->label());
}

void Server::handle_accept(const ConnectionPtr& connection, const Frame& frame) {
    if (connection->state != ConnectionState::ReceiverMatched) {
        reject_and_close(connection, "no introduction is waiting for a decision");
        return;
    }

    Pairing pairing;
    if (!sessions_.find_pairing(connection->pairing_id, pairing)) {
        reject_and_close(connection, "that introduction has expired");
        return;
    }

    ConnectionPtr sender = pairing.sender.lock();
    if (sender == nullptr) {
        connection->state = ConnectionState::ReceiverIdle;
        connection->pairing_id = 0;
        return;
    }

    // Validated only to the extent of being well-formed; the contents are the
    // peers' business.
    PeerIntroduction introduction = PeerIntroduction::decode(frame.payload);
    introduction.pairing_id = connection->pairing_id;

    introduction.candidates = connection->hello.local_candidates;
    Endpoint reflexive = connection->observed_endpoint;
    reflexive.set_port(connection->hello.tcp_port);
    introduction.candidates.push_back(reflexive);

    sender->enqueue_frame(MessageType::Matched, introduction.encode());
    wake_for(sender);
}

void Server::handle_reject(const ConnectionPtr& connection, const Frame& frame) {
    if (connection->pairing_id == 0) return;

    Pairing pairing;
    if (sessions_.find_pairing(connection->pairing_id, pairing)) {
        if (ConnectionPtr sender = pairing.sender.lock()) {
            if (sender != connection) {
                sender->enqueue_frame(MessageType::Reject, frame.payload);
                sender->request_close("the receiver declined");
                wake_for(sender);
            }
        }
        sessions_.destroy_pairing(connection->pairing_id);
    }

    // The receiver stays connected and available for the next sender.
    connection->pairing_id = 0;
    if (connection->state == ConnectionState::ReceiverMatched) {
        connection->state = ConnectionState::ReceiverIdle;
    }
}

void Server::handle_relay_open(const ConnectionPtr& connection, const Frame& frame) {
    (void)frame;

    if (!options_.allow_relay) {
        reject_and_close(connection, "this server does not relay; a direct path is required");
        return;
    }
    if (connection->pairing_id == 0) {
        reject_and_close(connection, "no pairing to relay");
        return;
    }

    Pairing pairing;
    if (!sessions_.find_pairing(connection->pairing_id, pairing)) {
        reject_and_close(connection, "that pairing has expired");
        return;
    }

    ConnectionPtr sender = pairing.sender.lock();
    ConnectionPtr receiver = pairing.receiver.lock();
    if (sender == nullptr || receiver == nullptr) {
        reject_and_close(connection, "the other peer disconnected");
        return;
    }

    bool from_sender = (sender == connection);
    if (!sessions_.request_relay(connection->pairing_id, from_sender)) {
        // Only one side has given up so far. Waiting for the other keeps the
        // peers in step: starting now would strand whichever one is still
        // punching.
        return;
    }

    sender->attach_relay_peer(receiver);
    receiver->attach_relay_peer(sender);
    // Relaying is published after both attachments, so a shard that observes
    // Relaying is guaranteed to find a peer. Reversing the two would let the
    // first RelayData land on a connection whose peer pointer is still empty,
    // which closes the transfer.
    sender->state = ConnectionState::Relaying;
    receiver->state = ConnectionState::Relaying;

    sender->enqueue_empty(MessageType::RelayOpen);
    receiver->enqueue_empty(MessageType::RelayOpen);
    wake_for(sender);
    wake_for(receiver);

    log::debug("relaying between " + sender->label() + " and " + receiver->label());
}

void Server::handle_relay_data(const ConnectionPtr& connection, const Frame& frame) {
    if (connection->state != ConnectionState::Relaying) {
        reject_and_close(connection, "this connection is not relaying");
        return;
    }

    ConnectionPtr peer = connection->relay_peer();
    if (peer == nullptr) {
        connection->request_close("the other peer disconnected");
        return;
    }

    // Forwarded verbatim. These bytes are the peers' end-to-end encrypted
    // stream: the server has no key for them, cannot tell one file from another
    // inside them, and does not keep a copy once the write drains.
    peer->enqueue_frame(MessageType::RelayData, frame.payload);
    total_relayed_bytes_.fetch_add(frame.payload.size());

    // Back-pressure. Without this a fast sender would fill the server's memory
    // with bytes a slow receiver has not taken yet.
    if (peer->pending_output() > kRelayPauseThreshold) connection->set_read_paused(true);

    wake_for(peer);
}

void Server::handle_relay_close(const ConnectionPtr& connection, const Frame& frame) {
    if (ConnectionPtr peer = connection->relay_peer()) {
        peer->enqueue_frame(MessageType::RelayClose, frame.payload);
        peer->request_close("the other peer closed the relay");
        wake_for(peer);
    }
    connection->request_close("relay closed");
}

void Server::reject_and_close(const ConnectionPtr& connection, const std::string& reason) {
    connection->enqueue_frame(MessageType::Reject, reason.data(), reason.size());
    connection->request_close(reason);
}

}  // namespace dz::server
