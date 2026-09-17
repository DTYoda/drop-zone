// The server's entire memory: who is currently accepting, and who is currently
// being introduced to whom.
//
// Everything here is in-process and transient. There is no database, no file
// and no account registry, which is a deliberate consequence of the promise
// that the server retains nothing:
//
//  * A username is claimed when a receiver enters accept mode and released the
//    moment its socket closes. Two people can use the same username on
//    different days; only one can be accepting at any instant.
//  * A pairing exists from the moment a sender is matched with a receiver until
//    either of them disconnects.
//
// The cost of having no registry is that the server cannot vouch for who owns a
// username. That job belongs to the clients, which pin a peer's Ed25519
// identity key the first time they see it -- see client/src/known_peers.cpp.

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "dz/server/connection.hpp"

namespace dz::server {

/// Two connections the server has introduced to each other.
struct Pairing {
    std::uint64_t id = 0;
    std::weak_ptr<Connection> sender;
    std::weak_ptr<Connection> receiver;
    /// Set once each side has asked to fall back to relaying.
    bool sender_wants_relay = false;
    bool receiver_wants_relay = false;
    bool relay_active = false;
    std::uint64_t created_ms = 0;
};

/// Outcome of trying to claim a username.
enum class ClaimResult {
    Granted,
    AlreadyClaimed,
    InvalidUsername,
};

class SessionTable {
public:
    /// Claim `username` for `connection`. One map guarded by one mutex: a
    /// sharded table would be pointless here because a claim happens once per
    /// accept-mode session, not once per packet.
    ClaimResult claim(const std::string& username, const ConnectionPtr& connection);

    /// Release a claim if `connection` still holds it. Idempotent, because
    /// teardown can be reached from more than one path.
    void release(const std::string& username, const Connection* connection);

    /// The connection currently accepting under `username`, or nullptr.
    ConnectionPtr lookup(const std::string& username) const;

    /// Record a new pairing and return its id. Ids come from a counter mixed
    /// with random bits so that one cannot be guessed by a third party trying to
    /// hijack a relay.
    std::uint64_t create_pairing(const ConnectionPtr& sender, const ConnectionPtr& receiver);

    /// Look up a pairing, returning false if it has expired or never existed.
    bool find_pairing(std::uint64_t id, Pairing& out) const;

    /// Note that one side wants to relay. Returns true once both sides have
    /// asked, which is when the server starts forwarding.
    bool request_relay(std::uint64_t id, bool from_sender);

    void destroy_pairing(std::uint64_t id);

    /// Drop pairings older than `max_age_ms` whose peers have gone away. Called
    /// from the maintenance tick so an abandoned introduction cannot leak a
    /// table entry for the lifetime of the process.
    std::size_t expire_pairings(std::uint64_t now_ms, std::uint64_t max_age_ms);

    std::size_t claimed_usernames() const;
    std::size_t active_pairings() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::weak_ptr<Connection>> claims_;
    std::unordered_map<std::uint64_t, Pairing> pairings_;
    std::uint64_t next_pairing_counter_ = 1;
    std::uint64_t pairing_id_salt_ = 0;
    bool salt_ready_ = false;
};

}  // namespace dz::server
