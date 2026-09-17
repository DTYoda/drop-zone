#include "dz/server/session_table.hpp"

#include "dz/crypto.hpp"
#include "dz/protocol.hpp"
#include "dz/socket.hpp"

namespace dz::server {

ClaimResult SessionTable::claim(const std::string& username, const ConnectionPtr& connection) {
    if (!is_valid_username(username)) return ClaimResult::InvalidUsername;

    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = claims_.find(username);
    if (existing != claims_.end()) {
        // A weak_ptr that has expired means the previous holder's connection was
        // destroyed without a clean release, so the name is free again.
        if (existing->second.lock() != nullptr) return ClaimResult::AlreadyClaimed;
        claims_.erase(existing);
    }

    claims_.emplace(username, connection);
    return ClaimResult::Granted;
}

void SessionTable::release(const std::string& username, const Connection* connection) {
    if (username.empty()) return;

    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = claims_.find(username);
    if (existing == claims_.end()) return;

    // Only the current holder may release, so a stale teardown cannot evict a
    // newer session that has since claimed the same name.
    ConnectionPtr holder = existing->second.lock();
    if (holder == nullptr || holder.get() == connection) claims_.erase(existing);
}

ConnectionPtr SessionTable::lookup(const std::string& username) const {
    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = claims_.find(username);
    if (existing == claims_.end()) return nullptr;
    return existing->second.lock();
}

std::uint64_t SessionTable::create_pairing(const ConnectionPtr& sender,
                                          const ConnectionPtr& receiver) {
    std::lock_guard<std::mutex> guard(mutex_);

    if (!salt_ready_) {
        random_bytes(&pairing_id_salt_, sizeof(pairing_id_salt_));
        salt_ready_ = true;
    }

    // A plain counter would let anybody who has ever been paired guess the ids
    // of other people's pairings and try to attach to their relay. Mixing in a
    // per-process random salt keeps the ids unique without making them
    // predictable.
    std::uint64_t id = 0;
    do {
        id = next_pairing_counter_++ ^ pairing_id_salt_;
    } while (id == 0 || pairings_.count(id) != 0);

    Pairing pairing;
    pairing.id = id;
    pairing.sender = sender;
    pairing.receiver = receiver;
    pairing.created_ms = monotonic_millis();
    pairings_.emplace(id, pairing);

    return id;
}

bool SessionTable::find_pairing(std::uint64_t id, Pairing& out) const {
    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = pairings_.find(id);
    if (existing == pairings_.end()) return false;

    out = existing->second;
    return true;
}

bool SessionTable::request_relay(std::uint64_t id, bool from_sender) {
    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = pairings_.find(id);
    if (existing == pairings_.end()) return false;

    Pairing& pairing = existing->second;
    if (from_sender) {
        pairing.sender_wants_relay = true;
    } else {
        pairing.receiver_wants_relay = true;
    }

    // Relaying only starts once both peers have given up on a direct path.
    // Starting when only one has asked would strand the other still punching.
    if (pairing.sender_wants_relay && pairing.receiver_wants_relay && !pairing.relay_active) {
        pairing.relay_active = true;
        return true;
    }
    return false;
}

void SessionTable::destroy_pairing(std::uint64_t id) {
    std::lock_guard<std::mutex> guard(mutex_);
    pairings_.erase(id);
}

std::size_t SessionTable::expire_pairings(std::uint64_t now_ms, std::uint64_t max_age_ms) {
    std::lock_guard<std::mutex> guard(mutex_);

    std::size_t removed = 0;
    for (auto it = pairings_.begin(); it != pairings_.end();) {
        const Pairing& pairing = it->second;

        bool both_gone = pairing.sender.expired() && pairing.receiver.expired();
        bool too_old = now_ms - pairing.created_ms > max_age_ms;

        if (both_gone || too_old) {
            it = pairings_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

std::size_t SessionTable::claimed_usernames() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return claims_.size();
}

std::size_t SessionTable::active_pairings() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return pairings_.size();
}

}  // namespace dz::server
