// Abuse limiting that does not require remembering who anybody is.
//
// A rate limiter normally keys on the client's address, which would be exactly
// the kind of retention the server promises to avoid. The way out is that a
// token bucket does not need the address itself, only a stable key for it: the
// bucket is keyed by a keyed hash of the address under a salt generated at
// start-up and never written down.
//
// What that buys and what it does not:
//
//  * The salt exists only in this process's memory and dies with it, so a
//    memory image or a leaked table cannot be turned back into a list of who
//    connected -- the keys are not reversible without the salt, and a dictionary
//    attack over the whole IPv4 space would need it too.
//  * It is not a claim that the server never handles addresses. The kernel knows
//    the peer of every open socket, and the introduction the server exists to
//    perform is precisely an exchange of addresses between two peers. The
//    promise is that none of it is written down or kept past the session.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "dz/socket.hpp"

namespace dz::server {

struct RateLimits {
    /// New connections allowed from one address per minute.
    double connections_per_minute = 60.0;
    /// Introduction requests allowed from one address per minute. Lower than the
    /// connection limit because a wrong public password is only detectable by
    /// the receiver, so this is the one knob that slows a password-guessing run.
    double requests_per_minute = 20.0;
    /// Burst allowance, so a legitimate client retrying twice is not throttled.
    double burst = 10.0;
    /// Buckets to keep before evicting the least recently used.
    std::size_t max_buckets = 65536;
};

class RateLimiter {
public:
    explicit RateLimiter(const RateLimits& limits);

    /// Derive this address's bucket key. The address is used and discarded; only
    /// the key is stored.
    std::uint64_t key_for(const Endpoint& endpoint) const;

    /// Charge one connection against `key`. Returns false when the caller should
    /// be refused.
    bool allow_connection(std::uint64_t key, std::uint64_t now_ms);

    /// Charge one introduction request against `key`.
    bool allow_request(std::uint64_t key, std::uint64_t now_ms);

    /// Drop buckets that have been full and untouched long enough that they
    /// carry no information.
    std::size_t evict_idle(std::uint64_t now_ms, std::uint64_t idle_ms);

    std::size_t bucket_count() const;

private:
    struct Bucket {
        double connection_tokens;
        double request_tokens;
        std::uint64_t last_refill_ms;
    };

    /// Refill and charge one token. Returns false when the bucket is empty.
    bool consume(std::uint64_t key, std::uint64_t now_ms, bool is_request);

    RateLimits limits_;
    std::uint8_t salt_[16];

    mutable std::mutex mutex_;
    std::unordered_map<std::uint64_t, Bucket> buckets_;
};

}  // namespace dz::server
