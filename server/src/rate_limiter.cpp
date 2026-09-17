#include "dz/server/rate_limiter.hpp"

#include <netinet/in.h>

#include <cstring>

#include "dz/crypto.hpp"
#include "dz/endian.hpp"

namespace dz::server {

RateLimiter::RateLimiter(const RateLimits& limits) : limits_(limits), salt_{} {
    random_bytes(salt_, sizeof(salt_));
}

std::uint64_t RateLimiter::key_for(const Endpoint& endpoint) const {
    // Only the address is hashed, not the port: a NAT gateway shares one address
    // across many ports, and an attacker behind one could otherwise get a fresh
    // bucket per source port simply by reconnecting.
    std::uint8_t address[16] = {};
    std::size_t length = 0;

    if (endpoint.family() == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(endpoint.sockaddr_ptr());
        std::memcpy(address, &v4->sin_addr, 4);
        length = 4;
    } else if (endpoint.family() == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(endpoint.sockaddr_ptr());
        // Only the /64 prefix. A single IPv6 client is routinely handed far more
        // than one address, so limiting per address would be no limit at all.
        std::memcpy(address, &v6->sin6_addr, 8);
        length = 8;
    } else {
        return 0;
    }

    std::uint8_t mac[kSha256Size];
    hmac_sha256(salt_, sizeof(salt_), address, length, mac);
    return load_u64(mac);
}

bool RateLimiter::allow_connection(std::uint64_t key, std::uint64_t now_ms) {
    return consume(key, now_ms, false);
}

bool RateLimiter::allow_request(std::uint64_t key, std::uint64_t now_ms) {
    return consume(key, now_ms, true);
}

bool RateLimiter::consume(std::uint64_t key, std::uint64_t now_ms, bool is_request) {
    std::lock_guard<std::mutex> guard(mutex_);

    auto existing = buckets_.find(key);
    if (existing == buckets_.end()) {
        if (buckets_.size() >= limits_.max_buckets) {
            // The table is full. Rather than track access order, drop the whole
            // thing: every bucket refills within a minute anyway, so the worst
            // case is that limits reset a little early under an attack broad
            // enough to fill 65536 buckets. Keeping the memory bounded matters
            // more than being precise here.
            buckets_.clear();
        }

        Bucket fresh{limits_.burst, limits_.burst, now_ms};
        existing = buckets_.emplace(key, fresh).first;
    }

    Bucket& bucket = existing->second;

    double elapsed_minutes = static_cast<double>(now_ms - bucket.last_refill_ms) / 60'000.0;
    if (elapsed_minutes > 0.0) {
        bucket.connection_tokens += elapsed_minutes * limits_.connections_per_minute;
        bucket.request_tokens += elapsed_minutes * limits_.requests_per_minute;

        if (bucket.connection_tokens > limits_.burst) bucket.connection_tokens = limits_.burst;
        if (bucket.request_tokens > limits_.burst) bucket.request_tokens = limits_.burst;

        bucket.last_refill_ms = now_ms;
    }

    double& tokens = is_request ? bucket.request_tokens : bucket.connection_tokens;
    if (tokens < 1.0) return false;

    tokens -= 1.0;
    return true;
}

std::size_t RateLimiter::evict_idle(std::uint64_t now_ms, std::uint64_t idle_ms) {
    std::lock_guard<std::mutex> guard(mutex_);

    std::size_t removed = 0;
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        if (now_ms - it->second.last_refill_ms > idle_ms) {
            it = buckets_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

std::size_t RateLimiter::bucket_count() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return buckets_.size();
}

}  // namespace dz::server
