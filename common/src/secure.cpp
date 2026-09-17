#include "dz/secure.hpp"

#include <openssl/crypto.h>
#include <sys/resource.h>

#include <cstdio>

namespace dz {

void secure_zero(void* p, std::size_t len) noexcept {
    if (p == nullptr || len == 0) return;
    // OPENSSL_cleanse exists precisely because a memset() on a dying buffer is
    // dead code that -O3 removes; it uses a volatile write loop the optimiser
    // must keep.
    OPENSSL_cleanse(p, len);
}

bool constant_time_equal(const void* a, const void* b, std::size_t len) noexcept {
    return CRYPTO_memcmp(a, b, len) == 0;
}

void disable_core_dumps() noexcept {
    rlimit limit{};
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    // A best-effort hardening step: if the platform refuses, the server still
    // runs, it just no longer guarantees that a crash cannot write the session
    // table to disk. Nothing useful can be done about the failure here.
    (void)setrlimit(RLIMIT_CORE, &limit);
}

std::string to_hex(const void* data, std::size_t len) {
    static const char kDigits[] = "0123456789abcdef";
    const auto* bytes = static_cast<const std::uint8_t*>(data);

    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kDigits[bytes[i] >> 4];
        out[2 * i + 1] = kDigits[bytes[i] & 0x0f];
    }
    return out;
}

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

bool from_hex(std::string_view hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;

    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);
        if (high < 0 || low < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>(high << 4 | low));
    }
    return true;
}

}  // namespace dz
