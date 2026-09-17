#include "dz/log.hpp"

#include <ctime>
#include <cstdio>
#include <mutex>

#include "dz/crypto.hpp"
#include "dz/endian.hpp"
#include "dz/secure.hpp"

namespace dz::log {
namespace {

Level g_level = Level::Info;
bool g_timestamps = false;

/// One mutex so that two threads cannot interleave halves of a line. Log volume
/// is a handful of lines per transfer, so the contention is irrelevant.
std::mutex& output_mutex() {
    static std::mutex mutex;
    return mutex;
}

/// Random per-process salt for describe_peer(). Generated on first use and
/// never stored, which is what makes the connection labels in the log
/// meaningless to anyone who later reads them.
const std::uint8_t* peer_label_salt() {
    static std::uint8_t salt[16] = {};
    static std::once_flag once;
    std::call_once(once, [] { random_bytes(salt, sizeof(salt)); });
    return salt;
}

const char* level_name(Level level) {
    switch (level) {
        case Level::Error: return "error";
        case Level::Warn: return "warn";
        case Level::Info: return "info";
        case Level::Debug: return "debug";
    }
    return "?";
}

}  // namespace

void set_level(Level level) { g_level = level; }

Level level() { return g_level; }

bool parse_level(std::string_view name, Level& out) {
    if (name == "error") { out = Level::Error; return true; }
    if (name == "warn" || name == "warning") { out = Level::Warn; return true; }
    if (name == "info") { out = Level::Info; return true; }
    if (name == "debug") { out = Level::Debug; return true; }
    return false;
}

void set_timestamps(bool enabled) { g_timestamps = enabled; }

void write(Level level, std::string_view message) {
    if (static_cast<int>(level) > static_cast<int>(g_level)) return;

    // Errors and warnings go to stderr so that a client run inside a pipeline
    // keeps its progress reporting separate from its problems.
    FILE* stream = (level <= Level::Warn) ? stderr : stdout;

    char timestamp[32] = {};
    if (g_timestamps) {
        std::time_t now = std::time(nullptr);
        std::tm parts{};
        gmtime_r(&now, &parts);
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ ", &parts);
    }

    std::lock_guard<std::mutex> guard(output_mutex());
    std::fprintf(stream, "%s%s: %.*s\n", timestamp, level_name(level),
                 static_cast<int>(message.size()), message.data());
    std::fflush(stream);
}

std::string describe_peer(std::uint64_t connection_id) {
    // HMAC of the connection id under the ephemeral salt, truncated. The
    // connection id itself is a counter and would already be address-free, but
    // hashing it under a secret salt also stops anybody correlating labels
    // across two log excerpts to count or order a server's sessions.
    std::uint8_t id_bytes[8];
    store_u64(id_bytes, connection_id);

    std::uint8_t mac[kSha256Size];
    hmac_sha256(peer_label_salt(), 16, id_bytes, sizeof(id_bytes), mac);

    return "peer/" + to_hex(mac, 4);
}

}  // namespace dz::log
