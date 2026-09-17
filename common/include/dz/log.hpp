// Minimal logging.
//
// The rendezvous server promises never to retain a peer's address, and a log
// line is retention: it lands in journald, gets shipped to a log collector and
// outlives the session by weeks. That promise is therefore enforced here rather
// than left to the discipline of each call site -- see the note on
// dz::log::describe_peer() below, which is the only sanctioned way for server
// code to refer to a particular connection in a message.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace dz::log {

enum class Level : int {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
};

/// Messages above this level are dropped. Defaults to Info.
void set_level(Level level);
Level level();

/// Parse "error", "warn", "info" or "debug". Returns false if unrecognised.
bool parse_level(std::string_view name, Level& out);

/// Prefix every line with a UTC timestamp. Off by default because the client
/// writes to a terminal, on for the server because journald-less deployments
/// need it.
void set_timestamps(bool enabled);

void write(Level level, std::string_view message);

inline void error(std::string_view message) { write(Level::Error, message); }
inline void warn(std::string_view message) { write(Level::Warn, message); }
inline void info(std::string_view message) { write(Level::Info, message); }
inline void debug(std::string_view message) { write(Level::Debug, message); }

/// Produce a stable, non-reversible label for a connection so that server logs
/// can correlate several lines about the same peer without recording who it is.
///
/// The label is derived from a random salt generated at process start-up and
/// never written down, so it is meaningless outside the lifetime of this
/// process and cannot be turned back into an address even by whoever holds the
/// logs. Server code must never format a sockaddr into a log message directly.
std::string describe_peer(std::uint64_t connection_id);

}  // namespace dz::log
