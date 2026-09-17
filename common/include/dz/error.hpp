// Error reporting for drop-zone.
//
// The C prototype this replaces called perror() and exit(1) from wherever the
// failure happened, which made it impossible for a caller to recover -- a
// rejected transfer had to tear down the whole process. Here every failure
// raises dz::Error instead, and the two main() functions are the only places
// that turn an error into an exit status and a message on stderr.

#pragma once

#include <cerrno>
#include <stdexcept>
#include <string>
#include <string_view>

namespace dz {

/// Every deliberate failure in drop-zone is reported by throwing this type.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

/// A failure the user is expected to fix (bad password, unknown peer, ...).
/// Distinguished from Error so main() can suppress the "unexpected" framing.
class UserError : public Error {
public:
    explicit UserError(const std::string& message) : Error(message) {}
};

/// Thrown when the peer closed the connection cleanly mid-protocol.
class PeerClosed : public Error {
public:
    PeerClosed() : Error("peer closed the connection") {}
};

[[noreturn]] void fail(std::string_view message);

[[noreturn]] void fail_user(std::string_view message);

/// Raise an Error describing `what` followed by strerror(err), the C++
/// equivalent of the prototype's perror() calls.
[[noreturn]] void fail_errno(std::string_view what, int err = errno);

/// Raise an Error naming the most recent OpenSSL failure. libcrypto keeps a
/// per-thread error queue; this drains it so a later unrelated failure cannot
/// report a stale reason.
[[noreturn]] void fail_openssl(std::string_view what);

/// Empty libcrypto's per-thread error queue.
///
/// Needed wherever a libcrypto failure is an expected outcome rather than a
/// bug -- a chunk with a bad authentication tag, say. The queue is per thread
/// and never drains itself, so entries left behind would surface later as the
/// reason for an unrelated failure.
void clear_openssl_errors() noexcept;

/// Return `value` if it is not -1, otherwise fail_errno(what).
int check_syscall(int value, std::string_view what);

}  // namespace dz
