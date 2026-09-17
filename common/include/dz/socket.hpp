// Socket ownership, socket tuning and address handling.

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dz {

/// Owns a file descriptor and closes it exactly once. The prototype leaked a
/// descriptor on every error path that called exit() from a helper; with this
/// type an exception unwinding out of a transfer closes everything it opened.
class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : fd_(fd) {}
    ~Fd() { reset(); }

    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    /// Relinquish ownership without closing.
    int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void reset(int fd = -1) noexcept;

private:
    int fd_ = -1;
};

/// An IPv4 or IPv6 socket address.
///
/// Kept as a sockaddr_storage rather than a parsed string because that is the
/// form the kernel wants, and the hole-punching code compares addresses for
/// equality far more often than it prints them.
class Endpoint {
public:
    Endpoint() noexcept;

    static Endpoint from_sockaddr(const sockaddr* addr, socklen_t len);

    /// Parse "host:port", "1.2.3.4:9000" or "[::1]:9000". Does not resolve DNS.
    static bool parse(std::string_view text, Endpoint& out);

    /// Resolve "host:port" through getaddrinfo, returning every address the
    /// name has. A server published under both an A and an AAAA record yields
    /// two entries and the client tries them in order.
    static std::vector<Endpoint> resolve(std::string_view host, std::uint16_t port);

    const sockaddr* sockaddr_ptr() const noexcept;
    sockaddr* sockaddr_ptr() noexcept;
    socklen_t sockaddr_len() const noexcept { return len_; }
    void set_sockaddr_len(socklen_t len) noexcept { len_ = len; }

    int family() const noexcept;
    std::uint16_t port() const noexcept;
    void set_port(std::uint16_t port) noexcept;

    bool is_unspecified() const noexcept;
    bool is_loopback() const noexcept;

    /// True for RFC1918 / RFC4193 / link-local addresses. Used to sort the
    /// candidate list so that same-LAN pairs try their private addresses first.
    bool is_private() const noexcept;

    std::string ip_string() const;
    std::string to_string() const;

    bool operator==(const Endpoint& other) const noexcept;
    bool operator!=(const Endpoint& other) const noexcept { return !(*this == other); }

    /// This address in the IPv4-mapped IPv6 form ::ffff:a.b.c.d.
    ///
    /// A dual-stack AF_INET6 socket can only reach an IPv4 host through this form;
    /// handing it a plain sockaddr_in fails with EAFNOSUPPORT. Returns *this
    /// unchanged when it is already IPv6.
    Endpoint as_v4_mapped() const;

private:
    sockaddr_storage storage_{};
    socklen_t len_ = 0;
};

void set_nonblocking(int fd, bool enabled);

void set_close_on_exec(int fd);

void set_reuse_addr(int fd);

/// Enable SO_REUSEPORT. The server uses it to let several event-loop threads
/// each own a listening socket for the same port, which spreads accept() work
/// across cores instead of funnelling it through one thread.
bool set_reuse_port(int fd);

/// Disable Nagle's algorithm. drop-zone writes large framed chunks and then
/// waits for the peer, which is precisely the pattern Nagle penalises: it would
/// hold the tail of a chunk back for an ACK that only arrives once the peer has
/// seen that tail.
void set_tcp_nodelay(int fd, bool enabled = true);

/// Request send and receive buffers of `bytes`. The kernel usually grants less
/// than asked, and that is fine -- the point is to raise the ceiling on the
/// bandwidth-delay product the socket can keep in flight on a fast long link.
void set_socket_buffers(int fd, int bytes);

/// Suppress SIGPIPE for writes to this socket where the platform supports it
/// (SO_NOSIGPIPE on macOS). On Linux the process ignores SIGPIPE globally and
/// writes pass MSG_NOSIGNAL instead.
void set_no_sigpipe(int fd);

/// Ignore SIGPIPE process-wide, so a peer disappearing mid-transfer surfaces as
/// EPIPE from write() instead of killing the process.
void ignore_sigpipe();

Endpoint local_endpoint(int fd);
Endpoint peer_endpoint(int fd);

/// Convert `target` into a form a socket of `socket_family` can send to.
///
/// Needed because a candidate list mixes IPv4 and IPv6 addresses while a socket has
/// one family for life. An IPv4 target reached from a dual-stack IPv6 socket becomes
/// its IPv4-mapped form; an IPv4-mapped target reached from an IPv4 socket is
/// unwrapped. Returns false for a pair that cannot be reconciled at all, such as a
/// real IPv6 address from an IPv4-only socket, which the caller should skip.
bool adapt_endpoint_for_socket(const Endpoint& target, int socket_family, Endpoint& out);

/// Write every byte or throw. Handles short writes and EINTR.
void write_all(int fd, const void* data, std::size_t len);

/// Read exactly `len` bytes or throw. Throws PeerClosed on a clean EOF at a
/// message boundary so callers can tell "peer went away" from "peer sent junk".
void read_exact(int fd, void* data, std::size_t len);

/// Wait until `fd` is readable. Returns false on timeout.
bool wait_readable(int fd, int timeout_ms);

/// Wait until `fd` is readable, with a microsecond timeout.
///
/// poll() only takes whole milliseconds, which is far too coarse for pacing a
/// transport: the interval between packets on a fast path is a few microseconds, so
/// rounding a wait up to a millisecond turns a small delay into a large one. ppoll on
/// Linux accepts a timespec and honours it to within the kernel's timer slack, around
/// fifty microseconds. Elsewhere this rounds up to the nearest millisecond, which is
/// the best poll() can express.
bool wait_readable_micros(int fd, std::uint64_t timeout_us);

/// Wait until `fd` is writable. Returns false on timeout.
bool wait_writable(int fd, int timeout_ms);

/// Every usable unicast address of every up interface, excluding loopback
/// unless `include_loopback` is set. These become the local half of the
/// candidate list exchanged during hole punching, which is what lets two peers
/// on the same LAN find each other directly instead of hairpinning through
/// their router.
std::vector<Endpoint> local_interface_addresses(bool include_loopback);

/// Milliseconds on a monotonic clock. Used for every timeout and RTT estimate;
/// deliberately not the wall clock, which can jump backwards mid-transfer.
std::uint64_t monotonic_millis();

std::uint64_t monotonic_micros();

}  // namespace dz
