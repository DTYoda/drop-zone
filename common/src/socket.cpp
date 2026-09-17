#include "dz/socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <ctime>

#include "dz/error.hpp"

namespace dz {

// ---------------------------------------------------------------------------
// Fd
// ---------------------------------------------------------------------------

void Fd::reset(int fd) noexcept {
    if (fd_ >= 0 && fd_ != fd) {
        // Retrying close() on EINTR is wrong on Linux -- the descriptor is
        // already gone and the number may have been reused by another thread --
        // so the result is deliberately ignored.
        ::close(fd_);
    }
    fd_ = fd;
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

Endpoint::Endpoint() noexcept { storage_.ss_family = AF_UNSPEC; }

Endpoint Endpoint::from_sockaddr(const sockaddr* addr, socklen_t len) {
    Endpoint endpoint;
    if (len > static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        fail("socket address larger than sockaddr_storage");
    }
    std::memcpy(&endpoint.storage_, addr, len);
    endpoint.len_ = len;

    // A dual-stack listening socket reports an IPv4 client as the mapped address
    // ::ffff:1.2.3.4. Left in that form it would be handed to the other peer as a
    // candidate that only an AF_INET6 socket can reach, so it is unwrapped back
    // into the plain IPv4 address it stands for.
    if (endpoint.storage_.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&endpoint.storage_);
        if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
            std::uint16_t port = v6->sin6_port;
            in_addr v4_address{};
            std::memcpy(&v4_address, v6->sin6_addr.s6_addr + 12, 4);

            sockaddr_in v4{};
            v4.sin_family = AF_INET;
            v4.sin_port = port;
            v4.sin_addr = v4_address;

            std::memset(&endpoint.storage_, 0, sizeof(endpoint.storage_));
            std::memcpy(&endpoint.storage_, &v4, sizeof(v4));
            endpoint.len_ = sizeof(v4);
        }
    }

    return endpoint;
}

bool Endpoint::parse(std::string_view text, Endpoint& out) {
    if (text.empty()) return false;

    std::string_view host;
    std::string_view port_text;

    if (text.front() == '[') {
        // Bracketed IPv6: [::1]:9000
        std::size_t close = text.find(']');
        if (close == std::string_view::npos || close + 2 >= text.size() || text[close + 1] != ':') {
            return false;
        }
        host = text.substr(1, close - 1);
        port_text = text.substr(close + 2);
    } else {
        std::size_t colon = text.rfind(':');
        if (colon == std::string_view::npos) return false;
        host = text.substr(0, colon);
        port_text = text.substr(colon + 1);
        // A bare IPv6 literal has more than one colon and no port.
        if (host.find(':') != std::string_view::npos) return false;
    }

    unsigned port = 0;
    auto result = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (result.ec != std::errc() || result.ptr != port_text.data() + port_text.size()) return false;
    if (port == 0 || port > 65535) return false;

    std::string host_string(host);

    Endpoint endpoint;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&endpoint.storage_);
    if (::inet_pton(AF_INET, host_string.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(static_cast<std::uint16_t>(port));
        endpoint.len_ = sizeof(sockaddr_in);
        out = endpoint;
        return true;
    }

    auto* v6 = reinterpret_cast<sockaddr_in6*>(&endpoint.storage_);
    std::memset(v6, 0, sizeof(*v6));
    if (::inet_pton(AF_INET6, host_string.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(static_cast<std::uint16_t>(port));
        endpoint.len_ = sizeof(sockaddr_in6);
        out = endpoint;
        return true;
    }

    return false;
}

std::vector<Endpoint> Endpoint::resolve(std::string_view host, std::uint16_t port) {
    std::string host_string(host);
    std::string port_string = std::to_string(port);

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;
    int rc = ::getaddrinfo(host_string.c_str(), port_string.c_str(), &hints, &results);
    if (rc != 0) {
        fail("cannot resolve '" + host_string + "': " + ::gai_strerror(rc));
    }

    std::vector<Endpoint> endpoints;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
        endpoints.push_back(from_sockaddr(it->ai_addr, it->ai_addrlen));
    }
    ::freeaddrinfo(results);

    if (endpoints.empty()) fail("cannot resolve '" + host_string + "': no addresses");
    return endpoints;
}

const sockaddr* Endpoint::sockaddr_ptr() const noexcept {
    return reinterpret_cast<const sockaddr*>(&storage_);
}

sockaddr* Endpoint::sockaddr_ptr() noexcept { return reinterpret_cast<sockaddr*>(&storage_); }

int Endpoint::family() const noexcept { return storage_.ss_family; }

std::uint16_t Endpoint::port() const noexcept {
    if (storage_.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&storage_)->sin_port);
    }
    if (storage_.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_port);
    }
    return 0;
}

void Endpoint::set_port(std::uint16_t port) noexcept {
    if (storage_.ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(&storage_)->sin_port = htons(port);
    } else if (storage_.ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(&storage_)->sin6_port = htons(port);
    }
}

bool Endpoint::is_unspecified() const noexcept {
    if (storage_.ss_family == AF_INET) {
        return reinterpret_cast<const sockaddr_in*>(&storage_)->sin_addr.s_addr == INADDR_ANY;
    }
    if (storage_.ss_family == AF_INET6) {
        const auto& addr = reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_addr;
        return IN6_IS_ADDR_UNSPECIFIED(&addr);
    }
    return true;
}

bool Endpoint::is_loopback() const noexcept {
    if (storage_.ss_family == AF_INET) {
        std::uint32_t addr = ntohl(reinterpret_cast<const sockaddr_in*>(&storage_)->sin_addr.s_addr);
        return (addr >> 24) == 127;
    }
    if (storage_.ss_family == AF_INET6) {
        const auto& addr = reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(&addr);
    }
    return false;
}

bool Endpoint::is_private() const noexcept {
    if (storage_.ss_family == AF_INET) {
        std::uint32_t addr = ntohl(reinterpret_cast<const sockaddr_in*>(&storage_)->sin_addr.s_addr);
        std::uint32_t first = addr >> 24;
        std::uint32_t second = (addr >> 16) & 0xff;
        if (first == 10) return true;                                  // 10/8
        if (first == 172 && second >= 16 && second <= 31) return true;  // 172.16/12
        if (first == 192 && second == 168) return true;                 // 192.168/16
        if (first == 169 && second == 254) return true;                 // link-local
        if (first == 127) return true;
        return false;
    }
    if (storage_.ss_family == AF_INET6) {
        const auto& addr = reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(&addr)) return true;
        if (IN6_IS_ADDR_LINKLOCAL(&addr)) return true;
        if (IN6_IS_ADDR_SITELOCAL(&addr)) return true;
        return (addr.s6_addr[0] & 0xfe) == 0xfc;  // fc00::/7 unique-local
    }
    return false;
}

std::string Endpoint::ip_string() const {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (storage_.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&storage_);
        ::inet_ntop(AF_INET, &v4->sin_addr, buffer, sizeof(buffer));
    } else if (storage_.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&storage_);
        ::inet_ntop(AF_INET6, &v6->sin6_addr, buffer, sizeof(buffer));
    } else {
        return "unspecified";
    }
    return buffer;
}

std::string Endpoint::to_string() const {
    if (storage_.ss_family == AF_INET6) {
        return "[" + ip_string() + "]:" + std::to_string(port());
    }
    if (storage_.ss_family == AF_INET) {
        return ip_string() + ":" + std::to_string(port());
    }
    return "unspecified";
}

bool Endpoint::operator==(const Endpoint& other) const noexcept {
    if (storage_.ss_family != other.storage_.ss_family) return false;

    if (storage_.ss_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(&storage_);
        const auto* b = reinterpret_cast<const sockaddr_in*>(&other.storage_);
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    if (storage_.ss_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(&storage_);
        const auto* b = reinterpret_cast<const sockaddr_in6*>(&other.storage_);
        // The scope id is deliberately excluded: the same link-local address
        // reported by two hosts carries their own local interface indices.
        return a->sin6_port == b->sin6_port &&
               std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Socket options
// ---------------------------------------------------------------------------

void set_nonblocking(int fd, bool enabled) {
    int flags = check_syscall(::fcntl(fd, F_GETFL, 0), "fcntl(F_GETFL)");
    int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    check_syscall(::fcntl(fd, F_SETFL, updated), "fcntl(F_SETFL)");
}

void set_close_on_exec(int fd) {
    int flags = check_syscall(::fcntl(fd, F_GETFD, 0), "fcntl(F_GETFD)");
    check_syscall(::fcntl(fd, F_SETFD, flags | FD_CLOEXEC), "fcntl(F_SETFD)");
}

void set_reuse_addr(int fd) {
    int on = 1;
    check_syscall(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)),
                  "setsockopt(SO_REUSEADDR)");
}

bool set_reuse_port(int fd) {
#ifdef SO_REUSEPORT
    int on = 1;
    return ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == 0;
#else
    (void)fd;
    return false;
#endif
}

void set_tcp_nodelay(int fd, bool enabled) {
    int on = enabled ? 1 : 0;
    // Not fatal: the option is meaningless on a UDP or Unix socket, and a
    // transfer that keeps Nagle enabled is slower but still correct.
    (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

void set_socket_buffers(int fd, int bytes) {
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
}

void set_no_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int on = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    (void)fd;
#endif
}

void ignore_sigpipe() {
    struct sigaction action{};
    action.sa_handler = SIG_IGN;
    (void)::sigaction(SIGPIPE, &action, nullptr);
}

Endpoint local_endpoint(int fd) {
    sockaddr_storage storage{};
    socklen_t len = sizeof(storage);
    check_syscall(::getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &len), "getsockname");
    return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), len);
}

Endpoint peer_endpoint(int fd) {
    sockaddr_storage storage{};
    socklen_t len = sizeof(storage);
    check_syscall(::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &len), "getpeername");
    return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), len);
}

// ---------------------------------------------------------------------------
// Blocking transfer helpers
// ---------------------------------------------------------------------------

void write_all(int fd, const void* data, std::size_t len) {
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = len;

    while (remaining > 0) {
#ifdef MSG_NOSIGNAL
        ssize_t written = ::send(fd, cursor, remaining, MSG_NOSIGNAL);
#else
        ssize_t written = ::send(fd, cursor, remaining, 0);
#endif
        if (written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // The socket is only non-blocking on paths that also apply
                // their own back-pressure, but wait here so this helper is
                // usable either way.
                if (!wait_writable(fd, 30'000)) fail("socket write timed out");
                continue;
            }
            fail_errno("write to socket failed");
        }
        cursor += written;
        remaining -= static_cast<std::size_t>(written);
    }
}

void read_exact(int fd, void* data, std::size_t len) {
    auto* cursor = static_cast<std::uint8_t*>(data);
    std::size_t remaining = len;

    while (remaining > 0) {
        ssize_t got = ::recv(fd, cursor, remaining, 0);
        if (got == 0) {
            // A clean EOF at the very start of a read is the peer hanging up
            // between messages, which callers treat as an orderly end.
            throw PeerClosed();
        }
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!wait_readable(fd, 120'000)) fail("socket read timed out");
                continue;
            }
            fail_errno("read from socket failed");
        }
        cursor += got;
        remaining -= static_cast<std::size_t>(got);
    }
}

namespace {

bool wait_for(int fd, short events, int timeout_ms) {
    pollfd entry{};
    entry.fd = fd;
    entry.events = events;

    std::uint64_t deadline = monotonic_millis() + static_cast<std::uint64_t>(timeout_ms);
    for (;;) {
        int rc = ::poll(&entry, 1, timeout_ms);
        if (rc > 0) return true;
        if (rc == 0) return false;
        if (errno != EINTR) fail_errno("poll failed");

        // A signal cut the wait short; resume with whatever time is left.
        std::uint64_t now = monotonic_millis();
        if (now >= deadline) return false;
        timeout_ms = static_cast<int>(deadline - now);
    }
}

}  // namespace

bool wait_readable(int fd, int timeout_ms) { return wait_for(fd, POLLIN, timeout_ms); }

bool wait_writable(int fd, int timeout_ms) { return wait_for(fd, POLLOUT, timeout_ms); }

// ---------------------------------------------------------------------------
// Interface enumeration and clocks
// ---------------------------------------------------------------------------

std::vector<Endpoint> local_interface_addresses(bool include_loopback) {
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) fail_errno("getifaddrs failed");

    std::vector<Endpoint> addresses;
    for (ifaddrs* it = list; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr) continue;
        if ((it->ifa_flags & IFF_UP) == 0) continue;

        socklen_t len;
        if (it->ifa_addr->sa_family == AF_INET) {
            len = sizeof(sockaddr_in);
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            len = sizeof(sockaddr_in6);
        } else {
            continue;
        }

        Endpoint endpoint = Endpoint::from_sockaddr(it->ifa_addr, len);
        if (endpoint.is_unspecified()) continue;
        if (endpoint.is_loopback() && !include_loopback) continue;

        bool duplicate = false;
        for (const Endpoint& existing : addresses) {
            if (existing.ip_string() == endpoint.ip_string()) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) addresses.push_back(endpoint);
    }
    ::freeifaddrs(list);

    return addresses;
}

std::uint64_t monotonic_millis() { return monotonic_micros() / 1000; }

std::uint64_t monotonic_micros() {
    timespec now{};
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<std::uint64_t>(now.tv_sec) * 1'000'000 +
           static_cast<std::uint64_t>(now.tv_nsec) / 1000;
}

}  // namespace dz
