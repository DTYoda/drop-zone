// Walking the transport ladder.

#include "dz/client/transport.hpp"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "dz/client/reliable_udp.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"

namespace dz::client {
namespace {

/// Attempts at finding a port both a TCP listener and a UDP socket can have.
///
/// Sharing one number is what lets a single candidate list serve both tiers. The
/// two protocols have separate port spaces so a collision is uncommon, but
/// something else may already hold the UDP side of a port the TCP bind just won.
constexpr int kPortAttempts = 32;

/// Bind a TCP listener to `port` (0 for any) and return it.
Fd bind_listener(std::uint16_t port) {
    Fd listener(::socket(AF_INET6, SOCK_STREAM, 0));
    bool dual_stack = listener.valid();

    if (!dual_stack) {
        // A machine with IPv6 disabled entirely. IPv4 alone still works, it just
        // cannot be reached by an IPv6 peer.
        listener.reset(::socket(AF_INET, SOCK_STREAM, 0));
        if (!listener.valid()) fail_errno("cannot create a listening socket");
    }

    set_close_on_exec(listener.get());
    set_reuse_addr(listener.get());

    if (dual_stack) {
        int off = 0;
        (void)::setsockopt(listener.get(), IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_any;
        address.sin6_port = htons(port);
        if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            return Fd();
        }
    } else {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            return Fd();
        }
    }

    if (::listen(listener.get(), 8) != 0) return Fd();
    return listener;
}

/// Bind a UDP socket to a specific port.
Fd bind_udp(std::uint16_t port) {
    Fd socket_fd(::socket(AF_INET6, SOCK_DGRAM, 0));
    bool dual_stack = socket_fd.valid();

    if (!dual_stack) {
        socket_fd.reset(::socket(AF_INET, SOCK_DGRAM, 0));
        if (!socket_fd.valid()) fail_errno("cannot create a UDP socket");
    }

    set_close_on_exec(socket_fd.get());

    if (dual_stack) {
        int off = 0;
        (void)::setsockopt(socket_fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_any;
        address.sin6_port = htons(port);
        if (::bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            return Fd();
        }
    } else {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        if (::bind(socket_fd.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            return Fd();
        }
    }

    // Every UDP path here -- reflexive discovery, punching, the reliable stream --
    // drains the socket until EAGAIN, so it must never block.
    set_nonblocking(socket_fd.get(), true);
    return socket_fd;
}

}  // namespace

LocalSockets open_local_sockets(bool include_loopback) {
    LocalSockets sockets;

    for (int attempt = 0; attempt < kPortAttempts; ++attempt) {
        // Let the kernel pick, then try to claim the same number for UDP.
        Fd listener = bind_listener(0);
        if (!listener.valid()) continue;

        std::uint16_t port = local_endpoint(listener.get()).port();

        Fd udp = bind_udp(port);
        if (!udp.valid()) continue;  // Something else holds the UDP side; try again.

        sockets.tcp_listener = std::move(listener);
        sockets.udp_socket = std::move(udp);
        sockets.port = port;
        break;
    }

    if (!sockets.tcp_listener.valid()) {
        fail("could not find a port available for both TCP and UDP after " +
             std::to_string(kPortAttempts) + " attempts");
    }

    set_nonblocking(sockets.tcp_listener.get(), true);

    // Advertise every address this machine has, each carrying the shared port. On
    // a LAN this is what lets the peers connect directly without either of them
    // being reachable from the internet.
    for (const Endpoint& address : local_interface_addresses(include_loopback)) {
        Endpoint candidate = address;
        candidate.set_port(sockets.port);
        sockets.local_candidates.push_back(candidate);
    }

    return sockets;
}

void discover_reflexive_address(LocalSockets& sockets, const Endpoint& server_endpoint) {
    std::uint8_t reply[kMaxReflexiveReplySize];

    // The control connection may have resolved the server to an IPv4 address while
    // this socket is dual-stack IPv6, so the target has to be put into a form the
    // socket can reach.
    Endpoint target;
    if (!adapt_endpoint_for_socket(server_endpoint, local_endpoint(sockets.udp_socket.get()).family(),
                                   target)) {
        log::debug("the server's address is not reachable from the UDP socket; "
                   "skipping reflexive discovery");
        return;
    }

    // Three tries. The probe is a single datagram, so a lost one is entirely
    // ordinary and one retry short of enough.
    for (int attempt = 0; attempt < 3; ++attempt) {
        ssize_t written =
            ::sendto(sockets.udp_socket.get(), kReflexiveProbeMagic,
                     sizeof(kReflexiveProbeMagic), 0, target.sockaddr_ptr(), target.sockaddr_len());
        if (written < 0) continue;

        if (!wait_readable(sockets.udp_socket.get(), 400)) continue;

        ssize_t got = ::recv(sockets.udp_socket.get(), reply, sizeof(reply), 0);
        if (got <= 0) continue;

        Endpoint observed;
        if (!decode_reflexive_reply(reply, static_cast<std::size_t>(got), observed)) continue;

        sockets.reflexive_udp = observed;
        sockets.reflexive_known = true;
        log::debug("this machine looks like " + observed.to_string() + " from outside");
        return;
    }

    // Not fatal. On a LAN the local candidates are enough, and behind a firewall
    // that eats the probe the relay tier still works.
    log::debug("could not learn this machine's external address; relying on local candidates");
}

ChannelPtr establish_channel(LocalSockets& sockets, const TransportRequest& request) {
    if (request.peer_candidates.empty() && request.forced != TransportKind::ServerRelay) {
        log::warn("the peer advertised no addresses, so only the relay can be tried");
    }

    bool try_tcp = request.forced == TransportKind::None ||
                   request.forced == TransportKind::DirectTcp;
    bool try_udp = request.forced == TransportKind::None ||
                   request.forced == TransportKind::HolePunchUdp;
    bool try_relay = request.forced == TransportKind::None ||
                     request.forced == TransportKind::ServerRelay;

    if (try_tcp) {
        if (ChannelPtr channel = try_direct_tcp(sockets, request)) return channel;
        if (request.forced == TransportKind::DirectTcp) {
            fail_user("no direct TCP connection could be made and --force-transport=tcp was given");
        }
    }

    if (try_udp) {
        if (ChannelPtr channel = try_hole_punch_udp(sockets, request)) return channel;
        if (request.forced == TransportKind::HolePunchUdp) {
            fail_user("no UDP path could be opened and --force-transport=udp was given");
        }
    }

    if (try_relay) {
        log::info("no direct path to the peer; falling back to the rendezvous server");
        return open_server_relay(request);
    }

    fail_user("no transport was available");
}

ChannelPtr try_hole_punch_udp(LocalSockets& sockets, const TransportRequest& request) {
    Endpoint peer;
    if (!punch_udp_path(sockets.udp_socket.get(), request.peer_candidates, request.handshake_key,
                        request.is_sender, request.udp_budget_ms, peer)) {
        return nullptr;
    }

    // The socket is moved into the channel, which now owns the punched path. The
    // mapping the NAT created belongs to this socket, so reusing a fresh one here
    // would throw away the whole point of the punch.
    return std::make_unique<ReliableUdpChannel>(std::move(sockets.udp_socket), std::move(peer));
}

}  // namespace dz::client
