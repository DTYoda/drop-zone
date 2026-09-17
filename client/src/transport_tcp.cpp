// Tier 1 of the ladder: a direct TCP connection.
//
// Both peers listen and both connect to every address the other advertised, all
// at once. Whichever completes first wins and the rest are dropped. Doing both
// halves rather than picking a "server" side is what makes this work in the
// asymmetric cases: if only one peer is reachable -- one on a LAN with a port
// forward, the other behind a NAT that allows nothing inbound -- then exactly one
// direction succeeds, and neither peer has to know in advance which.
//
// A completed connection is not trusted until a two-way handshake over it proves
// the other end holds the session's handshake key. Without that, anything that
// scanned the listening port would be adopted as the peer.

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

#include "dz/client/transport.hpp"
#include "dz/crypto.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

/// Tag distinguishing the two directions of the handshake, so the proof one peer
/// sends cannot be echoed back as the answer.
constexpr const char* kSenderTag = "drop-zone/v1 tcp handshake sender";
constexpr const char* kReceiverTag = "drop-zone/v1 tcp handshake receiver";

/// Size of a socket buffer request. 4 MiB covers a 100 ms path at 320 Mb/s
/// without the window becoming the limit; the kernel usually grants less and
/// autotunes upwards from there.
constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

void compute_proof(const Key& key, const char* tag, std::uint8_t out[kSha256Size]) {
    hmac_sha256(key.data(), key.size(), tag, std::strlen(tag), out);
}

void tune_socket(int fd) {
    set_tcp_nodelay(fd);
    set_socket_buffers(fd, kSocketBufferBytes);
    set_no_sigpipe(fd);
}

/// Exchange proofs over a freshly connected socket. Returns false if the other
/// end cannot prove it belongs to this session.
bool authenticate(int fd, const Key& key, bool is_sender, int timeout_ms) {
    std::uint8_t own[kSha256Size];
    std::uint8_t expected[kSha256Size];
    compute_proof(key, is_sender ? kSenderTag : kReceiverTag, own);
    compute_proof(key, is_sender ? kReceiverTag : kSenderTag, expected);

    // Blocking with a receive timeout, rather than another poll loop: by this
    // point there is exactly one socket left and the handshake is two 32-byte
    // messages.
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    try {
        write_all(fd, own, sizeof(own));

        std::uint8_t received[kSha256Size];
        read_exact(fd, received, sizeof(received));

        if (!constant_time_equal(received, expected, sizeof(expected))) return false;
    } catch (const Error&) {
        return false;
    }

    // Clear the timeouts: the data plane manages its own deadlines and a stalled
    // 1 MiB write is not a failure.
    timeval none{};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &none, sizeof(none));
    return true;
}

/// A connect() in progress.
struct PendingConnect {
    Fd fd;
    Endpoint target;
};

/// Start a non-blocking connect to `target`. Returns an invalid Fd if the
/// attempt could not even be started, which happens routinely -- a candidate on
/// an interface this machine has no route to fails immediately.
Fd start_connect(const Endpoint& target) {
    Fd fd(::socket(target.family(), SOCK_STREAM, 0));
    if (!fd.valid()) return Fd();

    set_close_on_exec(fd.get());
    set_nonblocking(fd.get(), true);
    tune_socket(fd.get());

    // Binding the listening port here too would let a NAT reuse one mapping for
    // both directions, but it also makes the connect fail outright on systems
    // that will not share the port, so the simpler unbound connect is used.
    if (::connect(fd.get(), target.sockaddr_ptr(), target.sockaddr_len()) == 0) return fd;
    if (errno == EINPROGRESS || errno == EINTR) return fd;
    return Fd();
}

/// Check whether a non-blocking connect has finished. Returns 1 for connected,
/// 0 for still trying, -1 for failed.
int connect_status(int fd) {
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0) return -1;
    if (error == 0) return 1;
    if (error == EINPROGRESS || error == EALREADY) return 0;
    return -1;
}

}  // namespace

/// A Channel over a connected TCP socket.
///
/// Everything here is a thin wrapper over the kernel's own reliable stream, which
/// is exactly why this tier is the fastest: no retransmission logic, no
/// congestion control and no copy in this process.
class TcpChannel : public Channel {
public:
    TcpChannel(Fd fd, Endpoint peer) : fd_(std::move(fd)), peer_(std::move(peer)) {}

    TransportKind kind() const override { return TransportKind::DirectTcp; }

    std::string describe() const override { return "direct TCP to " + peer_.to_string(); }

    void read_exactly(void* data, std::size_t len) override { read_exact(fd_.get(), data, len); }

    void write_bytes(const void* data, std::size_t len) override {
        write_all(fd_.get(), data, len);
    }

    void write_pair(const void* first, std::size_t first_len, const void* second,
                    std::size_t second_len) override {
        if (second_len == 0) {
            write_all(fd_.get(), first, first_len);
            return;
        }

        // One writev so an 8-byte frame header does not become its own segment
        // ahead of a megabyte of payload.
        iovec parts[2];
        parts[0].iov_base = const_cast<void*>(first);
        parts[0].iov_len = first_len;
        parts[1].iov_base = const_cast<void*>(second);
        parts[1].iov_len = second_len;

        std::size_t total = first_len + second_len;
        std::size_t sent = 0;
        int index = 0;

        while (sent < total) {
            ssize_t written = ::writev(fd_.get(), parts + index, 2 - index);
            if (written < 0) {
                if (errno == EINTR) continue;
                fail_errno("writev to the peer failed");
            }

            sent += static_cast<std::size_t>(written);
            auto consumed = static_cast<std::size_t>(written);
            while (index < 2 && consumed >= parts[index].iov_len) {
                consumed -= parts[index].iov_len;
                ++index;
            }
            if (index < 2 && consumed > 0) {
                parts[index].iov_base =
                    static_cast<std::uint8_t*>(parts[index].iov_base) + consumed;
                parts[index].iov_len -= consumed;
            }
        }
    }

    int sendfile_fd() const override { return fd_.get(); }

    void close_gracefully() override {
        // Half-close so the peer's read returns cleanly instead of as a reset.
        (void)::shutdown(fd_.get(), SHUT_WR);
    }

private:
    Fd fd_;
    Endpoint peer_;
};

ChannelPtr try_direct_tcp(LocalSockets& sockets, const TransportRequest& request) {
    std::vector<PendingConnect> attempts;
    attempts.reserve(request.peer_candidates.size());

    for (const Endpoint& candidate : request.peer_candidates) {
        Fd fd = start_connect(candidate);
        if (fd.valid()) attempts.push_back(PendingConnect{std::move(fd), candidate});
    }

    log::debug("direct TCP: listening on port " + std::to_string(sockets.port) + " and trying " +
               std::to_string(attempts.size()) + " candidates");

    std::uint64_t deadline = monotonic_millis() + request.tcp_budget_ms;

    while (monotonic_millis() < deadline) {
        std::vector<pollfd> waits;
        waits.reserve(attempts.size() + 1);

        // The listener first, so an inbound connection is noticed as readily as
        // an outbound one completing.
        pollfd listener{};
        listener.fd = sockets.tcp_listener.get();
        listener.events = POLLIN;
        waits.push_back(listener);

        for (const PendingConnect& attempt : attempts) {
            pollfd entry{};
            entry.fd = attempt.fd.get();
            entry.events = POLLOUT;
            waits.push_back(entry);
        }

        std::uint64_t now = monotonic_millis();
        int remaining = static_cast<int>((deadline > now) ? (deadline - now) : 0);
        // Poll in short slices so a candidate that fails fast is retired promptly
        // rather than at the end of the budget.
        int slice = (remaining > 200) ? 200 : remaining;

        int ready = ::poll(waits.data(), static_cast<nfds_t>(waits.size()), slice);
        if (ready < 0) {
            if (errno == EINTR) continue;
            fail_errno("poll failed while opening a direct connection");
        }

        if ((waits[0].revents & POLLIN) != 0) {
            sockaddr_storage storage{};
            socklen_t length = sizeof(storage);
            int raw = ::accept(sockets.tcp_listener.get(), reinterpret_cast<sockaddr*>(&storage),
                               &length);
            if (raw >= 0) {
                Fd accepted(raw);
                set_close_on_exec(accepted.get());
                tune_socket(accepted.get());

                Endpoint peer =
                    Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), length);

                // The inbound side of the pair takes the opposite handshake role,
                // so both directions of a simultaneous open agree.
                if (authenticate(accepted.get(), request.handshake_key, !request.is_sender, 2000)) {
                    log::debug("direct TCP: accepted a connection from " + peer.to_string());
                    return std::make_unique<TcpChannel>(std::move(accepted), std::move(peer));
                }
                log::debug("direct TCP: an inbound connection could not prove it was the peer");
            }
        }

        for (std::size_t i = 0; i < attempts.size();) {
            short events = waits[i + 1].revents;
            if (events == 0) {
                ++i;
                continue;
            }

            int status = connect_status(attempts[i].fd.get());
            if (status == 1) {
                Fd fd = std::move(attempts[i].fd);
                Endpoint target = attempts[i].target;
                set_nonblocking(fd.get(), false);

                if (authenticate(fd.get(), request.handshake_key, request.is_sender, 2000)) {
                    log::debug("direct TCP: connected to " + target.to_string());
                    return std::make_unique<TcpChannel>(std::move(fd), std::move(target));
                }
                log::debug("direct TCP: " + target.to_string() + " could not prove it was the peer");
                attempts.erase(attempts.begin() + static_cast<std::ptrdiff_t>(i));
                waits.erase(waits.begin() + static_cast<std::ptrdiff_t>(i) + 1);
                continue;
            }
            if (status < 0) {
                attempts.erase(attempts.begin() + static_cast<std::ptrdiff_t>(i));
                waits.erase(waits.begin() + static_cast<std::ptrdiff_t>(i) + 1);
                continue;
            }
            ++i;
        }

        // Every attempt failed and nothing is listening for us. Keep waiting on
        // the listener alone in case the peer is slower to start.
        if (attempts.empty() && !wait_readable(sockets.tcp_listener.get(), slice)) {
            if (monotonic_millis() >= deadline) break;
        }
    }

    log::debug("direct TCP: no connection within the budget");
    return nullptr;
}

}  // namespace dz::client
