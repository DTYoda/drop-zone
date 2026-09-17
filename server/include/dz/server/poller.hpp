// Readiness notification, over epoll on Linux and kqueue on macOS.
//
// Edge-triggered throughout: the kernel reports a descriptor once when its
// readiness changes rather than on every wait, so the loop must drain a
// descriptor until EAGAIN before waiting again. That is more demanding of the
// caller than level-triggered polling, and worth it here because a relayed
// transfer produces a continuous stream of readiness on both directions of two
// sockets -- level-triggered would return the same four descriptors on every
// single wait() and burn a syscall per iteration doing nothing.

#pragma once

#if defined(DZ_PLATFORM_MACOS)
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#include <cstdint>
#include <vector>

#include "dz/socket.hpp"

namespace dz::server {

/// What a caller wants to be told about, and what the kernel reports.
enum class Interest : std::uint32_t {
    None = 0,
    Readable = 1u << 0,
    Writable = 1u << 1,
};

inline Interest operator|(Interest a, Interest b) {
    return static_cast<Interest>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

inline bool has(Interest set, Interest bit) {
    return (static_cast<std::uint32_t>(set) & static_cast<std::uint32_t>(bit)) != 0;
}

struct ReadyEvent {
    int fd = -1;
    bool readable = false;
    bool writable = false;
    /// The peer hung up or the descriptor errored. The loop still tries to read
    /// first, because a peer that sent its last frame and closed leaves data
    /// waiting behind the hangup.
    bool closed = false;
};

class Poller {
public:
    Poller();
    ~Poller();

    Poller(const Poller&) = delete;
    Poller& operator=(const Poller&) = delete;

    void add(int fd, Interest interest);
    void modify(int fd, Interest interest);
    void remove(int fd);

    /// Wait for readiness. `timeout_ms` of -1 waits forever. Returns the number
    /// of events written into `out`.
    std::size_t wait(std::vector<ReadyEvent>& out, int timeout_ms);

private:
    Fd handle_;
#if defined(DZ_PLATFORM_MACOS)
    /// kqueue reports read and write readiness as separate events, so one
    /// descriptor can appear twice in a single wait; the merge below folds them
    /// back into one ReadyEvent per descriptor.
    std::vector<struct kevent> scratch_;
#else
    std::vector<struct epoll_event> scratch_;
#endif
};

}  // namespace dz::server
