#include "dz/server/poller.hpp"

#include <unistd.h>

#include <cerrno>

#include "dz/error.hpp"

namespace dz::server {
namespace {

constexpr std::size_t kBatchSize = 256;

}  // namespace

#if defined(DZ_PLATFORM_MACOS)

Poller::Poller() {
    handle_.reset(::kqueue());
    if (!handle_.valid()) fail_errno("cannot create a kqueue");
    set_close_on_exec(handle_.get());
    scratch_.resize(kBatchSize);
}

Poller::~Poller() = default;

void Poller::add(int fd, Interest interest) { modify(fd, interest); }

void Poller::modify(int fd, Interest interest) {
    struct kevent changes[2];
    int count = 0;

    // EV_CLEAR is kqueue's edge-triggered mode. Filters the caller no longer
    // wants are disabled rather than deleted so that a later modify() does not
    // have to know whether they were ever added.
    EV_SET(&changes[count++], fd, EVFILT_READ,
           has(interest, Interest::Readable) ? (EV_ADD | EV_CLEAR) : (EV_ADD | EV_DISABLE), 0, 0,
           nullptr);
    EV_SET(&changes[count++], fd, EVFILT_WRITE,
           has(interest, Interest::Writable) ? (EV_ADD | EV_CLEAR) : (EV_ADD | EV_DISABLE), 0, 0,
           nullptr);

    if (::kevent(handle_.get(), changes, count, nullptr, 0, nullptr) < 0) {
        fail_errno("cannot register a descriptor with kqueue");
    }
}

void Poller::remove(int fd) {
    struct kevent changes[2];
    EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    // Failures are ignored: closing a descriptor already removes its filters, so
    // a "not found" here is the normal case on the teardown path.
    (void)::kevent(handle_.get(), changes, 2, nullptr, 0, nullptr);
}

std::size_t Poller::wait(std::vector<ReadyEvent>& out, int timeout_ms) {
    timespec timeout{};
    timespec* timeout_ptr = nullptr;
    if (timeout_ms >= 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1'000'000;
        timeout_ptr = &timeout;
    }

    int count = ::kevent(handle_.get(), nullptr, 0, scratch_.data(),
                         static_cast<int>(scratch_.size()), timeout_ptr);
    if (count < 0) {
        if (errno == EINTR) return 0;
        fail_errno("kevent failed");
    }

    out.clear();
    for (int i = 0; i < count; ++i) {
        const struct kevent& event = scratch_[static_cast<std::size_t>(i)];
        int fd = static_cast<int>(event.ident);

        // Fold the separate read and write events for one descriptor together.
        ReadyEvent* existing = nullptr;
        for (ReadyEvent& candidate : out) {
            if (candidate.fd == fd) {
                existing = &candidate;
                break;
            }
        }
        if (existing == nullptr) {
            out.push_back(ReadyEvent{fd, false, false, false});
            existing = &out.back();
        }

        if (event.filter == EVFILT_READ) existing->readable = true;
        if (event.filter == EVFILT_WRITE) existing->writable = true;
        if ((event.flags & EV_EOF) != 0 || (event.flags & EV_ERROR) != 0) existing->closed = true;
    }
    return out.size();
}

#else  // Linux

Poller::Poller() {
    handle_.reset(::epoll_create1(EPOLL_CLOEXEC));
    if (!handle_.valid()) fail_errno("cannot create an epoll instance");
    scratch_.resize(kBatchSize);
}

Poller::~Poller() = default;

namespace {

std::uint32_t to_epoll_events(Interest interest) {
    // EPOLLET makes this edge-triggered; EPOLLRDHUP reports a peer's orderly
    // half-close, which EPOLLIN alone does not distinguish from data arriving.
    std::uint32_t events = EPOLLET | EPOLLRDHUP;
    if (has(interest, Interest::Readable)) events |= EPOLLIN;
    if (has(interest, Interest::Writable)) events |= EPOLLOUT;
    return events;
}

}  // namespace

void Poller::add(int fd, Interest interest) {
    epoll_event event{};
    event.events = to_epoll_events(interest);
    event.data.fd = fd;

    if (::epoll_ctl(handle_.get(), EPOLL_CTL_ADD, fd, &event) != 0) {
        fail_errno("cannot add a descriptor to epoll");
    }
}

void Poller::modify(int fd, Interest interest) {
    epoll_event event{};
    event.events = to_epoll_events(interest);
    event.data.fd = fd;

    if (::epoll_ctl(handle_.get(), EPOLL_CTL_MOD, fd, &event) != 0) {
        fail_errno("cannot update a descriptor in epoll");
    }
}

void Poller::remove(int fd) {
    // Ignored on failure for the same reason as the kqueue path: a descriptor
    // that has already been closed is gone from the interest list too.
    (void)::epoll_ctl(handle_.get(), EPOLL_CTL_DEL, fd, nullptr);
}

std::size_t Poller::wait(std::vector<ReadyEvent>& out, int timeout_ms) {
    int count = ::epoll_wait(handle_.get(), scratch_.data(), static_cast<int>(scratch_.size()),
                             timeout_ms);
    if (count < 0) {
        if (errno == EINTR) return 0;
        fail_errno("epoll_wait failed");
    }

    out.clear();
    out.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        const epoll_event& event = scratch_[static_cast<std::size_t>(i)];

        ReadyEvent ready;
        ready.fd = event.data.fd;
        ready.readable = (event.events & EPOLLIN) != 0;
        ready.writable = (event.events & EPOLLOUT) != 0;
        ready.closed = (event.events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0;
        out.push_back(ready);
    }
    return out.size();
}

#endif

}  // namespace dz::server
