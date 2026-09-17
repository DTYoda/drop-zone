#include "dz/client/progress.hpp"

#include <unistd.h>

#include <cstdio>

#include "dz/fileio.hpp"
#include "dz/socket.hpp"

namespace dz::client {
namespace {

/// Shortest gap between updates. Fast enough to look live, slow enough that the
/// formatting never competes with the transfer.
constexpr std::uint64_t kRenderIntervalMs = 100;

}  // namespace

Progress::Progress(std::string label, std::uint64_t total_bytes, bool enabled)
    : label_(std::move(label)), total_bytes_(total_bytes), enabled_(enabled) {
    started_ms_ = monotonic_millis();
    last_render_ms_ = 0;

    // Only animate on a terminal. Redirected to a file, the carriage returns would
    // produce one very long unreadable line.
    if (enabled_ && ::isatty(STDERR_FILENO) != 1) enabled_ = false;
}

void Progress::advance(std::uint64_t bytes) {
    transferred_.fetch_add(bytes, std::memory_order_relaxed);
    if (!enabled_) return;

    std::uint64_t now = monotonic_millis();
    std::uint64_t last = last_render_ms_.load(std::memory_order_relaxed);
    if (now - last < kRenderIntervalMs) return;
    if (!last_render_ms_.compare_exchange_strong(last, now)) return;

    // try_lock rather than lock: if another thread is already drawing, this update
    // is redundant and waiting for it would put terminal I/O on the decryption
    // path.
    std::unique_lock<std::mutex> guard(render_mutex_, std::try_to_lock);
    if (!guard.owns_lock()) return;

    render(false);
}

double Progress::elapsed_seconds() const {
    std::uint64_t elapsed_ms = monotonic_millis() - started_ms_;
    return static_cast<double>(elapsed_ms) / 1000.0;
}

void Progress::render(bool final_line) {
    double seconds = elapsed_seconds();
    std::uint64_t transferred = transferred_.load(std::memory_order_relaxed);

    int percent = 0;
    if (total_bytes_ > 0) {
        percent = static_cast<int>((transferred * 100) / total_bytes_);
        if (percent > 100) percent = 100;
    }

    std::fprintf(stderr, "\r%s  %3d%%  %s of %s  %s   ", label_.c_str(), percent,
                 format_bytes(transferred).c_str(), format_bytes(total_bytes_).c_str(),
                 format_rate(transferred, seconds).c_str());
    if (final_line) std::fputc('\n', stderr);
    std::fflush(stderr);

    line_open_ = !final_line;
}

void Progress::finish(const std::string& suffix) {
    double seconds = elapsed_seconds();
    std::uint64_t transferred = transferred_.load();

    if (enabled_ && line_open_) {
        // Overwrite the in-progress line rather than leaving it above the summary.
        std::fprintf(stderr, "\r%*s\r", 78, "");
    }

    std::fprintf(stderr, "%s  %s in %.2fs (%s)%s%s\n", label_.c_str(),
                 format_bytes(transferred).c_str(), seconds,
                 format_rate(transferred, seconds).c_str(), suffix.empty() ? "" : "  ",
                 suffix.c_str());
    std::fflush(stderr);

    line_open_ = false;
}

}  // namespace dz::client
