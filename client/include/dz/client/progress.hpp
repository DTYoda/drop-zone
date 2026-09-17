// Progress reporting for a transfer.

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace dz::client {

/// Prints a single self-overwriting line while a transfer runs, and a summary when
/// it finishes.
///
/// Updates are rate-limited rather than emitted per chunk: at multiple gigabytes a
/// second a per-chunk update would be thousands of writes to the terminal, and the
/// formatting alone would show up in the transfer rate.
///
/// advance() is safe to call from several threads, because on the receiving side it
/// is the decryption workers that know a chunk has landed. The byte counter is
/// atomic and rendering is attempted under a try_lock, so a worker never waits on
/// the terminal -- at worst it skips an update another thread is already drawing.
class Progress {
public:
    Progress(std::string label, std::uint64_t total_bytes, bool enabled);

    /// Note that `bytes` more have moved.
    void advance(std::uint64_t bytes);

    /// Print the final line, with the average rate over the whole transfer.
    void finish(const std::string& suffix);

    std::uint64_t transferred() const { return transferred_.load(); }

    /// Seconds since the transfer started.
    double elapsed_seconds() const;

private:
    void render(bool final_line);

    std::string label_;
    std::uint64_t total_bytes_;
    bool enabled_;

    std::atomic<std::uint64_t> transferred_{0};
    std::uint64_t started_ms_ = 0;
    std::atomic<std::uint64_t> last_render_ms_{0};
    std::mutex render_mutex_;
    /// True once anything has been written, so finish() knows whether it needs to
    /// clear a partial line.
    bool line_open_ = false;
};

}  // namespace dz::client
