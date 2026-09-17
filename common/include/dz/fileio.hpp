// File access on the transfer hot path, and the platform differences it hides.
//
// Three techniques matter for throughput here and each has its own wrapper:
//
//  * sendfile() copies a file to a socket entirely inside the kernel, so the
//    bytes never enter this process's address space at all. It is only usable
//    when the payload on the wire is byte-for-byte the file, which means the
//    direct-TCP transport with encryption off.
//  * mmap() lets the encryption workers read straight out of the page cache
//    with no read() copy into a staging buffer, which matters because the AEAD
//    is already fast enough that a redundant memcpy is visible.
//  * pwrite() writes at an explicit offset without touching a shared file
//    position, which is what allows several workers to commit chunks
//    concurrently and out of order -- required for the reliable-UDP transport
//    and useful for all of them.

#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "dz/socket.hpp"

namespace dz {

/// A read-only memory mapping of a whole file.
///
/// Zero-length files are legal and map to a null pointer with size 0, which the
/// callers must tolerate because mmap() rejects a zero length.
class MappedFile {
public:
    MappedFile() = default;
    explicit MappedFile(const std::string& path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    const std::uint8_t* data() const noexcept { return data_; }
    std::uint64_t size() const noexcept { return size_; }
    int fd() const noexcept { return fd_.get(); }
    bool valid() const noexcept { return fd_.valid(); }

    /// Tell the kernel the whole mapping will be read soon and sequentially, so
    /// readahead runs well ahead of the workers instead of faulting a page at a
    /// time.
    void advise_sequential() const;

    void close();

private:
    Fd fd_;
    const std::uint8_t* data_ = nullptr;
    std::uint64_t size_ = 0;
};

/// Reserve `size` bytes for a file up front.
///
/// This is both a speed and a correctness measure: the filesystem can pick one
/// contiguous extent instead of growing the file a chunk at a time, and a
/// transfer that will not fit fails now rather than at 90%.
void preallocate_file(int fd, std::uint64_t size);

/// Write `len` bytes at `offset`, looping over short writes. Safe to call
/// concurrently on the same descriptor at non-overlapping offsets.
void pwrite_all(int fd, const void* data, std::size_t len, std::uint64_t offset);

/// Read exactly `len` bytes from `offset`.
void pread_all(int fd, void* data, std::size_t len, std::uint64_t offset);

/// True when this build can copy file to socket without a userspace bounce.
bool sendfile_supported();

/// Copy `len` bytes from `file_fd` at `offset` into the socket `socket_fd`
/// without the data entering userspace, looping until it is all gone.
///
/// Wraps Linux's sendfile(2), whose offset is an in/out pointer, and macOS's
/// sendfile(2), whose signature and argument order differ.
void sendfile_all(int socket_fd, int file_fd, std::uint64_t offset, std::uint64_t len);

/// Flush a file's data to stable storage. Called once per received file before
/// the receiver reports success, so "transfer complete" means the bytes survive
/// a power cut rather than merely having reached the page cache.
void fsync_file(int fd);

/// Create every missing component of `path`, like `mkdir -p`.
void make_directories(const std::string& path);

bool path_exists(const std::string& path);
bool is_directory(const std::string& path);
bool is_regular_file(const std::string& path);

/// Size of a regular file.
std::uint64_t file_size(const std::string& path);

/// The current working directory, which is where received files land when the
/// user gives no output directory.
std::string current_directory();

/// Expand a leading "~/" using $HOME.
std::string expand_user_path(const std::string& path);

std::string join_path(std::string_view a, std::string_view b);

/// Everything after the last '/'.
std::string base_name(std::string_view path);

/// Everything before the last '/', or "." when there is none.
std::string parent_path(std::string_view path);

/// Human-readable byte count, e.g. "1.4 GiB".
std::string format_bytes(std::uint64_t bytes);

/// Human-readable rate, e.g. "938 MiB/s".
std::string format_rate(std::uint64_t bytes, double seconds);

}  // namespace dz
