#include "dz/fileio.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(DZ_PLATFORM_LINUX)
#include <sys/sendfile.h>
#elif defined(DZ_PLATFORM_MACOS)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "dz/error.hpp"

namespace dz {

// ---------------------------------------------------------------------------
// MappedFile
// ---------------------------------------------------------------------------

MappedFile::MappedFile(const std::string& path) {
    fd_.reset(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd_.valid()) fail_errno("cannot open '" + path + "'");

    struct stat info{};
    if (::fstat(fd_.get(), &info) != 0) fail_errno("cannot stat '" + path + "'");
    if (!S_ISREG(info.st_mode)) fail("'" + path + "' is not a regular file");

    size_ = static_cast<std::uint64_t>(info.st_size);
    if (size_ == 0) {
        // mmap() rejects a zero length, and an empty file has nothing to map.
        // Callers must cope with data() == nullptr, which they do because they
        // are already driven by size_.
        return;
    }

    void* mapping = ::mmap(nullptr, static_cast<std::size_t>(size_), PROT_READ, MAP_PRIVATE,
                           fd_.get(), 0);
    if (mapping == MAP_FAILED) fail_errno("cannot map '" + path + "' into memory");

    data_ = static_cast<const std::uint8_t*>(mapping);
}

MappedFile::~MappedFile() { close(); }

MappedFile::MappedFile(MappedFile&& other) noexcept
    : fd_(std::move(other.fd_)), data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = std::move(other.fd_);
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void MappedFile::advise_sequential() const {
    if (data_ == nullptr) return;

    // MADV_SEQUENTIAL tells the kernel to read ahead aggressively and to drop
    // pages behind the read cursor. Without it the encryption workers stall on
    // a fault every page, which on a fast NVMe device is the difference between
    // saturating the link and not.
#if defined(MADV_SEQUENTIAL)
    (void)::madvise(const_cast<std::uint8_t*>(data_), static_cast<std::size_t>(size_),
                    MADV_SEQUENTIAL);
#endif
#if defined(POSIX_FADV_SEQUENTIAL)
    (void)::posix_fadvise(fd_.get(), 0, static_cast<off_t>(size_), POSIX_FADV_SEQUENTIAL);
    (void)::posix_fadvise(fd_.get(), 0, static_cast<off_t>(size_), POSIX_FADV_WILLNEED);
#endif
}

void MappedFile::close() {
    if (data_ != nullptr) {
        (void)::munmap(const_cast<std::uint8_t*>(data_), static_cast<std::size_t>(size_));
        data_ = nullptr;
    }
    size_ = 0;
    fd_.reset();
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

void preallocate_file(int fd, std::uint64_t size) {
    if (size == 0) return;

#if defined(DZ_PLATFORM_LINUX)
    int rc = ::posix_fallocate(fd, 0, static_cast<off_t>(size));
    if (rc == 0) return;
    // Filesystems that cannot reserve extents return EOPNOTSUPP or EINVAL; a
    // plain truncate still sets the size so the sparse file is at least the
    // right shape.
    if (rc != EOPNOTSUPP && rc != EINVAL) fail_errno("cannot reserve space for the output file", rc);
#elif defined(DZ_PLATFORM_MACOS)
    // F_PREALLOCATE is advisory and does not move the end-of-file marker, so
    // the ftruncate() below is still needed.
    fstore_t request{};
    request.fst_flags = F_ALLOCATECONTIG | F_ALLOCATEALL;
    request.fst_posmode = F_PEOFPOSMODE;
    request.fst_offset = 0;
    request.fst_length = static_cast<off_t>(size);
    if (::fcntl(fd, F_PREALLOCATE, &request) == -1) {
        // Retry without demanding one contiguous extent.
        request.fst_flags = F_ALLOCATEALL;
        (void)::fcntl(fd, F_PREALLOCATE, &request);
    }
#endif

    if (::ftruncate(fd, static_cast<off_t>(size)) != 0) {
        fail_errno("cannot set the size of the output file");
    }
}

void write_file_all(int fd, const void* data, std::size_t len) {
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = len;

    while (remaining > 0) {
        ssize_t written = ::write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            fail_errno("cannot write to file");
        }
        if (written == 0) fail("the file accepted no bytes");

        cursor += written;
        remaining -= static_cast<std::size_t>(written);
    }
}

void pwrite_all(int fd, const void* data, std::size_t len, std::uint64_t offset) {
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = len;
    std::uint64_t position = offset;

    while (remaining > 0) {
        ssize_t written = ::pwrite(fd, cursor, remaining, static_cast<off_t>(position));
        if (written < 0) {
            if (errno == EINTR) continue;
            fail_errno("cannot write to the output file");
        }
        if (written == 0) fail("the output file accepted no bytes");

        cursor += written;
        position += static_cast<std::uint64_t>(written);
        remaining -= static_cast<std::size_t>(written);
    }
}

void pread_all(int fd, void* data, std::size_t len, std::uint64_t offset) {
    auto* cursor = static_cast<std::uint8_t*>(data);
    std::size_t remaining = len;
    std::uint64_t position = offset;

    while (remaining > 0) {
        ssize_t got = ::pread(fd, cursor, remaining, static_cast<off_t>(position));
        if (got < 0) {
            if (errno == EINTR) continue;
            fail_errno("cannot read from the input file");
        }
        if (got == 0) fail("the input file ended sooner than its size claimed");

        cursor += got;
        position += static_cast<std::uint64_t>(got);
        remaining -= static_cast<std::size_t>(got);
    }
}

// ---------------------------------------------------------------------------
// Zero-copy send
// ---------------------------------------------------------------------------

bool sendfile_supported() {
#if defined(DZ_PLATFORM_LINUX) || defined(DZ_PLATFORM_MACOS)
    return true;
#else
    return false;
#endif
}

void sendfile_all(int socket_fd, int file_fd, std::uint64_t offset, std::uint64_t len) {
#if defined(DZ_PLATFORM_LINUX)
    std::uint64_t remaining = len;
    off_t position = static_cast<off_t>(offset);

    while (remaining > 0) {
        // Linux caps one call at 0x7ffff000 bytes; loop for anything larger.
        std::size_t batch = static_cast<std::size_t>(
            remaining < 0x7ffff000ull ? remaining : 0x7ffff000ull);

        ssize_t sent = ::sendfile(socket_fd, file_fd, &position, batch);
        if (sent < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!wait_writable(socket_fd, 30'000)) fail("sendfile timed out");
                continue;
            }
            fail_errno("sendfile failed");
        }
        if (sent == 0) throw PeerClosed();

        remaining -= static_cast<std::uint64_t>(sent);
    }
#elif defined(DZ_PLATFORM_MACOS)
    off_t position = static_cast<off_t>(offset);
    off_t remaining = static_cast<off_t>(len);

    while (remaining > 0) {
        off_t batch = remaining;
        // macOS reports how much it managed in `batch` even when it returns -1
        // with EAGAIN, so progress has to be taken from there rather than from
        // the return value.
        int rc = ::sendfile(file_fd, socket_fd, position, &batch, nullptr, 0);
        position += batch;
        remaining -= batch;

        if (rc == 0) continue;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (remaining > 0 && !wait_writable(socket_fd, 30'000)) fail("sendfile timed out");
            continue;
        }
        fail_errno("sendfile failed");
    }
#else
    // Portable fallback: read into a staging buffer and write it out. Correct
    // but with the extra copy sendfile exists to avoid.
    std::vector<std::uint8_t> buffer(1u << 20);
    std::uint64_t remaining = len;
    std::uint64_t position = offset;

    while (remaining > 0) {
        std::size_t batch = static_cast<std::size_t>(
            remaining < buffer.size() ? remaining : buffer.size());
        pread_all(file_fd, buffer.data(), batch, position);
        write_all(socket_fd, buffer.data(), batch);
        position += batch;
        remaining -= batch;
    }
#endif
}

void fsync_file(int fd) {
#if defined(DZ_PLATFORM_MACOS)
    // fsync() on macOS only pushes to the drive's own cache; F_FULLFSYNC is the
    // one that reaches stable storage.
    if (::fcntl(fd, F_FULLFSYNC) == 0) return;
#endif
    if (::fsync(fd) != 0) fail_errno("cannot flush the output file to disk");
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

void make_directories(const std::string& path) {
    if (path.empty() || path == "." || path == "/") return;

    std::string partial;
    partial.reserve(path.size());

    std::size_t index = 0;
    if (path[0] == '/') {
        partial = "/";
        index = 1;
    }

    while (index <= path.size()) {
        std::size_t slash = path.find('/', index);
        std::string component =
            path.substr(index, (slash == std::string::npos) ? std::string::npos : slash - index);

        if (!component.empty()) {
            if (partial.empty()) {
                partial = component;
            } else if (partial.back() == '/') {
                partial += component;
            } else {
                partial += "/" + component;
            }

            if (::mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) {
                fail_errno("cannot create directory '" + partial + "'");
            }
        }

        if (slash == std::string::npos) break;
        index = slash + 1;
    }
}

bool path_exists(const std::string& path) {
    struct stat info{};
    return ::stat(path.c_str(), &info) == 0;
}

bool is_directory(const std::string& path) {
    struct stat info{};
    if (::stat(path.c_str(), &info) != 0) return false;
    return S_ISDIR(info.st_mode);
}

bool is_regular_file(const std::string& path) {
    struct stat info{};
    if (::stat(path.c_str(), &info) != 0) return false;
    return S_ISREG(info.st_mode);
}

std::uint64_t file_size(const std::string& path) {
    struct stat info{};
    if (::stat(path.c_str(), &info) != 0) fail_errno("cannot stat '" + path + "'");
    return static_cast<std::uint64_t>(info.st_size);
}

std::string current_directory() {
    char buffer[4096];
    if (::getcwd(buffer, sizeof(buffer)) == nullptr) fail_errno("cannot read the current directory");
    return buffer;
}

std::string expand_user_path(const std::string& path) {
    if (path.size() < 2 || path[0] != '~' || path[1] != '/') return path;

    const char* home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') return path;
    return std::string(home) + path.substr(1);
}

std::string join_path(std::string_view a, std::string_view b) {
    if (a.empty()) return std::string(b);
    if (b.empty()) return std::string(a);
    if (b.front() == '/') return std::string(b);

    std::string joined(a);
    if (joined.back() != '/') joined += '/';
    joined += b;
    return joined;
}

std::string base_name(std::string_view path) {
    // Ignore trailing slashes so that base_name("a/b/") is "b", matching what a
    // user typing `drop-zone send mydir/` expects the transfer to be called.
    while (path.size() > 1 && path.back() == '/') path.remove_suffix(1);

    std::size_t slash = path.rfind('/');
    if (slash == std::string_view::npos) return std::string(path);
    return std::string(path.substr(slash + 1));
}

std::string parent_path(std::string_view path) {
    while (path.size() > 1 && path.back() == '/') path.remove_suffix(1);

    std::size_t slash = path.rfind('/');
    if (slash == std::string_view::npos) return ".";
    if (slash == 0) return "/";
    return std::string(path.substr(0, slash));
}

std::string format_bytes(std::uint64_t bytes) {
    static const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};

    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 5) {
        value /= 1024.0;
        ++unit;
    }

    char buffer[64];
    if (unit == 0) {
        std::snprintf(buffer, sizeof(buffer), "%llu B", static_cast<unsigned long long>(bytes));
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, kUnits[unit]);
    }
    return buffer;
}

std::string format_rate(std::uint64_t bytes, double seconds) {
    if (seconds <= 0.0) return "-";
    return format_bytes(static_cast<std::uint64_t>(static_cast<double>(bytes) / seconds)) + "/s";
}

}  // namespace dz
