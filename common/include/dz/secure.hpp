// Handling of secret material: wiping it, comparing it without leaking timing.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace dz {

/// Overwrite `len` bytes at `p` with zeroes in a way the optimiser may not
/// discard. A plain memset() over a buffer that is about to be freed is dead
/// code as far as the compiler is concerned, and both GCC and Clang do remove
/// it at -O3, which is exactly how keys end up surviving in freed heap pages.
void secure_zero(void* p, std::size_t len) noexcept;

/// Compare two buffers in time that depends only on `len`, never on where the
/// first difference is. Used for every MAC and password-proof check: a plain
/// memcmp() lets an attacker recover a MAC byte by byte from response timing.
bool constant_time_equal(const void* a, const void* b, std::size_t len) noexcept;

/// Allocator that wipes memory before handing it back to the system.
template <typename T>
struct ZeroingAllocator {
    using value_type = T;

    ZeroingAllocator() noexcept = default;
    template <typename U>
    explicit ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) { return std::allocator<T>().allocate(n); }

    void deallocate(T* p, std::size_t n) noexcept {
        secure_zero(p, n * sizeof(T));
        std::allocator<T>().deallocate(p, n);
    }

    template <typename U>
    bool operator==(const ZeroingAllocator<U>&) const noexcept {
        return true;
    }
    template <typename U>
    bool operator!=(const ZeroingAllocator<U>&) const noexcept {
        return false;
    }
};

/// A byte buffer that wipes itself when it goes away. Every key, shared secret
/// and password in drop-zone lives in one of these.
using SecretBytes = std::vector<std::uint8_t, ZeroingAllocator<std::uint8_t>>;

/// A string that wipes itself when it goes away, for passwords read from a tty.
using SecretString = std::basic_string<char, std::char_traits<char>, ZeroingAllocator<char>>;

/// Fixed-size secret, used for the 32-byte keys that dominate the crypto layer.
template <std::size_t N>
class SecretArray {
public:
    SecretArray() noexcept : bytes_{} {}
    ~SecretArray() { secure_zero(bytes_, N); }

    SecretArray(const SecretArray& other) noexcept { std::memcpy(bytes_, other.bytes_, N); }
    SecretArray& operator=(const SecretArray& other) noexcept {
        if (this != &other) std::memcpy(bytes_, other.bytes_, N);
        return *this;
    }

    std::uint8_t* data() noexcept { return bytes_; }
    const std::uint8_t* data() const noexcept { return bytes_; }
    static constexpr std::size_t size() noexcept { return N; }

    bool operator==(const SecretArray& other) const noexcept {
        return constant_time_equal(bytes_, other.bytes_, N);
    }
    bool operator!=(const SecretArray& other) const noexcept { return !(*this == other); }

private:
    std::uint8_t bytes_[N];
};

/// Prevent the kernel from writing a core dump of this process. The rendezvous
/// server calls this at start-up so that a crash cannot spill the session table
/// -- which holds live peer addresses -- onto the operator's disk.
void disable_core_dumps() noexcept;

/// Lowercase hexadecimal, for fingerprints in the UI and in known_peers.
std::string to_hex(const void* data, std::size_t len);

/// Parse lowercase or uppercase hexadecimal. Returns false on any non-hex byte
/// or an odd length.
bool from_hex(std::string_view hex, std::vector<std::uint8_t>& out);

}  // namespace dz
