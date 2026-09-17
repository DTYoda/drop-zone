// Fixed-width little-endian encoding for the wire protocol.
//
// Every integer that drop-zone puts on the wire goes through these helpers.
// Little-endian is chosen because both supported architectures (x86-64 and
// arm64) are little-endian natively, so on real hardware the byte-shuffling
// below compiles down to a single unaligned load or store; the shift-based
// implementation is kept because it is correct regardless of host endianness
// and never performs an unaligned access that UBSan would object to.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace dz {

inline void store_u16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
}

inline void store_u32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
    out[2] = static_cast<std::uint8_t>(value >> 16);
    out[3] = static_cast<std::uint8_t>(value >> 24);
}

inline void store_u64(std::uint8_t* out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

inline std::uint16_t load_u16(const std::uint8_t* in) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[0]) |
                                      static_cast<std::uint16_t>(in[1]) << 8);
}

inline std::uint32_t load_u32(const std::uint8_t* in) {
    return static_cast<std::uint32_t>(in[0]) | static_cast<std::uint32_t>(in[1]) << 8 |
           static_cast<std::uint32_t>(in[2]) << 16 | static_cast<std::uint32_t>(in[3]) << 24;
}

inline std::uint64_t load_u64(const std::uint8_t* in) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(in[i]) << (8 * i);
    }
    return value;
}

}  // namespace dz
