// Run-time CPU feature detection.
//
// The cipher choice is made here rather than at compile time so that one
// redistributable binary -- a Homebrew bottle, say -- runs the AES path on
// hardware that has AES instructions and the ChaCha20 path on hardware that
// does not, instead of either crashing with SIGILL or leaving a 5x speed-up on
// the table. See docs/PERFORMANCE.md for the measured difference.

#pragma once

#include <cstdint>
#include <string>

namespace dz {

struct CpuFeatures {
    /// AES round instructions: AES-NI on x86-64, FEAT_AES on arm64.
    bool aes = false;
    /// Carry-less multiply, which is what makes GCM's GHASH fast: PCLMULQDQ on
    /// x86-64, FEAT_PMULL on arm64. AES without it leaves GCM authentication as
    /// the bottleneck, so both are required before AES-GCM is preferred.
    bool carryless_multiply = false;
    bool avx2 = false;
    /// Vector AES (VAES), which lets libcrypto process four blocks per
    /// instruction. Reported for the diagnostics output only; libcrypto selects
    /// it internally.
    bool vaes = false;
};

const CpuFeatures& cpu_features();

/// True when AES-GCM is expected to beat ChaCha20-Poly1305 on this machine,
/// which is the case exactly when both AES and carry-less multiply are present.
bool cpu_prefers_aes();

/// Human-readable feature list for `drop-zone status`.
std::string cpu_features_summary();

/// Number of hardware threads, clamped to a sane range. Used to size the AEAD
/// worker pool.
unsigned hardware_threads();

}  // namespace dz
