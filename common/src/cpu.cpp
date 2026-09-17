#include "dz/cpu.hpp"

#include <thread>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#if defined(__aarch64__)
#if defined(DZ_PLATFORM_LINUX)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(DZ_PLATFORM_MACOS)
#include <sys/sysctl.h>
#endif
#endif

namespace dz {
namespace {

CpuFeatures detect() {
    CpuFeatures features;

#if defined(__x86_64__) || defined(__i386__)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        features.aes = (ecx & bit_AES) != 0;
        features.carryless_multiply = (ecx & bit_PCLMUL) != 0;
    }
    // AVX2 and VAES live in the leaf-7 feature words.
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        features.avx2 = (ebx & bit_AVX2) != 0;
        features.vaes = (ecx & bit_VAES) != 0;
    }
#elif defined(__aarch64__)
#if defined(DZ_PLATFORM_LINUX)
    unsigned long caps = ::getauxval(AT_HWCAP);
    features.aes = (caps & HWCAP_AES) != 0;
    features.carryless_multiply = (caps & HWCAP_PMULL) != 0;
#elif defined(DZ_PLATFORM_MACOS)
    // Every arm64 Mac has the crypto extensions, but ask rather than assume.
    int present = 0;
    std::size_t len = sizeof(present);
    if (::sysctlbyname("hw.optional.arm.FEAT_AES", &present, &len, nullptr, 0) == 0) {
        features.aes = present != 0;
    } else {
        features.aes = true;
    }
    len = sizeof(present);
    if (::sysctlbyname("hw.optional.arm.FEAT_PMULL", &present, &len, nullptr, 0) == 0) {
        features.carryless_multiply = present != 0;
    } else {
        features.carryless_multiply = true;
    }
#else
    features.aes = true;
    features.carryless_multiply = true;
#endif
#endif

    return features;
}

}  // namespace

const CpuFeatures& cpu_features() {
    static const CpuFeatures features = detect();
    return features;
}

bool cpu_prefers_aes() {
    const CpuFeatures& features = cpu_features();
    // Both halves are required. AES instructions without carry-less multiply
    // leave GHASH running in software, and a software GHASH is slower than all
    // of ChaCha20-Poly1305 -- so on such a CPU the "hardware accelerated"
    // cipher is the wrong choice.
    return features.aes && features.carryless_multiply;
}

std::string cpu_features_summary() {
    const CpuFeatures& features = cpu_features();

    std::string summary;
    auto add = [&summary](const char* name, bool present) {
        if (!present) return;
        if (!summary.empty()) summary += ", ";
        summary += name;
    };

    add("aes", features.aes);
    add("carryless-multiply", features.carryless_multiply);
    add("avx2", features.avx2);
    add("vaes", features.vaes);

    if (summary.empty()) summary = "no accelerated cipher instructions";
    return summary;
}

unsigned hardware_threads() {
    unsigned count = std::thread::hardware_concurrency();
    if (count == 0) count = 4;  // hardware_concurrency is allowed to return 0.
    // More than 16 AEAD workers has never helped in testing: the bottleneck
    // moves to the socket or the disk well before then, and each extra worker
    // costs a chunk-sized buffer.
    if (count > 16) count = 16;
    return count;
}

}  // namespace dz
