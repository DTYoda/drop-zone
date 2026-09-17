// The cryptographic primitives drop-zone uses, wrapped over OpenSSL libcrypto.
//
// Why libcrypto and not hand-written intrinsics: libcrypto's AES-GCM and
// ChaCha20-Poly1305 are hand-tuned assembly with multi-block pipelining, and
// they are faster than what a from-scratch intrinsics implementation is likely
// to reach while also being constant-time and audited. The throughput work in
// drop-zone therefore goes into the layer above -- keeping every chunk an
// independent AEAD message so a thread pool can encrypt them concurrently, and
// reusing one cipher context per worker so the key schedule is built once
// instead of once per megabyte. See dz::AeadPool in aead_pool.hpp.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "dz/secure.hpp"

namespace dz {

constexpr std::size_t kSha256Size = 32;
constexpr std::size_t kAeadKeySize = 32;   ///< 256 bits for both AEADs.
constexpr std::size_t kAeadNonceSize = 12; ///< 96 bits, the native size for both.
constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kX25519KeySize = 32;
constexpr std::size_t kEd25519PublicKeySize = 32;
constexpr std::size_t kEd25519PrivateKeySize = 32;
constexpr std::size_t kEd25519SignatureSize = 64;

using Key = SecretArray<kAeadKeySize>;
using Sha256Digest = std::array<std::uint8_t, kSha256Size>;

// ---------------------------------------------------------------------------
// Randomness and hashing
// ---------------------------------------------------------------------------

/// Fill `out` from the system CSPRNG, or throw. Never falls back to anything
/// weaker: a nonce or key from a degraded source is worse than a failed
/// transfer.
void random_bytes(void* out, std::size_t len);

Sha256Digest sha256(const void* data, std::size_t len);

/// Incremental SHA-256, used to hash the handshake transcript as it is built.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    void update(const void* data, std::size_t len);
    void update(std::string_view text) { update(text.data(), text.size()); }
    void update(const std::vector<std::uint8_t>& data) { update(data.data(), data.size()); }
    Sha256Digest finish();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// HMAC-SHA256. Used for the public-password proofs, whose comparison must go
/// through constant_time_equal.
void hmac_sha256(const void* key, std::size_t key_len, const void* data, std::size_t data_len,
                 std::uint8_t out[kSha256Size]);

/// HKDF-SHA256 extract-and-expand, used to turn one X25519 shared secret into
/// several independent keys.
void hkdf_sha256(const void* secret, std::size_t secret_len, const void* salt,
                 std::size_t salt_len, std::string_view info, void* out, std::size_t out_len);

// ---------------------------------------------------------------------------
// Password stretching
// ---------------------------------------------------------------------------

/// Cost parameters for scrypt.
///
/// N=2^15, r=8, p=1 needs 128*N*r = 32 MiB and takes on the order of 100 ms,
/// which is the standard interactive setting. The memory hardness is the point:
/// it is what makes an offline dictionary attack against a public password
/// expensive rather than trivial, and docs/SECURITY.md explains why that attack
/// is the residual risk in this design.
struct ScryptParams {
    std::uint64_t n = 1u << 15;
    std::uint32_t r = 8;
    std::uint32_t p = 1;
};

/// Derive `out_len` bytes from a password. Deliberately slow.
void scrypt_derive(std::string_view password, const void* salt, std::size_t salt_len,
                   const ScryptParams& params, void* out, std::size_t out_len);

// ---------------------------------------------------------------------------
// Asymmetric primitives
// ---------------------------------------------------------------------------

/// An X25519 key pair. Ephemeral: a fresh one is generated per transfer so that
/// a key recovered later cannot decrypt a recorded transfer.
struct X25519KeyPair {
    SecretArray<kX25519KeySize> secret;
    std::uint8_t public_key[kX25519KeySize]{};
};

X25519KeyPair x25519_generate();

/// Compute the shared secret. Throws if the peer's key is the all-zero point or
/// any other value X25519 maps to zero, which is how a peer would try to force
/// a known shared secret.
SecretArray<kX25519KeySize> x25519_shared(const SecretArray<kX25519KeySize>& own_secret,
                                          const std::uint8_t peer_public[kX25519KeySize]);

/// A long-lived Ed25519 identity. Created by `drop-zone setup`, stored sealed
/// under the private password, and pinned by peers on first use so that a
/// username cannot be silently taken over.
struct Ed25519KeyPair {
    SecretArray<kEd25519PrivateKeySize> secret;
    std::uint8_t public_key[kEd25519PublicKeySize]{};
};

Ed25519KeyPair ed25519_generate();

/// Recover the public key from a stored private key.
void ed25519_public_from_secret(const SecretArray<kEd25519PrivateKeySize>& secret,
                                std::uint8_t out[kEd25519PublicKeySize]);

void ed25519_sign(const SecretArray<kEd25519PrivateKeySize>& secret, const void* message,
                  std::size_t len, std::uint8_t out[kEd25519SignatureSize]);

bool ed25519_verify(const std::uint8_t public_key[kEd25519PublicKeySize], const void* message,
                    std::size_t len, const std::uint8_t signature[kEd25519SignatureSize]);

// ---------------------------------------------------------------------------
// Authenticated encryption
// ---------------------------------------------------------------------------

enum class AeadAlgorithm : std::uint8_t {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
};

const char* aead_algorithm_name(AeadAlgorithm algorithm);

/// The faster AEAD on this CPU: AES-256-GCM where the hardware has AES and
/// carry-less multiply instructions, ChaCha20-Poly1305 otherwise.
AeadAlgorithm preferred_aead();

/// One AEAD context bound to one key.
///
/// Not thread-safe by design: an OpenSSL cipher context holds mutable state, so
/// sharing one between threads would need a lock on the hot path. Give each
/// worker its own instance -- that is what AeadPool does -- and the key schedule
/// is still built only once per worker.
class Aead {
public:
    Aead(AeadAlgorithm algorithm, const Key& key);
    ~Aead();

    Aead(const Aead&) = delete;
    Aead& operator=(const Aead&) = delete;
    Aead(Aead&&) noexcept;
    Aead& operator=(Aead&&) noexcept;

    AeadAlgorithm algorithm() const { return algorithm_; }

    /// Ciphertext bytes produced for `plaintext_len` bytes of input.
    static constexpr std::size_t sealed_size(std::size_t plaintext_len) {
        return plaintext_len + kAeadTagSize;
    }

    /// Encrypt in place-adjacent form: `out` must have room for
    /// sealed_size(len). The tag is appended after the ciphertext. Returns the
    /// number of bytes written.
    std::size_t seal(const std::uint8_t nonce[kAeadNonceSize], const void* aad, std::size_t aad_len,
                     const void* plaintext, std::size_t plaintext_len, std::uint8_t* out);

    /// Decrypt and verify. Returns false if the tag does not match, in which
    /// case `out` must be treated as undefined and discarded. Never throws on a
    /// bad tag: an attacker forging chunks should not be able to distinguish
    /// failure modes.
    bool open(const std::uint8_t nonce[kAeadNonceSize], const void* aad, std::size_t aad_len,
              const void* ciphertext, std::size_t ciphertext_len, std::uint8_t* out,
              std::size_t* out_len);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    AeadAlgorithm algorithm_;
};

/// Build a 96-bit nonce from a per-session random prefix and a counter.
///
/// The prefix keeps nonces distinct between sessions that happen to reuse a
/// counter value, and the counter is unique per direction within a session, so
/// no (key, nonce) pair is ever used twice -- the one catastrophic failure mode
/// of both AEADs. Because the counter is carried explicitly in each chunk
/// header rather than implied by arrival order, chunks can be encrypted and
/// decrypted out of order and in parallel.
void build_nonce(const std::uint8_t prefix[4], std::uint64_t counter,
                 std::uint8_t out[kAeadNonceSize]);

/// Seal a short message with a one-off random nonce prepended to the output.
/// Used for the identity keystore and the sealed offer, where there is no
/// counter to draw on.
std::vector<std::uint8_t> seal_standalone(AeadAlgorithm algorithm, const Key& key,
                                          std::string_view aad, const void* plaintext,
                                          std::size_t len);

/// Inverse of seal_standalone. Returns false if the input is truncated or the
/// tag does not verify.
bool open_standalone(AeadAlgorithm algorithm, const Key& key, std::string_view aad,
                     const std::vector<std::uint8_t>& sealed, SecretBytes& out);

}  // namespace dz
