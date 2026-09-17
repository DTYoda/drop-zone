#include "dz/crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>

#include "dz/cpu.hpp"
#include "dz/endian.hpp"
#include "dz/error.hpp"

namespace dz {

// ---------------------------------------------------------------------------
// Randomness and hashing
// ---------------------------------------------------------------------------

void random_bytes(void* out, std::size_t len) {
    if (len == 0) return;
    if (RAND_bytes(static_cast<unsigned char*>(out), static_cast<int>(len)) != 1) {
        fail_openssl("the system random number generator failed");
    }
}

Sha256Digest sha256(const void* data, std::size_t len) {
    Sha256Digest digest{};
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, digest.data(), &out_len, EVP_sha256(), nullptr) != 1) {
        fail_openssl("SHA-256 failed");
    }
    return digest;
}

struct Sha256::Impl {
    EVP_MD_CTX* ctx = nullptr;
};

Sha256::Sha256() : impl_(std::make_unique<Impl>()) {
    impl_->ctx = EVP_MD_CTX_new();
    if (impl_->ctx == nullptr) fail_openssl("cannot allocate a digest context");
    if (EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr) != 1) {
        fail_openssl("cannot initialise SHA-256");
    }
}

Sha256::~Sha256() {
    if (impl_ && impl_->ctx != nullptr) EVP_MD_CTX_free(impl_->ctx);
}

void Sha256::update(const void* data, std::size_t len) {
    if (len == 0) return;
    if (EVP_DigestUpdate(impl_->ctx, data, len) != 1) fail_openssl("SHA-256 update failed");
}

Sha256Digest Sha256::finish() {
    Sha256Digest digest{};
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(impl_->ctx, digest.data(), &out_len) != 1) {
        fail_openssl("SHA-256 finalisation failed");
    }
    return digest;
}

void hmac_sha256(const void* key, std::size_t key_len, const void* data, std::size_t data_len,
                 std::uint8_t out[kSha256Size]) {
    unsigned int out_len = 0;
    if (HMAC(EVP_sha256(), key, static_cast<int>(key_len),
             static_cast<const unsigned char*>(data), data_len, out, &out_len) == nullptr) {
        fail_openssl("HMAC-SHA256 failed");
    }
    if (out_len != kSha256Size) fail("HMAC-SHA256 produced an unexpected length");
}

void hkdf_sha256(const void* secret, std::size_t secret_len, const void* salt,
                 std::size_t salt_len, std::string_view info, void* out, std::size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx == nullptr) fail_openssl("cannot allocate an HKDF context");

    struct Guard {
        EVP_PKEY_CTX* ctx;
        ~Guard() { EVP_PKEY_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_PKEY_derive_init(ctx) != 1) fail_openssl("cannot initialise HKDF");
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) fail_openssl("cannot select SHA-256");
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, static_cast<const unsigned char*>(salt),
                                    static_cast<int>(salt_len)) != 1) {
        fail_openssl("cannot set the HKDF salt");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, static_cast<const unsigned char*>(secret),
                                   static_cast<int>(secret_len)) != 1) {
        fail_openssl("cannot set the HKDF input key");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) != 1) {
        fail_openssl("cannot set the HKDF info string");
    }

    std::size_t produced = out_len;
    if (EVP_PKEY_derive(ctx, static_cast<unsigned char*>(out), &produced) != 1) {
        fail_openssl("HKDF derivation failed");
    }
    if (produced != out_len) fail("HKDF produced an unexpected length");
}

// ---------------------------------------------------------------------------
// Password stretching
// ---------------------------------------------------------------------------

void scrypt_derive(std::string_view password, const void* salt, std::size_t salt_len,
                   const ScryptParams& params, void* out, std::size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);
    if (ctx == nullptr) fail_openssl("cannot allocate an scrypt context");

    struct Guard {
        EVP_PKEY_CTX* ctx;
        ~Guard() { EVP_PKEY_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_PKEY_derive_init(ctx) != 1) fail_openssl("cannot initialise scrypt");
    if (EVP_PKEY_CTX_set1_pbe_pass(ctx, password.data(), static_cast<int>(password.size())) != 1) {
        fail_openssl("cannot set the scrypt password");
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, static_cast<const unsigned char*>(salt),
                                      static_cast<int>(salt_len)) != 1) {
        fail_openssl("cannot set the scrypt salt");
    }
    if (EVP_PKEY_CTX_set_scrypt_N(ctx, params.n) != 1) fail_openssl("cannot set scrypt N");
    if (EVP_PKEY_CTX_set_scrypt_r(ctx, params.r) != 1) fail_openssl("cannot set scrypt r");
    if (EVP_PKEY_CTX_set_scrypt_p(ctx, params.p) != 1) fail_openssl("cannot set scrypt p");

    // libcrypto refuses any parameter set needing more than 32 MiB unless the
    // caller raises the ceiling, and the default cost here needs exactly that
    // much. Asking for 128 MiB leaves room to raise the cost later without
    // having to remember to change two places.
    if (EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx, 128ull * 1024 * 1024) != 1) {
        fail_openssl("cannot raise the scrypt memory limit");
    }

    std::size_t produced = out_len;
    if (EVP_PKEY_derive(ctx, static_cast<unsigned char*>(out), &produced) != 1) {
        fail_openssl("scrypt derivation failed");
    }
    if (produced != out_len) fail("scrypt produced an unexpected length");
}

// ---------------------------------------------------------------------------
// Asymmetric primitives
// ---------------------------------------------------------------------------

namespace {

/// Generate a raw key pair for one of the Edwards/Montgomery curve types.
void generate_raw_keypair(int type, std::uint8_t* secret, std::size_t secret_len,
                          std::uint8_t* public_key, std::size_t public_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(type, nullptr);
    if (ctx == nullptr) fail_openssl("cannot allocate a key generation context");

    EVP_PKEY* key = nullptr;
    struct Guard {
        EVP_PKEY_CTX* ctx;
        EVP_PKEY** key;
        ~Guard() {
            EVP_PKEY_CTX_free(ctx);
            if (*key != nullptr) EVP_PKEY_free(*key);
        }
    } guard{ctx, &key};

    if (EVP_PKEY_keygen_init(ctx) != 1) fail_openssl("cannot initialise key generation");
    if (EVP_PKEY_keygen(ctx, &key) != 1) fail_openssl("key generation failed");

    std::size_t len = secret_len;
    if (EVP_PKEY_get_raw_private_key(key, secret, &len) != 1 || len != secret_len) {
        fail_openssl("cannot export the generated private key");
    }
    len = public_len;
    if (EVP_PKEY_get_raw_public_key(key, public_key, &len) != 1 || len != public_len) {
        fail_openssl("cannot export the generated public key");
    }
}

}  // namespace

X25519KeyPair x25519_generate() {
    X25519KeyPair pair;
    generate_raw_keypair(EVP_PKEY_X25519, pair.secret.data(), pair.secret.size(),
                         pair.public_key, sizeof(pair.public_key));
    return pair;
}

SecretArray<kX25519KeySize> x25519_shared(const SecretArray<kX25519KeySize>& own_secret,
                                          const std::uint8_t peer_public[kX25519KeySize]) {
    EVP_PKEY* own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, own_secret.data(),
                                                 own_secret.size());
    if (own == nullptr) fail_openssl("cannot load the local X25519 key");

    EVP_PKEY* peer =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public, kX25519KeySize);
    EVP_PKEY_CTX* ctx = (peer != nullptr) ? EVP_PKEY_CTX_new(own, nullptr) : nullptr;

    struct Guard {
        EVP_PKEY* own;
        EVP_PKEY* peer;
        EVP_PKEY_CTX* ctx;
        ~Guard() {
            if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
            if (peer != nullptr) EVP_PKEY_free(peer);
            EVP_PKEY_free(own);
        }
    } guard{own, peer, ctx};

    if (peer == nullptr) fail_openssl("the peer sent an unusable X25519 public key");
    if (ctx == nullptr) fail_openssl("cannot allocate a key agreement context");

    if (EVP_PKEY_derive_init(ctx) != 1) fail_openssl("cannot initialise key agreement");
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) {
        fail_openssl("the peer's X25519 public key was rejected");
    }

    SecretArray<kX25519KeySize> shared;
    std::size_t len = shared.size();
    // libcrypto fails here for every low-order point, which is what stops a
    // peer from forcing an all-zero shared secret that it already knows.
    if (EVP_PKEY_derive(ctx, shared.data(), &len) != 1 || len != shared.size()) {
        fail_openssl("X25519 key agreement failed");
    }
    return shared;
}

Ed25519KeyPair ed25519_generate() {
    Ed25519KeyPair pair;
    generate_raw_keypair(EVP_PKEY_ED25519, pair.secret.data(), pair.secret.size(),
                         pair.public_key, sizeof(pair.public_key));
    return pair;
}

void ed25519_public_from_secret(const SecretArray<kEd25519PrivateKeySize>& secret,
                                std::uint8_t out[kEd25519PublicKeySize]) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, secret.data(),
                                                 secret.size());
    if (key == nullptr) fail_openssl("cannot load the Ed25519 private key");

    struct Guard {
        EVP_PKEY* key;
        ~Guard() { EVP_PKEY_free(key); }
    } guard{key};

    std::size_t len = kEd25519PublicKeySize;
    if (EVP_PKEY_get_raw_public_key(key, out, &len) != 1 || len != kEd25519PublicKeySize) {
        fail_openssl("cannot derive the Ed25519 public key");
    }
}

void ed25519_sign(const SecretArray<kEd25519PrivateKeySize>& secret, const void* message,
                  std::size_t len, std::uint8_t out[kEd25519SignatureSize]) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, secret.data(),
                                                 secret.size());
    if (key == nullptr) fail_openssl("cannot load the Ed25519 signing key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    struct Guard {
        EVP_PKEY* key;
        EVP_MD_CTX* ctx;
        ~Guard() {
            if (ctx != nullptr) EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
        }
    } guard{key, ctx};

    if (ctx == nullptr) fail_openssl("cannot allocate a signing context");
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) != 1) {
        fail_openssl("cannot initialise Ed25519 signing");
    }

    std::size_t signature_len = kEd25519SignatureSize;
    if (EVP_DigestSign(ctx, out, &signature_len, static_cast<const unsigned char*>(message), len) !=
            1 ||
        signature_len != kEd25519SignatureSize) {
        fail_openssl("Ed25519 signing failed");
    }
}

bool ed25519_verify(const std::uint8_t public_key[kEd25519PublicKeySize], const void* message,
                    std::size_t len, const std::uint8_t signature[kEd25519SignatureSize]) {
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key,
                                                kEd25519PublicKeySize);
    if (key == nullptr) {
        // A malformed public key is a failed verification, not a crash: it
        // arrived from the network.
        clear_openssl_errors();
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    struct Guard {
        EVP_PKEY* key;
        EVP_MD_CTX* ctx;
        ~Guard() {
            if (ctx != nullptr) EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
        }
    } guard{key, ctx};

    if (ctx == nullptr) return false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) != 1) return false;

    int rc = EVP_DigestVerify(ctx, signature, kEd25519SignatureSize,
                              static_cast<const unsigned char*>(message), len);
    clear_openssl_errors();
    return rc == 1;
}

// ---------------------------------------------------------------------------
// Authenticated encryption
// ---------------------------------------------------------------------------

const char* aead_algorithm_name(AeadAlgorithm algorithm) {
    switch (algorithm) {
        case AeadAlgorithm::Aes256Gcm: return "AES-256-GCM";
        case AeadAlgorithm::ChaCha20Poly1305: return "ChaCha20-Poly1305";
    }
    return "unknown";
}

AeadAlgorithm preferred_aead() {
    return cpu_prefers_aes() ? AeadAlgorithm::Aes256Gcm : AeadAlgorithm::ChaCha20Poly1305;
}

namespace {

const EVP_CIPHER* cipher_for(AeadAlgorithm algorithm) {
    switch (algorithm) {
        case AeadAlgorithm::Aes256Gcm: return EVP_aes_256_gcm();
        case AeadAlgorithm::ChaCha20Poly1305: return EVP_chacha20_poly1305();
    }
    fail("unknown AEAD algorithm");
}

}  // namespace

struct Aead::Impl {
    EVP_CIPHER_CTX* seal_ctx = nullptr;
    EVP_CIPHER_CTX* open_ctx = nullptr;

    ~Impl() {
        if (seal_ctx != nullptr) EVP_CIPHER_CTX_free(seal_ctx);
        if (open_ctx != nullptr) EVP_CIPHER_CTX_free(open_ctx);
    }
};

Aead::Aead(AeadAlgorithm algorithm, const Key& key)
    : impl_(std::make_unique<Impl>()), algorithm_(algorithm) {
    const EVP_CIPHER* cipher = cipher_for(algorithm);

    // Two contexts, each initialised with the key exactly once here. Every
    // subsequent seal() or open() only installs a fresh nonce, so the AES key
    // schedule -- or the ChaCha state setup -- is computed once per worker
    // rather than once per megabyte. Over a 10 GiB transfer that is ten
    // thousand key schedules avoided.
    impl_->seal_ctx = EVP_CIPHER_CTX_new();
    impl_->open_ctx = EVP_CIPHER_CTX_new();
    if (impl_->seal_ctx == nullptr || impl_->open_ctx == nullptr) {
        fail_openssl("cannot allocate a cipher context");
    }

    if (EVP_EncryptInit_ex(impl_->seal_ctx, cipher, nullptr, key.data(), nullptr) != 1) {
        fail_openssl("cannot install the encryption key");
    }
    if (EVP_DecryptInit_ex(impl_->open_ctx, cipher, nullptr, key.data(), nullptr) != 1) {
        fail_openssl("cannot install the decryption key");
    }

    // Padding is meaningless for a stream AEAD and would add a block to every
    // chunk.
    EVP_CIPHER_CTX_set_padding(impl_->seal_ctx, 0);
    EVP_CIPHER_CTX_set_padding(impl_->open_ctx, 0);
}

Aead::~Aead() = default;
Aead::Aead(Aead&&) noexcept = default;
Aead& Aead::operator=(Aead&&) noexcept = default;

std::size_t Aead::seal(const std::uint8_t nonce[kAeadNonceSize], const void* aad,
                       std::size_t aad_len, const void* plaintext, std::size_t plaintext_len,
                       std::uint8_t* out) {
    EVP_CIPHER_CTX* ctx = impl_->seal_ctx;

    // Passing a null cipher and null key reuses the key already installed and
    // only refreshes the nonce.
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce) != 1) {
        fail_openssl("cannot set the encryption nonce");
    }

    int len = 0;
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, static_cast<const unsigned char*>(aad),
                              static_cast<int>(aad_len)) != 1) {
            fail_openssl("cannot authenticate the chunk header");
        }
    }

    int produced = 0;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, out, &produced, static_cast<const unsigned char*>(plaintext),
                              static_cast<int>(plaintext_len)) != 1) {
            fail_openssl("encryption failed");
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out + produced, &final_len) != 1) {
        fail_openssl("encryption finalisation failed");
    }
    produced += final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kAeadTagSize),
                            out + produced) != 1) {
        fail_openssl("cannot read the authentication tag");
    }

    return static_cast<std::size_t>(produced) + kAeadTagSize;
}

bool Aead::open(const std::uint8_t nonce[kAeadNonceSize], const void* aad, std::size_t aad_len,
                const void* ciphertext, std::size_t ciphertext_len, std::uint8_t* out,
                std::size_t* out_len) {
    if (ciphertext_len < kAeadTagSize) return false;

    std::size_t body_len = ciphertext_len - kAeadTagSize;
    const auto* body = static_cast<const unsigned char*>(ciphertext);
    const unsigned char* tag = body + body_len;

    EVP_CIPHER_CTX* ctx = impl_->open_ctx;

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce) != 1) {
        fail_openssl("cannot set the decryption nonce");
    }

    int len = 0;
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, static_cast<const unsigned char*>(aad),
                              static_cast<int>(aad_len)) != 1) {
            fail_openssl("cannot authenticate the chunk header");
        }
    }

    int produced = 0;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &produced, body, static_cast<int>(body_len)) != 1) {
            clear_openssl_errors();
            return false;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagSize),
                            const_cast<unsigned char*>(tag)) != 1) {
        fail_openssl("cannot install the authentication tag");
    }

    int final_len = 0;
    // This is where a forged or corrupted chunk is caught. A failure is
    // reported as false rather than an exception because it is an expected
    // outcome on a hostile network, and the caller decides whether to retry the
    // chunk or abandon the transfer.
    if (EVP_DecryptFinal_ex(ctx, out + produced, &final_len) != 1) {
        clear_openssl_errors();
        return false;
    }

    *out_len = static_cast<std::size_t>(produced + final_len);
    return true;
}

void build_nonce(const std::uint8_t prefix[4], std::uint64_t counter,
                 std::uint8_t out[kAeadNonceSize]) {
    std::memcpy(out, prefix, 4);
    store_u64(out + 4, counter);
}

std::vector<std::uint8_t> seal_standalone(AeadAlgorithm algorithm, const Key& key,
                                          std::string_view aad, const void* plaintext,
                                          std::size_t len) {
    // No counter is available for these one-off messages, so the nonce is
    // random and travels with the ciphertext. 96 random bits is safe for the
    // handful of messages a session seals this way, unlike for bulk chunks
    // where a counter is required.
    std::vector<std::uint8_t> out(kAeadNonceSize + Aead::sealed_size(len));
    random_bytes(out.data(), kAeadNonceSize);

    Aead aead(algorithm, key);
    std::size_t written = aead.seal(out.data(), aad.data(), aad.size(), plaintext, len,
                                    out.data() + kAeadNonceSize);
    out.resize(kAeadNonceSize + written);
    return out;
}

bool open_standalone(AeadAlgorithm algorithm, const Key& key, std::string_view aad,
                     const std::vector<std::uint8_t>& sealed, SecretBytes& out) {
    if (sealed.size() < kAeadNonceSize + kAeadTagSize) return false;

    std::size_t body_len = sealed.size() - kAeadNonceSize;
    out.resize(body_len - kAeadTagSize);

    Aead aead(algorithm, key);
    std::size_t produced = 0;
    bool ok = aead.open(sealed.data(), aad.data(), aad.size(), sealed.data() + kAeadNonceSize,
                        body_len, out.data(), &produced);
    if (!ok) {
        out.clear();
        return false;
    }
    out.resize(produced);
    return true;
}

}  // namespace dz
