// The crypto layer.
//
// These check the properties the protocol actually relies on, rather than testing
// libcrypto: that a tag catches a modified header as well as modified contents,
// that a counter produces distinct nonces, that key agreement rejects the
// degenerate keys a hostile peer would send, and that a nonce reuse is impossible
// by construction.

#include <cstring>
#include <set>
#include <vector>

#include "dz/crypto.hpp"
#include "dz/cpu.hpp"
#include "dz/protocol.hpp"
#include "dz/secure.hpp"
#include "harness.hpp"

using namespace dz;

namespace {

Key key_from_byte(std::uint8_t value) {
    Key key;
    std::memset(key.data(), value, key.size());
    return key;
}

}  // namespace

DZ_TEST(both_aeads_round_trip) {
    for (AeadAlgorithm algorithm : {AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305}) {
        Key key = key_from_byte(0x42);
        Aead aead(algorithm, key);

        std::uint8_t nonce[kAeadNonceSize] = {};
        std::string aad = "chunk header stand-in";
        std::vector<std::uint8_t> plaintext(4096);
        random_bytes(plaintext.data(), plaintext.size());

        std::vector<std::uint8_t> sealed(Aead::sealed_size(plaintext.size()));
        std::size_t written = aead.seal(nonce, aad.data(), aad.size(), plaintext.data(),
                                       plaintext.size(), sealed.data());
        DZ_CHECK_EQUAL(written, Aead::sealed_size(plaintext.size()));

        std::vector<std::uint8_t> opened(plaintext.size());
        std::size_t produced = 0;
        DZ_CHECK(aead.open(nonce, aad.data(), aad.size(), sealed.data(), written, opened.data(),
                           &produced));
        DZ_CHECK_EQUAL(produced, plaintext.size());
        DZ_CHECK(std::memcmp(opened.data(), plaintext.data(), plaintext.size()) == 0);
    }
}

DZ_TEST(a_modified_ciphertext_fails_to_open) {
    Key key = key_from_byte(0x11);
    Aead aead(preferred_aead(), key);

    std::uint8_t nonce[kAeadNonceSize] = {};
    std::vector<std::uint8_t> plaintext(1024, 0xaa);
    std::vector<std::uint8_t> sealed(Aead::sealed_size(plaintext.size()));

    std::size_t written = aead.seal(nonce, nullptr, 0, plaintext.data(), plaintext.size(),
                                   sealed.data());
    sealed[500] ^= 0x01;

    std::vector<std::uint8_t> opened(plaintext.size());
    std::size_t produced = 0;
    DZ_CHECK(!aead.open(nonce, nullptr, 0, sealed.data(), written, opened.data(), &produced));
}

DZ_TEST(a_modified_chunk_header_fails_to_open) {
    // This is the property that stops a chunk being moved to a different offset or a
    // different file. The ciphertext would still decrypt; the tag would not verify,
    // because the header is the associated data.
    Key key = key_from_byte(0x22);
    Aead aead(preferred_aead(), key);

    ChunkHeader header;
    header.file_index = 3;
    header.plaintext_length = 1024;
    header.offset = 4096;
    header.counter = 9;

    std::uint8_t header_bytes[kChunkHeaderSize];
    encode_chunk_header(header, header_bytes);

    std::uint8_t nonce[kAeadNonceSize];
    build_nonce(reinterpret_cast<const std::uint8_t*>("abcd"), header.counter, nonce);

    std::vector<std::uint8_t> plaintext(1024, 0x5a);
    std::vector<std::uint8_t> sealed(Aead::sealed_size(plaintext.size()));
    std::size_t written = aead.seal(nonce, header_bytes, sizeof(header_bytes), plaintext.data(),
                                   plaintext.size(), sealed.data());

    // Move the chunk to a different file.
    header.file_index = 4;
    encode_chunk_header(header, header_bytes);

    std::vector<std::uint8_t> opened(plaintext.size());
    std::size_t produced = 0;
    DZ_CHECK(!aead.open(nonce, header_bytes, sizeof(header_bytes), sealed.data(), written,
                        opened.data(), &produced));
}

DZ_TEST(a_wrong_key_fails_to_open) {
    std::uint8_t nonce[kAeadNonceSize] = {};
    std::vector<std::uint8_t> plaintext(256, 0x33);
    std::vector<std::uint8_t> sealed(Aead::sealed_size(plaintext.size()));

    Aead sealer(preferred_aead(), key_from_byte(1));
    std::size_t written = sealer.seal(nonce, nullptr, 0, plaintext.data(), plaintext.size(),
                                     sealed.data());

    Aead opener(preferred_aead(), key_from_byte(2));
    std::vector<std::uint8_t> opened(plaintext.size());
    std::size_t produced = 0;
    DZ_CHECK(!opener.open(nonce, nullptr, 0, sealed.data(), written, opened.data(), &produced));
}

DZ_TEST(a_context_survives_thousands_of_chunks) {
    // Each worker keeps one context for the whole transfer so the key schedule is
    // built once. That only works if a context can be reused indefinitely with a
    // fresh nonce each time, which is what this checks.
    Key key = key_from_byte(0x77);
    Aead aead(preferred_aead(), key);

    std::uint8_t prefix[4] = {1, 2, 3, 4};
    std::vector<std::uint8_t> plaintext(512, 0xc3);
    std::vector<std::uint8_t> sealed(Aead::sealed_size(plaintext.size()));
    std::vector<std::uint8_t> opened(plaintext.size());

    for (std::uint64_t counter = 0; counter < 5000; ++counter) {
        std::uint8_t nonce[kAeadNonceSize];
        build_nonce(prefix, counter, nonce);

        std::size_t written = aead.seal(nonce, nullptr, 0, plaintext.data(), plaintext.size(),
                                       sealed.data());
        std::size_t produced = 0;
        DZ_CHECK(aead.open(nonce, nullptr, 0, sealed.data(), written, opened.data(), &produced));
        DZ_CHECK_EQUAL(produced, plaintext.size());
    }
}

DZ_TEST(nonces_are_distinct_for_distinct_counters) {
    // Reusing a (key, nonce) pair breaks both AEADs outright, so the construction has
    // to guarantee uniqueness rather than merely make a collision unlikely.
    std::uint8_t prefix[4] = {0xde, 0xad, 0xbe, 0xef};
    std::set<std::vector<std::uint8_t>> seen;

    for (std::uint64_t counter = 0; counter < 10000; ++counter) {
        std::uint8_t nonce[kAeadNonceSize];
        build_nonce(prefix, counter, nonce);
        DZ_CHECK(seen.emplace(nonce, nonce + kAeadNonceSize).second);
    }

    // A different session prefix gives a different nonce for the same counter, which
    // is what keeps two sessions from colliding.
    std::uint8_t other_prefix[4] = {1, 2, 3, 4};
    std::uint8_t a[kAeadNonceSize];
    std::uint8_t b[kAeadNonceSize];
    build_nonce(prefix, 5, a);
    build_nonce(other_prefix, 5, b);
    DZ_CHECK(std::memcmp(a, b, kAeadNonceSize) != 0);
}

DZ_TEST(x25519_agrees_on_a_shared_secret) {
    X25519KeyPair alice = x25519_generate();
    X25519KeyPair bob = x25519_generate();

    SecretArray<kX25519KeySize> from_alice = x25519_shared(alice.secret, bob.public_key);
    SecretArray<kX25519KeySize> from_bob = x25519_shared(bob.secret, alice.public_key);
    DZ_CHECK(from_alice == from_bob);

    // And a third party's key gives something else entirely.
    X25519KeyPair eve = x25519_generate();
    DZ_CHECK(x25519_shared(alice.secret, eve.public_key) != from_alice);
}

DZ_TEST(x25519_rejects_a_low_order_public_key) {
    // The all-zero point maps every private key to a zero shared secret, so a peer
    // sending it could force a secret it already knows. libcrypto refuses, and the
    // wrapper turns that into an error rather than a silent zero key.
    X25519KeyPair own = x25519_generate();
    std::uint8_t zero[kX25519KeySize] = {};
    DZ_CHECK_THROWS(x25519_shared(own.secret, zero));
}

DZ_TEST(ed25519_signs_and_verifies) {
    Ed25519KeyPair keys = ed25519_generate();
    std::string message = "the handshake transcript";

    std::uint8_t signature[kEd25519SignatureSize];
    ed25519_sign(keys.secret, message.data(), message.size(), signature);

    DZ_CHECK(ed25519_verify(keys.public_key, message.data(), message.size(), signature));

    // A changed message must not verify.
    std::string tampered = "the handshake transcripT";
    DZ_CHECK(!ed25519_verify(keys.public_key, tampered.data(), tampered.size(), signature));

    // Nor must a different signer's key.
    Ed25519KeyPair other = ed25519_generate();
    DZ_CHECK(!ed25519_verify(other.public_key, message.data(), message.size(), signature));
}

DZ_TEST(ed25519_verification_survives_a_malformed_key) {
    // Public keys arrive from the network, so a nonsense one has to be a failed
    // verification rather than a crash.
    std::uint8_t nonsense[kEd25519PublicKeySize];
    std::memset(nonsense, 0xff, sizeof(nonsense));

    std::uint8_t signature[kEd25519SignatureSize] = {};
    DZ_CHECK(!ed25519_verify(nonsense, "x", 1, signature));
}

DZ_TEST(the_public_key_can_be_recovered_from_the_private_one) {
    // The keystore only stores the private half, so the two can never disagree.
    Ed25519KeyPair keys = ed25519_generate();

    std::uint8_t recovered[kEd25519PublicKeySize];
    ed25519_public_from_secret(keys.secret, recovered);
    DZ_CHECK(std::memcmp(recovered, keys.public_key, sizeof(recovered)) == 0);
}

DZ_TEST(hkdf_separates_keys_by_purpose) {
    std::uint8_t secret[32];
    std::uint8_t salt[32];
    random_bytes(secret, sizeof(secret));
    random_bytes(salt, sizeof(salt));

    // The two directions of the session must not share a key, or a message could be
    // reflected back at its own author.
    std::uint8_t forward[32];
    std::uint8_t backward[32];
    hkdf_sha256(secret, sizeof(secret), salt, sizeof(salt), kInfoDataKeySenderToReceiver, forward,
                sizeof(forward));
    hkdf_sha256(secret, sizeof(secret), salt, sizeof(salt), kInfoDataKeyReceiverToSender, backward,
                sizeof(backward));
    DZ_CHECK(std::memcmp(forward, backward, sizeof(forward)) != 0);

    // A different transcript gives different keys from the same secret, which is what
    // makes two sessions between the same peers independent.
    std::uint8_t other_salt[32];
    random_bytes(other_salt, sizeof(other_salt));

    std::uint8_t elsewhere[32];
    hkdf_sha256(secret, sizeof(secret), other_salt, sizeof(other_salt),
                kInfoDataKeySenderToReceiver, elsewhere, sizeof(elsewhere));
    DZ_CHECK(std::memcmp(forward, elsewhere, sizeof(forward)) != 0);

    // And it is deterministic, or the two peers would not agree.
    std::uint8_t again[32];
    hkdf_sha256(secret, sizeof(secret), salt, sizeof(salt), kInfoDataKeySenderToReceiver, again,
                sizeof(again));
    DZ_CHECK(std::memcmp(forward, again, sizeof(forward)) == 0);
}

DZ_TEST(the_public_password_key_depends_on_the_username) {
    // The salt is derived from the receiver's username, so the same password used by
    // two people does not produce the same MAC key.
    Key alice = derive_public_password_key("shared-password", "alice");
    Key bob = derive_public_password_key("shared-password", "bob");
    DZ_CHECK(alice != bob);

    // Deterministic for one username, or the sender's proof would never verify.
    DZ_CHECK(derive_public_password_key("shared-password", "alice") == alice);

    // And a different password gives a different key.
    DZ_CHECK(derive_public_password_key("other-password", "alice") != alice);
}

DZ_TEST(a_group_verifier_depends_on_the_password_and_the_name) {
    Key alice = derive_public_password_key("shared-password", "friends");
    std::uint8_t first[kSha256Size];
    std::uint8_t again[kSha256Size];
    derive_group_verifier(alice, "friends", first);
    derive_group_verifier(alice, "friends", again);
    DZ_CHECK(std::memcmp(first, again, kSha256Size) == 0);

    Key other_password = derive_public_password_key("other-password", "friends");
    std::uint8_t other[kSha256Size];
    derive_group_verifier(other_password, "friends", other);
    DZ_CHECK(std::memcmp(first, other, kSha256Size) != 0);

    std::uint8_t other_group[kSha256Size];
    derive_group_verifier(alice, "enemies", other_group);
    DZ_CHECK(std::memcmp(first, other_group, kSha256Size) != 0);

    // The group key is salted with the group name, so the same password used as
    // a personal public password does not produce the same MAC key.
    Key personal = derive_public_password_key("shared-password", "alice");
    DZ_CHECK(alice != personal);
}

DZ_TEST(standalone_sealing_round_trips_and_detects_tampering) {
    Key key = key_from_byte(0x99);
    std::string plaintext = "a sealed manifest the server cannot read";

    std::vector<std::uint8_t> sealed = seal_standalone(preferred_aead(), key, kInfoOfferKey,
                                                       plaintext.data(), plaintext.size());

    SecretBytes opened;
    DZ_CHECK(open_standalone(preferred_aead(), key, kInfoOfferKey, sealed, opened));
    DZ_CHECK_EQUAL(opened.size(), plaintext.size());
    DZ_CHECK(std::memcmp(opened.data(), plaintext.data(), plaintext.size()) == 0);

    // A different purpose string must not open it, which is what keeps a message
    // sealed for one role from being replayed into another.
    DZ_CHECK(!open_standalone(preferred_aead(), key, kKeystoreAad, sealed, opened));

    // Nor may a modified blob.
    std::vector<std::uint8_t> tampered = sealed;
    tampered[kAeadNonceSize + 2] ^= 0x40;
    DZ_CHECK(!open_standalone(preferred_aead(), key, kInfoOfferKey, tampered, opened));

    // Nor a truncated one.
    std::vector<std::uint8_t> truncated(sealed.begin(), sealed.begin() + 8);
    DZ_CHECK(!open_standalone(preferred_aead(), key, kInfoOfferKey, truncated, opened));
}

DZ_TEST(constant_time_comparison_agrees_with_memcmp) {
    std::uint8_t a[32];
    random_bytes(a, sizeof(a));

    std::uint8_t b[32];
    std::memcpy(b, a, sizeof(b));
    DZ_CHECK(constant_time_equal(a, b, sizeof(a)));

    // Differing in the last byte must be caught, not just the first: an
    // implementation that stopped early would pass a first-byte test and leak the
    // rest through timing.
    b[31] ^= 0x01;
    DZ_CHECK(!constant_time_equal(a, b, sizeof(a)));
}

DZ_TEST(hex_round_trips) {
    std::uint8_t bytes[16];
    random_bytes(bytes, sizeof(bytes));

    std::string hex = to_hex(bytes, sizeof(bytes));
    DZ_CHECK_EQUAL(hex.size(), 32u);

    std::vector<std::uint8_t> decoded;
    DZ_CHECK(from_hex(hex, decoded));
    DZ_CHECK_EQUAL(decoded.size(), sizeof(bytes));
    DZ_CHECK(std::memcmp(decoded.data(), bytes, sizeof(bytes)) == 0);

    DZ_CHECK(!from_hex("abc", decoded));      // Odd length.
    DZ_CHECK(!from_hex("zzzz", decoded));     // Not hex.
}

DZ_TEST(the_preferred_cipher_matches_the_cpu) {
    // The whole point of run-time selection: AES only when the hardware has both the
    // AES and the carry-less multiply instructions, because AES without the latter
    // leaves GCM's authentication in software and slower than ChaCha20.
    AeadAlgorithm expected =
        cpu_prefers_aes() ? AeadAlgorithm::Aes256Gcm : AeadAlgorithm::ChaCha20Poly1305;
    DZ_CHECK(preferred_aead() == expected);
    DZ_CHECK(!cpu_features_summary().empty());
    DZ_CHECK(hardware_threads() >= 1);
}
