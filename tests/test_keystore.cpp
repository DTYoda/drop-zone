// The identity keystore and the configuration file.
//
// The keystore is what stands between a stolen laptop and the private key that
// identifies its owner to their peers, so what matters is that a wrong password
// fails, that a tampered file fails, and that the file is never readable by anybody
// else on the machine.

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "dz/client/config.hpp"
#include "dz/client/identity.hpp"
#include "dz/client/known_peers.hpp"
#include "dz/crypto.hpp"
#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "harness.hpp"

using namespace dz;
using namespace dz::client;

namespace {

/// A scratch directory that removes itself.
class TemporaryDirectory {
public:
    TemporaryDirectory() {
        char pattern[] = "/tmp/drop-zone-test-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) throw dz::test::Failure("cannot create a temporary directory");
        path_ = created;
    }

    ~TemporaryDirectory() {
        // Only the files these tests create, so a bug here cannot delete a tree.
        for (const char* name : {"config.toml", "identity.key", "known_peers", "config.toml.tmp",
                                 "identity.key.tmp", "known_peers.tmp"}) {
            ::unlink(join_path(path_, name).c_str());
        }
        ::rmdir(path_.c_str());
    }

    const std::string& path() const { return path_; }

private:
    std::string path_;
};

Config make_config(const std::string& directory) {
    Config config;
    config.directory = directory;
    config.username = "alice";
    config.server_host = "drop-zone.example.net";
    config.server_port = 47654;
    random_bytes(config.keystore_salt, kKeystoreSaltSize);
    return config;
}

/// The file's permission bits.
mode_t permissions_of(const std::string& path) {
    struct stat info{};
    if (::stat(path.c_str(), &info) != 0) throw dz::test::Failure("cannot stat " + path);
    return info.st_mode & 07777;
}

}  // namespace

DZ_TEST(an_identity_unlocks_with_the_right_password) {
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    save_config(config);

    Identity created = create_identity(config, "the-private-password");
    Identity unlocked = unlock_identity(config, "the-private-password");

    // The public key is recomputed from the private one on unlock, so matching
    // fingerprints means the whole key survived the round trip.
    DZ_CHECK_EQUAL(unlocked.fingerprint(), created.fingerprint());
    DZ_CHECK(std::memcmp(unlocked.keys.public_key, created.keys.public_key,
                         kEd25519PublicKeySize) == 0);

    // And the recovered key really signs.
    std::string message = "a transcript";
    std::uint8_t signature[kEd25519SignatureSize];
    ed25519_sign(unlocked.keys.secret, message.data(), message.size(), signature);
    DZ_CHECK(ed25519_verify(created.keys.public_key, message.data(), message.size(), signature));
}

DZ_TEST(an_identity_does_not_unlock_with_the_wrong_password) {
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    save_config(config);

    create_identity(config, "the-private-password");
    DZ_CHECK_THROWS(unlock_identity(config, "the-wrong-password"));
    // Not even a password that differs in one character.
    DZ_CHECK_THROWS(unlock_identity(config, "the-private-passworD"));
}

DZ_TEST(a_tampered_keystore_does_not_unlock) {
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    save_config(config);
    create_identity(config, "password");

    // Flip a bit in the sealed body. The AEAD tag catches it, so somebody who can
    // write the file cannot substitute a key of their own.
    std::string path = config.identity_path();
    std::FILE* file = std::fopen(path.c_str(), "r+b");
    DZ_CHECK(file != nullptr);
    std::fseek(file, 20, SEEK_SET);
    int byte = std::fgetc(file);
    std::fseek(file, 20, SEEK_SET);
    std::fputc(byte ^ 0x01, file);
    std::fclose(file);

    DZ_CHECK_THROWS(unlock_identity(config, "password"));
}

DZ_TEST(a_different_salt_makes_the_same_password_useless) {
    // The salt is per installation, so two people with the same private password do
    // not end up with the same key sealing their identity.
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    save_config(config);
    create_identity(config, "password");

    Config with_other_salt = config;
    random_bytes(with_other_salt.keystore_salt, kKeystoreSaltSize);
    DZ_CHECK_THROWS(unlock_identity(with_other_salt, "password"));
}

DZ_TEST(the_config_and_keystore_are_private_to_their_owner) {
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    save_config(config);
    create_identity(config, "password");

    // Created 0600 rather than chmod-ed afterwards, so there is no window in which
    // the identity is readable by others.
    DZ_CHECK_EQUAL(permissions_of(config.config_path()), static_cast<mode_t>(0600));
    DZ_CHECK_EQUAL(permissions_of(config.identity_path()), static_cast<mode_t>(0600));
}

DZ_TEST(the_config_round_trips) {
    TemporaryDirectory directory;
    Config config = make_config(directory.path());
    config.default_output_directory = "/tmp/incoming";
    config.encrypt_by_default = false;
    config.verify_digests = true;
    config.prompt_before_accepting = false;
    save_config(config);

    Config loaded = load_config(directory.path());
    DZ_CHECK_EQUAL(loaded.username, std::string("alice"));
    DZ_CHECK_EQUAL(loaded.server_host, std::string("drop-zone.example.net"));
    DZ_CHECK_EQUAL(loaded.server_port, 47654);
    DZ_CHECK_EQUAL(loaded.default_output_directory, std::string("/tmp/incoming"));
    DZ_CHECK_EQUAL(loaded.encrypt_by_default, false);
    DZ_CHECK_EQUAL(loaded.verify_digests, true);
    DZ_CHECK_EQUAL(loaded.prompt_before_accepting, false);
    DZ_CHECK(std::memcmp(loaded.keystore_salt, config.keystore_salt, kKeystoreSaltSize) == 0);

    // The public password is not in the file at all: the client is the side that
    // already knows it, and storing it would make reading config.toml enough to
    // receive files as this user.
    std::string contents;
    {
        std::FILE* file = std::fopen(loaded.config_path().c_str(), "rb");
        DZ_CHECK(file != nullptr);
        char buffer[4096];
        std::size_t got = std::fread(buffer, 1, sizeof(buffer), file);
        contents.assign(buffer, got);
        std::fclose(file);
    }
    DZ_CHECK(contents.find("password = ") == std::string::npos);
}

DZ_TEST(a_missing_config_is_reported_as_something_the_user_can_fix) {
    TemporaryDirectory directory;
    DZ_CHECK(!config_exists(directory.path()));

    try {
        load_config(directory.path());
        DZ_CHECK(false);
    } catch (const UserError& error) {
        // Should name the remedy, not just the failure.
        DZ_CHECK(std::string(error.what()).find("drop-zone setup") != std::string::npos);
    }
}

DZ_TEST(known_peers_pins_a_key_on_first_sight) {
    TemporaryDirectory directory;
    std::string path = join_path(directory.path(), "known_peers");

    Ed25519KeyPair bob = ed25519_generate();

    KnownPeers peers(path);
    peers.load();
    DZ_CHECK(peers.check("bob", bob.public_key) == PinResult::FirstSight);

    peers.remember("bob", bob.public_key);
    DZ_CHECK(peers.check("bob", bob.public_key) == PinResult::Matches);

    // A different key under the same username is the case the record exists to
    // catch: either bob reinstalled, or somebody else has taken the name.
    Ed25519KeyPair impostor = ed25519_generate();
    DZ_CHECK(peers.check("bob", impostor.public_key) == PinResult::Changed);

    // And it survives a reload, which is the whole point of writing it down.
    KnownPeers reloaded(path);
    reloaded.load();
    DZ_CHECK(reloaded.check("bob", bob.public_key) == PinResult::Matches);
    DZ_CHECK(reloaded.check("bob", impostor.public_key) == PinResult::Changed);
    DZ_CHECK(reloaded.check("carol", bob.public_key) == PinResult::FirstSight);
}

DZ_TEST(known_peers_keeps_several_peers_apart) {
    TemporaryDirectory directory;
    std::string path = join_path(directory.path(), "known_peers");

    Ed25519KeyPair bob = ed25519_generate();
    Ed25519KeyPair carol = ed25519_generate();

    KnownPeers peers(path);
    peers.load();
    peers.remember("bob", bob.public_key);
    peers.remember("carol", carol.public_key);

    KnownPeers reloaded(path);
    reloaded.load();
    DZ_CHECK_EQUAL(reloaded.peers().size(), 2u);
    DZ_CHECK(reloaded.check("bob", bob.public_key) == PinResult::Matches);
    DZ_CHECK(reloaded.check("carol", carol.public_key) == PinResult::Matches);
    // Crucially, one peer's key must not verify for another's name.
    DZ_CHECK(reloaded.check("bob", carol.public_key) == PinResult::Changed);
}

DZ_TEST(fingerprints_are_short_stable_and_distinct) {
    Ed25519KeyPair a = ed25519_generate();
    Ed25519KeyPair b = ed25519_generate();

    std::string first = fingerprint_of(a.public_key);
    // Short enough to read out loud, long enough that a collision is out of reach.
    DZ_CHECK_EQUAL(first.size(), 32u);
    DZ_CHECK_EQUAL(fingerprint_of(a.public_key), first);
    DZ_CHECK(fingerprint_of(b.public_key) != first);
}
