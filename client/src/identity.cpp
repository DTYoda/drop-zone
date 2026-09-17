#include "dz/client/identity.hpp"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

/// Version byte at the front of identity.key, so a future format change can be
/// recognised rather than mis-parsed.
constexpr std::uint8_t kKeystoreVersion = 1;

/// Stretch the private password into the key that seals the identity.
Key derive_keystore_key(std::string_view private_password, const std::uint8_t* salt) {
    Key key;
    // The same deliberately slow scrypt parameters as everywhere else: this is
    // the only thing standing between a stolen identity.key and the private key
    // inside it, so a fast derivation would make the file's protection nominal.
    scrypt_derive(private_password, salt, kKeystoreSaltSize, ScryptParams{}, key.data(),
                  key.size());
    return key;
}

void write_sealed_file(const std::string& path, const std::vector<std::uint8_t>& contents) {
    std::string temporary = path + ".tmp";

    int raw = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (raw < 0) fail_errno("cannot create '" + temporary + "'");

    Fd fd(raw);
    write_all(fd.get(), contents.data(), contents.size());
    fsync_file(fd.get());
    fd.reset();

    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        fail_errno("cannot move '" + temporary + "' into place");
    }
}

std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    int raw = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (raw < 0) fail_errno("cannot open '" + path + "'");

    Fd fd(raw);

    std::vector<std::uint8_t> contents;
    std::uint8_t buffer[4096];
    for (;;) {
        ssize_t got = ::read(fd.get(), buffer, sizeof(buffer));
        if (got < 0) {
            if (errno == EINTR) continue;
            fail_errno("cannot read '" + path + "'");
        }
        if (got == 0) break;
        contents.insert(contents.end(), buffer, buffer + got);
    }
    return contents;
}

}  // namespace

std::string Identity::fingerprint() const { return fingerprint_of(keys.public_key); }

std::string fingerprint_of(const std::uint8_t public_key[kEd25519PublicKeySize]) {
    Sha256Digest digest = sha256(public_key, kEd25519PublicKeySize);
    return to_hex(digest.data(), 16);
}

bool identity_exists(const Config& config) { return is_regular_file(config.identity_path()); }

Identity create_identity(const Config& config, std::string_view private_password) {
    Identity identity;
    identity.keys = ed25519_generate();

    Key keystore_key = derive_keystore_key(private_password, config.keystore_salt);

    // Only the private half is sealed; the public half is recomputed from it on
    // unlock, so the two can never disagree.
    std::vector<std::uint8_t> sealed = seal_standalone(
        preferred_aead(), keystore_key, kKeystoreAad, identity.keys.secret.data(),
        identity.keys.secret.size());

    std::vector<std::uint8_t> file;
    file.push_back(kKeystoreVersion);
    file.push_back(static_cast<std::uint8_t>(preferred_aead()));
    file.insert(file.end(), sealed.begin(), sealed.end());

    write_sealed_file(config.identity_path(), file);
    return identity;
}

Identity unlock_identity(const Config& config, std::string_view private_password) {
    std::vector<std::uint8_t> file = read_file_bytes(config.identity_path());

    if (file.size() < 2) fail("identity.key is truncated");
    if (file[0] != kKeystoreVersion) {
        fail("identity.key was written by a different version of drop-zone");
    }

    std::uint8_t algorithm_tag = file[1];
    if (algorithm_tag != 1 && algorithm_tag != 2) fail("identity.key names an unknown cipher");
    auto algorithm = static_cast<AeadAlgorithm>(algorithm_tag);

    std::vector<std::uint8_t> sealed(file.begin() + 2, file.end());
    Key keystore_key = derive_keystore_key(private_password, config.keystore_salt);

    SecretBytes secret;
    if (!open_standalone(algorithm, keystore_key, kKeystoreAad, sealed, secret)) {
        // A wrong password and a tampered file both land here. The message does
        // not distinguish them, because an attacker who has the file already
        // knows whether they modified it and only the password is worth guessing.
        fail_user("that private password does not unlock this identity");
    }
    if (secret.size() != kEd25519PrivateKeySize) fail("identity.key holds a malformed key");

    Identity identity;
    std::memcpy(identity.keys.secret.data(), secret.data(), secret.size());
    ed25519_public_from_secret(identity.keys.secret, identity.keys.public_key);
    return identity;
}

// ---------------------------------------------------------------------------
// Terminal input
// ---------------------------------------------------------------------------

SecretString read_password(std::string_view prompt) {
    SecretString password;

    bool interactive = ::isatty(STDIN_FILENO) == 1;

    termios original{};
    bool echo_disabled = false;
    if (interactive) {
        std::fputs(std::string(prompt).c_str(), stderr);
        std::fflush(stderr);

        if (::tcgetattr(STDIN_FILENO, &original) == 0) {
            termios quiet = original;
            quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
            if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0) echo_disabled = true;
        }
    }

    // Read a byte at a time straight into the secret string, so the password
    // never lands in a std::string that would not be wiped.
    for (;;) {
        char c = 0;
        ssize_t got = ::read(STDIN_FILENO, &c, 1);
        if (got < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (got == 0 || c == '\n') break;
        if (c == '\r') continue;
        password.push_back(c);
    }

    if (echo_disabled) {
        (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        std::fputs("\n", stderr);
    }

    return password;
}

SecretString read_password_twice(std::string_view prompt, std::string_view confirm_prompt) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        SecretString first = read_password(prompt);
        if (first.empty()) {
            std::fputs("A password is required.\n", stderr);
            continue;
        }

        SecretString second = read_password(confirm_prompt);
        if (first.size() == second.size() &&
            constant_time_equal(first.data(), second.data(), first.size())) {
            return first;
        }

        std::fputs("Those did not match. Try again.\n", stderr);
    }

    fail_user("gave up after three mismatched password entries");
}

std::string read_line(std::string_view prompt, std::string_view fallback) {
    if (::isatty(STDIN_FILENO) == 1) {
        std::fputs(std::string(prompt).c_str(), stderr);
        std::fflush(stderr);
    }

    std::string line;
    if (!std::getline(std::cin, line)) return std::string(fallback);

    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (line.empty()) return std::string(fallback);
    return line;
}

bool read_yes_no(std::string_view prompt, bool fallback) {
    std::string answer = read_line(prompt, fallback ? "y" : "n");
    return answer == "y" || answer == "Y" || answer == "yes" || answer == "YES";
}

}  // namespace dz::client
