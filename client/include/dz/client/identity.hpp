// The local identity and the keystore that protects it.
//
// `drop-zone setup` generates one long-lived Ed25519 key pair and seals the
// private half -- along with the public password senders must know -- under the
// private password. Nothing else on the machine needs that password, and it
// never crosses the network in any form.
//
// The identity's job is continuity. The rendezvous server has no account
// registry -- it cannot, if it is to keep nothing -- so it cannot promise that
// the "alice" accepting files today is the same alice as last week. The identity
// key can: peers record the key they saw the first time and notice if it changes.

#pragma once

#include <string>

#include "dz/client/config.hpp"
#include "dz/crypto.hpp"

namespace dz::client {

/// An unlocked identity, held only for as long as a command is running.
struct Identity {
    Ed25519KeyPair keys;

    /// The public password senders must know, sealed in identity.key under the
    /// private password. Empty on a v1 keystore that has not been upgraded.
    SecretString public_password;

    /// Short, human-comparable form of the public key, for the UI and for
    /// known_peers. 16 bytes of SHA-256 -- long enough that finding a collision
    /// is out of reach, short enough to read out over a phone.
    std::string fingerprint() const;
};

/// Fingerprint of any Ed25519 public key, in the same form.
std::string fingerprint_of(const std::uint8_t public_key[kEd25519PublicKeySize]);

/// Generate a new identity and write it sealed under `private_password`, along
/// with `public_password` so `accept` does not have to ask for it again.
Identity create_identity(const Config& config, std::string_view private_password,
                         std::string_view public_password = {});

/// Unlock identity.key. Throws a UserError when the password is wrong, which is
/// indistinguishable from the file having been tampered with -- the AEAD tag
/// fails either way, and it is not worth telling an attacker which.
Identity unlock_identity(const Config& config, std::string_view private_password);

/// Re-seal identity.key with the current identity key and public password.
/// Used to store a public password chosen at setup, or to replace it later.
void save_identity(const Config& config, const Identity& identity,
                   std::string_view private_password);

/// True when identity.key exists.
bool identity_exists(const Config& config);

/// Read a password from the terminal with echo turned off.
///
/// Falls back to reading a line from stdin when there is no terminal, so the
/// end-to-end test can drive the client from a pipe.
SecretString read_password(std::string_view prompt);

/// Read a password twice and require the two to match.
SecretString read_password_twice(std::string_view prompt, std::string_view confirm_prompt);

/// Read a line of ordinary, echoed input.
std::string read_line(std::string_view prompt, std::string_view fallback);

/// Ask a yes/no question. Returns `fallback` when input is not a terminal and
/// nothing is available.
bool read_yes_no(std::string_view prompt, bool fallback);

}  // namespace dz::client
