// The client's on-disk configuration, written by `drop-zone setup`.
//
// Two files live in ~/.config/drop-zone, both mode 0600:
//
//   config.toml    username, server address, and preferences. No secrets.
//   identity.key   the Ed25519 identity, sealed under the private password.
//
// The public password is not stored in either. It is not a secret the client
// needs -- the client is the side that already knows it -- and keeping it out of
// the config means reading config.toml tells an attacker nothing they could use
// to receive files as this user.

#pragma once

#include <cstdint>
#include <string>

#include "dz/crypto.hpp"
#include "dz/protocol.hpp"

namespace dz::client {

struct Config {
    std::string username;
    std::string server_host;
    std::uint16_t server_port = kDefaultServerPort;

    /// Where received files go when `accept` is given no -o.
    /// Empty means the directory the program was run from.
    std::string default_output_directory;

    /// Encrypt the file payload by default. `--no-encrypt` overrides per run.
    bool encrypt_by_default = true;

    /// Hash every file and check the digests. Off by default because in
    /// encrypted mode the AEAD already authenticates every byte; see
    /// docs/SECURITY.md.
    bool verify_digests = false;

    /// Ask before accepting each transfer. Turning this off is what makes an
    /// unattended receiver possible.
    bool prompt_before_accepting = true;

    /// Salt for stretching the private password into the keystore key. Random
    /// per installation, so two people with the same password do not end up with
    /// the same keystore key.
    std::uint8_t keystore_salt[kKeystoreSaltSize]{};

    /// Path of the directory holding both files.
    std::string directory;

    std::string config_path() const;
    std::string identity_path() const;
    std::string known_peers_path() const;
};

/// The configuration directory: $DROP_ZONE_HOME, else $XDG_CONFIG_HOME/drop-zone,
/// else ~/.config/drop-zone.
///
/// The environment override exists so the end-to-end test can run two
/// independent clients on one machine without either touching the real
/// configuration of whoever is running it.
std::string default_config_directory();

/// Load the configuration, or throw a UserError telling the user to run setup.
Config load_config(const std::string& directory);

/// Write config.toml with mode 0600, replacing it atomically.
void save_config(const Config& config);

/// True when a configuration already exists in `directory`.
bool config_exists(const std::string& directory);

}  // namespace dz::client
