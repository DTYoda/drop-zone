#include "dz/client/config.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

/// Strip whitespace from both ends.
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return text;
}

/// Remove one layer of surrounding double quotes, if present.
std::string_view unquote(std::string_view text) {
    if (text.size() >= 2 && text.front() == '"' && text.back() == '"') {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

bool parse_bool(std::string_view text, bool fallback) {
    if (text == "true" || text == "yes" || text == "1") return true;
    if (text == "false" || text == "no" || text == "0") return false;
    return fallback;
}

/// Write `contents` to `path` with mode 0600, atomically.
///
/// Written to a temporary alongside the target and renamed, so an interrupted
/// write cannot leave a half-written config -- and created with 0600 from the
/// start rather than chmod-ed afterwards, which would leave a window in which
/// the identity was world-readable.
void write_private_file(const std::string& path, const std::string& contents) {
    std::string temporary = path + ".tmp";

    int raw = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (raw < 0) fail_errno("cannot create '" + temporary + "'");

    Fd fd(raw);
    write_file_all(fd.get(), contents.data(), contents.size());
    fsync_file(fd.get());
    fd.reset();

    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        fail_errno("cannot move '" + temporary + "' into place");
    }
}

}  // namespace

std::string Config::config_path() const { return join_path(directory, "config.toml"); }

std::string Config::identity_path() const { return join_path(directory, "identity.key"); }

std::string Config::known_peers_path() const { return join_path(directory, "known_peers"); }

std::string default_config_directory() {
    if (const char* override_path = std::getenv("DROP_ZONE_HOME");
        override_path != nullptr && *override_path != '\0') {
        return expand_user_path(override_path);
    }
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg != nullptr && *xdg != '\0') {
        return join_path(expand_user_path(xdg), "drop-zone");
    }

    const char* home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') {
        fail("cannot work out where to keep the configuration: neither $DROP_ZONE_HOME, "
             "$XDG_CONFIG_HOME nor $HOME is set");
    }
    return join_path(home, ".config/drop-zone");
}

bool config_exists(const std::string& directory) {
    return is_regular_file(join_path(directory, "config.toml"));
}

Config load_config(const std::string& directory) {
    std::string path = join_path(directory, "config.toml");

    std::ifstream input(path);
    if (!input) {
        fail_user("no drop-zone configuration found at '" + path +
                  "'. Run `drop-zone setup` first.");
    }

    Config config;
    config.directory = directory;

    std::string line;
    while (std::getline(input, line)) {
        std::string_view view = trim(line);
        if (view.empty() || view.front() == '#' || view.front() == '[') continue;

        std::size_t equals = view.find('=');
        if (equals == std::string_view::npos) continue;

        std::string_view key = trim(view.substr(0, equals));
        std::string_view value = unquote(trim(view.substr(equals + 1)));

        if (key == "username") {
            config.username = std::string(value);
        } else if (key == "server_host") {
            config.server_host = std::string(value);
        } else if (key == "server_port") {
            unsigned port = 0;
            auto result = std::from_chars(value.data(), value.data() + value.size(), port);
            if (result.ec == std::errc() && port > 0 && port <= 65535) {
                config.server_port = static_cast<std::uint16_t>(port);
            }
        } else if (key == "output_directory") {
            config.default_output_directory = expand_user_path(std::string(value));
        } else if (key == "encrypt") {
            config.encrypt_by_default = parse_bool(value, true);
        } else if (key == "verify_digests") {
            config.verify_digests = parse_bool(value, false);
        } else if (key == "prompt_before_accepting") {
            config.prompt_before_accepting = parse_bool(value, true);
        } else if (key == "keystore_salt") {
            std::vector<std::uint8_t> salt;
            if (!from_hex(value, salt) || salt.size() != kKeystoreSaltSize) {
                fail("config.toml has a malformed keystore_salt; the identity cannot be unlocked");
            }
            std::memcpy(config.keystore_salt, salt.data(), salt.size());
        }
    }

    if (config.username.empty()) fail("config.toml does not name a username");
    if (!is_valid_username(config.username)) {
        fail("config.toml names an invalid username: '" + config.username + "'");
    }
    if (config.server_host.empty()) fail("config.toml does not name a server");

    return config;
}

void save_config(const Config& config) {
    make_directories(config.directory);

    std::ostringstream out;
    out << "# drop-zone client configuration.\n"
        << "#\n"
        << "# Written by `drop-zone setup`. Safe to edit by hand; it holds no secrets.\n"
        << "# The private password is never stored -- it only unlocks identity.key. The\n"
        << "# public password is sealed inside identity.key, not written here, so reading\n"
        << "# this file is not enough to receive files as this user.\n"
        << "\n"
        << "[identity]\n"
        << "username = \"" << config.username << "\"\n"
        << "# Random per installation, so the same password on two machines does not\n"
        << "# produce the same key for identity.key.\n"
        << "keystore_salt = \"" << to_hex(config.keystore_salt, kKeystoreSaltSize) << "\"\n"
        << "\n"
        << "[server]\n"
        << "# The rendezvous server only introduces peers; files never pass through it\n"
        << "# unless neither side can open a direct path.\n"
        << "server_host = \"" << config.server_host << "\"\n"
        << "server_port = " << config.server_port << "\n"
        << "\n"
        << "[transfers]\n"
        << "# Where received files go when `drop-zone accept` is given no -o. Empty (the\n"
        << "# setup default) means whichever directory the command was run from. Change\n"
        << "# this with `drop-zone set-output DIR`, or override it for one run with -o.\n"
        << "output_directory = \"" << config.default_output_directory << "\"\n"
        << "# Encrypt file contents end to end. Turn it off only on a network you trust:\n"
        << "# the handshake stays encrypted either way, but the file bytes would not be.\n"
        << "encrypt = " << (config.encrypt_by_default ? "true" : "false") << "\n"
        << "# Hash every file and compare. Costs an extra read pass on both sides and adds\n"
        << "# nothing when encryption is on, which is why it is off by default.\n"
        << "verify_digests = " << (config.verify_digests ? "true" : "false") << "\n"
        << "# Ask before accepting each transfer. Set to false for an unattended receiver.\n"
        << "prompt_before_accepting = " << (config.prompt_before_accepting ? "true" : "false")
        << "\n";

    write_private_file(config.config_path(), out.str());
}

}  // namespace dz::client
