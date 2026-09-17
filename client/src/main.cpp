// drop-zone: the terminal file-transfer client.
//
// This is the program a user installs. Each subcommand is one function below, and
// the shape of them is deliberately flat: parse, load configuration, unlock the
// identity, connect, do the thing.

#include <unistd.h>

#include <cstdio>
#include <exception>
#include <string>

#include "dz/client/cli.hpp"
#include "dz/client/config.hpp"
#include "dz/client/identity.hpp"
#include "dz/client/known_peers.hpp"
#include "dz/client/manifest.hpp"
#include "dz/client/rendezvous.hpp"
#include "dz/client/transfer.hpp"
#include "dz/client/transport.hpp"
#include "dz/cpu.hpp"
#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/log.hpp"
#include "dz/protocol.hpp"

namespace dz::client {
namespace {

/// Include loopback addresses in the candidate list.
///
/// Normally pointless -- a peer cannot reach our 127.0.0.1 -- but it is exactly
/// what lets two clients on one machine find each other, which is how the
/// end-to-end test exercises the direct path.
bool should_include_loopback() {
    const char* value = std::getenv("DROP_ZONE_ALLOW_LOOPBACK");
    return value != nullptr && *value != '\0' && std::string(value) != "0";
}

std::string resolve_config_directory(const CommandLine& args) {
    if (!args.config_directory.empty()) return expand_user_path(args.config_directory);
    return default_config_directory();
}

/// Prepare the sockets a peer must have open before it announces itself, and learn
/// this machine's external address.
LocalSockets prepare_sockets(const Endpoint& server_endpoint) {
    LocalSockets sockets = open_local_sockets(should_include_loopback());
    discover_reflexive_address(sockets, server_endpoint);
    return sockets;
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

int command_setup(const CommandLine& args) {
    std::string directory = resolve_config_directory(args);

    bool already = config_exists(directory);
    if (already) {
        std::fprintf(stderr, "A drop-zone configuration already exists in %s\n",
                     directory.c_str());
        if (!read_yes_no("Replace it? This creates a new identity and peers will "
                         "notice. (y/n) ",
                         false)) {
            std::fprintf(stderr, "Left the existing configuration alone.\n");
            return 0;
        }
    }

    std::fprintf(stderr,
                 "\nSetting up drop-zone.\n"
                 "\n"
                 "You need three things:\n"
                 "  * a username, which is how people address files to you;\n"
                 "  * a private password, which stays on this machine and protects your\n"
                 "    identity key. It is never sent anywhere;\n"
                 "  * a public password, which you hand to anybody you want to be able to\n"
                 "    send you files. Choose it like a passphrase, not a PIN: it is the only\n"
                 "    thing stopping a stranger from sending to you, and the only thing that\n"
                 "    keeps the rendezvous server out of your transfers.\n"
                 "\n");

    Config config;
    config.directory = directory;

    for (;;) {
        config.username = read_line("Username: ", "");
        if (is_valid_username(config.username)) break;
        std::fprintf(stderr, "A username may only contain lowercase letters, digits, '-', '_' "
                             "and '.', and may not start with '.'.\n");
    }

    std::string server = read_line("Rendezvous server [drop-zone.example.net]: ",
                                   "drop-zone.example.net");
    std::uint16_t port = kDefaultServerPort;

    std::size_t colon = server.rfind(':');
    if (colon != std::string::npos && server.find(':') == colon) {
        std::string port_text = server.substr(colon + 1);
        server = server.substr(0, colon);
        port = static_cast<std::uint16_t>(std::strtoul(port_text.c_str(), nullptr, 10));
        if (port == 0) port = kDefaultServerPort;
    }

    config.server_host = server;
    config.server_port = port;

    std::string output = read_line("Save received files in [the current directory]: ", "");
    config.default_output_directory = output.empty() ? "" : expand_user_path(output);

    // Random per installation, so two people who pick the same private password do
    // not end up with the same key sealing their identity files.
    random_bytes(config.keystore_salt, kKeystoreSaltSize);

    SecretString private_password =
        read_password_twice("Private password (protects this machine's identity): ",
                            "Confirm private password: ");

    SecretString public_password =
        read_password_twice("Public password (what senders will need): ",
                            "Confirm public password: ");

    // Warn but do not refuse. The strength that matters is explained in
    // docs/SECURITY.md; refusing a short password would be paternalistic for
    // somebody using this on a home network.
    if (public_password.size() < 12) {
        std::fprintf(stderr,
                     "\nNote: that public password is short. Anybody who intercepts one of\n"
                     "your transfers can attack it offline, so a longer passphrase is worth\n"
                     "the extra typing.\n");
    }

    save_config(config);
    Identity identity =
        create_identity(config, std::string_view(private_password.data(), private_password.size()));

    std::fprintf(stderr,
                 "\nDone.\n"
                 "\n"
                 "  username:    %s\n"
                 "  fingerprint: %s\n"
                 "  config:      %s\n"
                 "\n"
                 "Give people your username and your public password. Your fingerprint is\n"
                 "how they can confirm it is really you -- read it out to them once and\n"
                 "drop-zone will check it on every transfer from then on.\n"
                 "\n"
                 "Now run `drop-zone accept` to start receiving.\n",
                 config.username.c_str(), identity.fingerprint().c_str(),
                 config.config_path().c_str());

    return 0;
}

// ---------------------------------------------------------------------------
// whoami and status
// ---------------------------------------------------------------------------

int command_whoami(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    if (!identity_exists(config)) {
        fail_user("no identity found in " + config.directory + ". Run `drop-zone setup`.");
    }

    // The fingerprint comes from the public key, which is recomputed from the
    // private one -- so this needs the private password even though it prints
    // nothing secret.
    SecretString password = read_password("Private password: ");
    Identity identity =
        unlock_identity(config, std::string_view(password.data(), password.size()));

    std::printf("%s\n", config.username.c_str());
    std::printf("fingerprint %s\n", identity.fingerprint().c_str());
    return 0;
}

int command_status(const CommandLine& args) {
    std::string directory = resolve_config_directory(args);

    std::printf("drop-zone %s\n\n", DZ_VERSION_STRING);

    std::printf("This machine\n");
    std::printf("  cipher instructions   %s\n", cpu_features_summary().c_str());
    std::printf("  preferred cipher      %s\n", aead_algorithm_name(preferred_aead()));
    std::printf("  encryption workers    %u\n", hardware_threads());
    std::printf("  zero-copy send        %s\n", sendfile_supported() ? "available" : "unavailable");
    std::printf("  chunk size            %s\n", format_bytes(kDefaultChunkSize).c_str());

    if (!config_exists(directory)) {
        std::printf("\nNo configuration in %s. Run `drop-zone setup`.\n", directory.c_str());
        return 0;
    }

    Config config = load_config(directory);

    std::printf("\nConfiguration (%s)\n", config.config_path().c_str());
    std::printf("  username              %s\n", config.username.c_str());
    std::printf("  server                %s:%u\n", config.server_host.c_str(),
                static_cast<unsigned>(config.server_port));
    std::printf("  output directory      %s\n", config.default_output_directory.empty()
                                                    ? "(wherever you run the command)"
                                                    : config.default_output_directory.c_str());
    std::printf("  encrypt by default    %s\n", config.encrypt_by_default ? "yes" : "no");
    std::printf("  verify digests        %s\n", config.verify_digests ? "yes" : "no");
    std::printf("  identity              %s\n",
                identity_exists(config) ? "present" : "MISSING -- run setup");

    KnownPeers known_peers(config.known_peers_path());
    known_peers.load();

    std::printf("\nKnown peers (%zu)\n", known_peers.peers().size());
    for (const KnownPeer& peer : known_peers.peers()) {
        std::printf("  %-20s %s\n", peer.username.c_str(),
                    fingerprint_of(peer.identity_key).c_str());
    }

    return 0;
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

int command_send(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    // Built before anything is unlocked or connected, so a typo in a filename
    // fails immediately instead of after a password prompt and a round trip.
    Manifest manifest = build_manifest(args.inputs);

    if (!args.quiet) {
        std::fprintf(stderr, "sending %s (%s across %zu file%s) to %s\n",
                     manifest.display_name.c_str(), format_bytes(manifest.total_bytes).c_str(),
                     manifest.files.size(), manifest.files.size() == 1 ? "" : "s",
                     args.target.c_str());
    }

    SecretString private_password = read_password("Your private password: ");
    Identity identity = unlock_identity(
        config, std::string_view(private_password.data(), private_password.size()));

    // Prompted rather than required on the command line, so it stays out of shell
    // history and out of the process list.
    SecretString public_password;
    if (args.public_password.empty()) {
        public_password = read_password(args.target + "'s public password: ");
    } else {
        public_password.assign(args.public_password.begin(), args.public_password.end());
    }

    KnownPeers known_peers(config.known_peers_path());
    known_peers.load();

    ControlConnection control(config, args.server_host, args.server_port);
    LocalSockets sockets = prepare_sockets(control.server_endpoint());

    // A fresh key pair per transfer, so recovering one session's keys later reveals
    // nothing about any other.
    X25519KeyPair session_keys = x25519_generate();

    control.say_hello(ClientRole::Sender, config.username, identity, session_keys.public_key,
                      sockets);

    Introduction introduction = request_introduction(
        control, config, identity, session_keys, args.target,
        std::string_view(public_password.data(), public_password.size()), args.force_transport,
        known_peers);

    TransportRequest request;
    request.is_sender = true;
    request.peer_candidates = introduction.peer_candidates;
    request.handshake_key = introduction.keys.handshake_key;
    request.forced = introduction.transport_hint;
    request.control = &control.stream();
    request.pairing_id = introduction.pairing_id;

    ChannelPtr channel = establish_channel(sockets, request);
    if (!args.quiet) std::fprintf(stderr, "connected: %s\n", channel->describe().c_str());

    SendOptions options;
    options.encrypt = args.encrypt_set ? args.encrypt : config.encrypt_by_default;
    options.compute_digests = args.verify_set ? args.verify : config.verify_digests;
    options.quiet = args.quiet;

    SendResult result =
        send_transfer(*channel, manifest, introduction.keys, config.username, options);

    channel->close_gracefully();
    control.say_goodbye();

    if (!args.quiet && !result.output_directory.empty()) {
        std::fprintf(stderr, "saved on %s in %s\n", args.target.c_str(),
                     result.output_directory.c_str());
    }
    return 0;
}

// ---------------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------------

int command_accept(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    SecretString private_password = read_password("Your private password: ");
    Identity identity = unlock_identity(
        config, std::string_view(private_password.data(), private_password.size()));

    SecretString public_password =
        read_password("Your public password (what senders will need): ");

    // Stretched once here, not per incoming request. scrypt takes about a tenth of
    // a second, so doing it per request would let anybody pin this machine's CPU
    // just by asking to send repeatedly.
    Key password_key = derive_public_password_key(
        std::string_view(public_password.data(), public_password.size()), config.username);

    std::string output_directory = args.output_directory.empty()
                                       ? config.default_output_directory
                                       : expand_user_path(args.output_directory);
    if (output_directory.empty()) output_directory = current_directory();
    make_directories(output_directory);

    KnownPeers known_peers(config.known_peers_path());
    known_peers.load();

    ControlConnection control(config, args.server_host, args.server_port);

    if (!args.quiet) {
        std::fprintf(stderr, "accepting as %s, saving into %s\n", config.username.c_str(),
                     output_directory.c_str());
        std::fprintf(stderr, "fingerprint %s\n", identity.fingerprint().c_str());
    }

    bool announced = false;

    for (;;) {
        // Fresh sockets and a fresh ephemeral key for each transfer: the previous
        // transfer consumed the UDP socket if it used the punched path, and a new
        // key pair keeps sessions independent of each other.
        LocalSockets sockets = prepare_sockets(control.server_endpoint());
        X25519KeyPair session_keys = x25519_generate();

        ServerHello hello = control.say_hello(ClientRole::Receiver, config.username, identity,
                                              session_keys.public_key, sockets);
        if (!announced) {
            if (!args.quiet) std::fprintf(stderr, "%s\n", hello.message.c_str());
            announced = true;
        }

        Introduction introduction;
        if (!await_introduction(control, config, identity, session_keys, password_key,
                                args.force_transport, known_peers, /*timeout_ms=*/0,
                                introduction)) {
            break;
        }

        TransportRequest request;
        request.is_sender = false;
        request.peer_candidates = introduction.peer_candidates;
        request.handshake_key = introduction.keys.handshake_key;
        request.forced = introduction.transport_hint;
        request.control = &control.stream();
        request.pairing_id = introduction.pairing_id;

        ChannelPtr channel = establish_channel(sockets, request);
        if (!args.quiet) std::fprintf(stderr, "connected: %s\n", channel->describe().c_str());

        ReceiveOptions options;
        options.output_directory = output_directory;
        options.prompt = !args.assume_yes && config.prompt_before_accepting;
        options.verify_digests = args.verify_set ? args.verify : config.verify_digests;
        options.quiet = args.quiet;

        ReceiveResult result = receive_transfer(*channel, introduction.keys,
                                                introduction.peer_username, options);

        channel->close_gracefully();

        if (!result.accepted && !args.quiet) {
            std::fprintf(stderr, "declined the transfer from %s\n",
                         introduction.peer_username.c_str());
        }

        if (args.once) break;

        // The relay tier tunnels through the control connection, so once a transfer
        // has used it that connection is no longer usable for anything else.
        if (channel->kind() == TransportKind::ServerRelay) {
            if (!args.quiet) {
                std::fprintf(stderr, "that transfer used the relay, so reconnecting\n");
            }
            break;
        }
    }

    control.say_goodbye();
    return 0;
}

int run(int argc, char* argv[]) {
    CommandLine args = parse_command_line(argc, argv);

    if (!args.log_level.empty()) {
        log::Level level;
        if (!log::parse_level(args.log_level, level)) print_help("unknown log level");
        log::set_level(level);
    } else if (args.quiet) {
        log::set_level(log::Level::Error);
    }

    // A peer disappearing mid-transfer should surface as an error from write(),
    // not as a signal that kills the process without a message.
    ignore_sigpipe();

    switch (args.command) {
        case Command::Setup: return command_setup(args);
        case Command::Accept: return command_accept(args);
        case Command::Send: return command_send(args);
        case Command::WhoAmI: return command_whoami(args);
        case Command::Status: return command_status(args);
        case Command::Version:
            std::printf("drop-zone %s\n", DZ_VERSION_STRING);
            return 0;
        case Command::Help:
            print_help(nullptr);
        case Command::None:
            print_help("no command given");
    }
    return 1;
}

}  // namespace
}  // namespace dz::client

int main(int argc, char* argv[]) {
    try {
        return dz::client::run(argc, argv);
    } catch (const dz::UserError& error) {
        // Something the user can act on, so it is reported plainly with no
        // suggestion that drop-zone itself went wrong.
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "drop-zone: %s\n", error.what());
        return 1;
    }
}
