// drop-zone: the terminal file-transfer client.
//
// This is the program a user installs. Each subcommand is one function below, and
// the shape of them is deliberately flat: parse, load configuration, unlock the
// identity, connect, do the thing.

#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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

    // The official public server unless setup was given --server, which writes
    // that host into the config. Change it later with `drop-zone set-server`.
    if (!args.server_host.empty()) {
        config.server_host = args.server_host;
        config.server_port = args.server_port != 0 ? args.server_port : kDefaultServerPort;
    } else {
        config.server_host = kDefaultServerHost;
        config.server_port = kDefaultServerPort;
    }

    // Received files land in the directory `accept` is run from unless the user
    // later runs `drop-zone set-output` or passes `-o` for a single run.
    config.default_output_directory = "";

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
        create_identity(config, std::string_view(private_password.data(), private_password.size()),
                        std::string_view(public_password.data(), public_password.size()));

    std::fprintf(stderr,
                 "\nDone.\n"
                 "\n"
                 "  username:    %s\n"
                 "  server:      %s:%u\n"
                 "  fingerprint: %s\n"
                 "  config:      %s\n"
                 "\n"
                 "Give people your username and your public password. Your fingerprint is\n"
                 "how they can confirm it is really you -- read it out to them once and\n"
                 "drop-zone will check it on every transfer from then on.\n"
                 "\n"
                 "Now run `drop-zone accept` to start receiving. Files land in the directory\n"
                 "you run that from; change the default with `drop-zone set-output DIR`, or\n"
                 "pass `-o DIR` on a single accept. The public password is remembered from\n"
                 "setup; change it with `drop-zone set-public-password`, or pass `-p` on a\n"
                 "single accept. To use a different rendezvous server later, run\n"
                 "`drop-zone set-server HOST[:PORT]`.\n",
                 config.username.c_str(), config.server_host.c_str(),
                 static_cast<unsigned>(config.server_port), identity.fingerprint().c_str(),
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
                                                    ? "./ (wherever you run the command)"
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
// set-server
// ---------------------------------------------------------------------------

int command_set_server(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    config.server_host = args.server_host;
    config.server_port = args.server_port != 0 ? args.server_port : kDefaultServerPort;
    save_config(config);

    std::fprintf(stderr, "Rendezvous server is now %s:%u\n", config.server_host.c_str(),
                 static_cast<unsigned>(config.server_port));
    return 0;
}

// ---------------------------------------------------------------------------
// set-output
// ---------------------------------------------------------------------------

/// Empty, `.` and `./` all mean "the directory accept is run from". Anything
/// else is stored as an absolute path so the default does not silently follow
/// later working-directory changes.
std::string resolve_configured_output_directory(const std::string& requested) {
    std::string path = expand_user_path(requested);
    if (path.empty() || path == "." || path == "./") return "";
    if (path.front() == '/') return path;
    return join_path(current_directory(), path);
}

int command_set_output(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    config.default_output_directory = resolve_configured_output_directory(args.output_directory);
    save_config(config);

    if (config.default_output_directory.empty()) {
        std::fprintf(stderr, "Received files will now be saved in ./ (the directory you run "
                             "`accept` from)\n");
    } else {
        std::fprintf(stderr, "Received files will now be saved in %s\n",
                     config.default_output_directory.c_str());
    }
    return 0;
}

// ---------------------------------------------------------------------------
// set-public-password
// ---------------------------------------------------------------------------

int command_set_public_password(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    SecretString private_password = read_password("Private password: ");
    Identity identity = unlock_identity(
        config, std::string_view(private_password.data(), private_password.size()));

    SecretString public_password =
        read_password_twice("New public password (what senders will need): ",
                            "Confirm public password: ");

    if (public_password.size() < 12) {
        std::fprintf(stderr,
                     "\nNote: that public password is short. Anybody who intercepts one of\n"
                     "your transfers can attack it offline, so a longer passphrase is worth\n"
                     "the extra typing.\n");
    }

    identity.public_password = std::move(public_password);
    save_identity(config, identity,
                  std::string_view(private_password.data(), private_password.size()));

    std::fprintf(stderr, "Public password updated. Tell senders the new one.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

/// One member of a group fan-out: its own control connection and sockets, so
/// the transfers really run at once rather than queueing on one pairing.
int send_to_one(const Config& config, const Identity& identity, const Manifest& manifest,
                const CommandLine& args, KnownPeers& known_peers, const std::string& target,
                std::string_view public_password, const std::string& group_name) {
    ControlConnection control(config, args.server_host, args.server_port);
    LocalSockets sockets = prepare_sockets(control.server_endpoint());
    X25519KeyPair session_keys = x25519_generate();

    control.say_hello(ClientRole::Sender, config.username, identity, session_keys.public_key,
                      sockets);

    Introduction introduction = request_introduction(
        control, config, identity, session_keys, target, public_password, args.force_transport,
        known_peers, group_name);

    TransportRequest request;
    request.is_sender = true;
    request.peer_candidates = introduction.peer_candidates;
    request.handshake_key = introduction.keys.handshake_key;
    request.forced = introduction.transport_hint;
    request.control = &control.stream();
    request.pairing_id = introduction.pairing_id;

    ChannelPtr channel = establish_channel(sockets, request);
    log::info(std::string("connected to ") + target + ": " + channel->describe());

    SendOptions options;
    options.encrypt = args.encrypt_set ? args.encrypt : config.encrypt_by_default;
    options.compute_digests = args.verify_set ? args.verify : config.verify_digests;
    options.quiet = args.quiet;

    SendResult result =
        send_transfer(*channel, manifest, introduction.keys, config.username, options);

    channel->close_gracefully();
    control.say_goodbye();

    if (!args.quiet && !result.output_directory.empty()) {
        std::fprintf(stderr, "saved on %s in %s\n", target.c_str(),
                     result.output_directory.c_str());
    }
    return 0;
}

int command_send(const CommandLine& args) {
    Config config = load_config(resolve_config_directory(args));

    // Built before anything is unlocked or connected, so a typo in a filename
    // fails immediately instead of after a password prompt and a round trip.
    Manifest manifest = build_manifest(args.inputs);

    const bool group_send = !args.group.empty();
    if (!args.quiet) {
        if (group_send) {
            std::fprintf(stderr, "sending %s (%s across %zu file%s) to group %s\n",
                         manifest.display_name.c_str(), format_bytes(manifest.total_bytes).c_str(),
                         manifest.files.size(), manifest.files.size() == 1 ? "" : "s",
                         args.group.c_str());
        } else {
            std::fprintf(stderr, "sending %s (%s across %zu file%s) to %s\n",
                         manifest.display_name.c_str(), format_bytes(manifest.total_bytes).c_str(),
                         manifest.files.size(), manifest.files.size() == 1 ? "" : "s",
                         args.target.c_str());
        }
    }

    SecretString private_password = read_password("Your private password: ");
    Identity identity = unlock_identity(
        config, std::string_view(private_password.data(), private_password.size()));

    // Prompted rather than required on the command line, so it stays out of shell
    // history and out of the process list.
    SecretString public_password;
    if (args.public_password.empty()) {
        std::string prompt = group_send ? (args.group + "'s group password: ")
                                        : (args.target + "'s public password: ");
        public_password = read_password(prompt);
    } else {
        public_password.assign(args.public_password.begin(), args.public_password.end());
    }

    KnownPeers known_peers(config.known_peers_path());
    known_peers.load();

    if (!group_send) {
        return send_to_one(config, identity, manifest, args, known_peers, args.target,
                           std::string_view(public_password.data(), public_password.size()),
                           /*group_name=*/"");
    }

    // Fetch the current idle roster on a short-lived sender connection, then
    // fan out one full 1:1 transfer per member in parallel.
    std::vector<std::string> roster;
    {
        ControlConnection control(config, args.server_host, args.server_port);
        LocalSockets sockets = prepare_sockets(control.server_endpoint());
        X25519KeyPair session_keys = x25519_generate();
        control.say_hello(ClientRole::Sender, config.username, identity, session_keys.public_key,
                          sockets);
        GroupRoster members = request_group_roster(control, args.group);
        roster = std::move(members.usernames);
        control.say_goodbye();
    }

    if (roster.empty()) {
        fail_user("nobody in group '" + args.group + "' is accepting files right now");
    }

    if (!args.quiet) {
        std::fprintf(stderr, "group %s has %zu member%s accepting:\n", args.group.c_str(),
                     roster.size(), roster.size() == 1 ? "" : "s");
        for (const std::string& member : roster) {
            std::fprintf(stderr, "  %s\n", member.c_str());
        }
    }

    std::vector<std::thread> workers;
    std::vector<std::string> errors(roster.size());
    std::atomic<std::size_t> failures{0};

    workers.reserve(roster.size());
    for (std::size_t i = 0; i < roster.size(); ++i) {
        workers.emplace_back([&, i]() {
            try {
                send_to_one(config, identity, manifest, args, known_peers, roster[i],
                            std::string_view(public_password.data(), public_password.size()),
                            args.group);
            } catch (const std::exception& error) {
                errors[i] = error.what();
                failures.fetch_add(1);
            }
        });
    }

    for (std::thread& worker : workers) worker.join();

    for (std::size_t i = 0; i < roster.size(); ++i) {
        if (errors[i].empty()) continue;
        std::fprintf(stderr, "failed for %s: %s\n", roster[i].c_str(), errors[i].c_str());
    }

    if (failures.load() != 0) {
        fail_user("group send finished with " + std::to_string(failures.load()) + " failure" +
                  (failures.load() == 1 ? "" : "s") + " out of " + std::to_string(roster.size()));
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

    SecretString public_password;
    if (!args.public_password.empty()) {
        public_password.assign(args.public_password.begin(), args.public_password.end());
    } else if (!identity.public_password.empty()) {
        public_password = identity.public_password;
    } else {
        // v1 keystore, or setup ran before public passwords were stored.
        public_password = read_password("Your public password (what senders will need): ");
        identity.public_password = public_password;
        save_identity(config, identity,
                      std::string_view(private_password.data(), private_password.size()));
    }

    // Stretched once here, not per incoming request. scrypt takes about a tenth of
    // a second, so doing it per request would let anybody pin this machine's CPU
    // just by asking to send repeatedly.
    Key personal_password_key = derive_public_password_key(
        std::string_view(public_password.data(), public_password.size()), config.username);

    std::string output_directory = args.output_directory.empty()
                                       ? config.default_output_directory
                                       : expand_user_path(args.output_directory);
    if (output_directory.empty()) output_directory = current_directory();
    make_directories(output_directory);

    KnownPeers known_peers(config.known_peers_path());
    known_peers.load();

    if (!args.quiet) {
        std::fprintf(stderr, "accepting as %s, saving into %s\n", config.username.c_str(),
                     output_directory.c_str());
        std::fprintf(stderr, "fingerprint %s\n", identity.fingerprint().c_str());
    }

    // The group password key is derived on the first successful join and reused
    // after a relay forces a reconnect.
    std::unique_ptr<Key> group_password_key;
    SecretString cached_group_password;
    bool group_password_known = false;

    for (;;) {
        ControlConnection control(config, args.server_host, args.server_port);
        bool announced = false;
        bool need_reconnect = false;

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

                if (!args.group.empty()) {
                    if (!group_password_known) {
                        GroupStatus status = query_group(control, args.group);
                        if (!status.exists) {
                            cached_group_password = public_password;
                            if (!args.quiet) {
                                std::fprintf(stderr,
                                             "creating group %s; its password is your public "
                                             "password\n",
                                             args.group.c_str());
                            }
                        } else {
                            cached_group_password =
                                read_password("Group " + args.group + "'s password: ");
                        }
                        group_password_key = std::make_unique<Key>(derive_public_password_key(
                            std::string_view(cached_group_password.data(),
                                             cached_group_password.size()),
                            args.group));
                        group_password_known = true;
                    }

                    GroupResult result = join_group(control, args.group, *group_password_key);
                    switch (result.outcome) {
                        case GroupJoinOutcome::Created:
                        case GroupJoinOutcome::Joined:
                        case GroupJoinOutcome::AlreadyMember:
                            if (!args.quiet) {
                                std::fprintf(stderr, "%s (%u member%s)\n", result.message.c_str(),
                                             result.member_count,
                                             result.member_count == 1 ? "" : "s");
                            }
                            break;
                        case GroupJoinOutcome::WrongPassword:
                            fail_user("wrong password for group '" + args.group + "'");
                        case GroupJoinOutcome::Full:
                            fail_user("group '" + args.group + "' is full");
                        case GroupJoinOutcome::InvalidName:
                            fail_user("'" + args.group + "' is not a usable group name");
                    }
                }

                announced = true;
            }

            Introduction introduction;
            if (!await_introduction(control, config, identity, session_keys, personal_password_key,
                                    group_password_key.get(), args.group, args.force_transport,
                                    known_peers, /*timeout_ms=*/0, introduction)) {
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
            log::info(std::string("connected: ") + channel->describe());

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

            if (args.once) {
                control.say_goodbye();
                return 0;
            }

            // Always reconnect after a transfer. The relay tier consumes the
            // control connection; a direct TCP/UDP transfer leaves the pairing
            // live on the server until the sender hangs up, which used to inject
            // a RelayClose that the next say_hello then misread as a protocol
            // error. A fresh control connection avoids both.
            log::info("reconnect after transfer (" + std::string(channel->describe()) + ")");
            need_reconnect = true;
            break;
        }

        control.say_goodbye();
        if (!need_reconnect) return 0;
    }
}

int run(int argc, char* argv[]) {
    CommandLine args = parse_command_line(argc, argv);

    if (!args.log_level.empty()) {
        log::Level level;
        if (!log::parse_level(args.log_level, level)) print_help("unknown log level");
        log::set_level(level);
    } else if (args.quiet) {
        log::set_level(log::Level::Error);
    } else if (args.verbose) {
        // Debug includes the per-candidate TCP/UDP probes as well as the
        // high-level "trying TCP" lines at Info.
        log::set_level(log::Level::Debug);
    } else {
        // Warn still reports password failures, skipped files, and errors.
        // Transport-ladder chatter stays off until -v or --log-level.
        log::set_level(log::Level::Warn);
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
        case Command::SetServer: return command_set_server(args);
        case Command::SetOutput: return command_set_output(args);
        case Command::SetPublicPassword: return command_set_public_password(args);
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
