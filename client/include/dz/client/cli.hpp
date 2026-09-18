// Command-line parsing for the client.
//
// Keeps the shape of the prototype's helpers.c: one struct carrying everything
// the command line said, one function that fills it in, and one hand-written
// help message. What changed is that the modes are now subcommands rather than
// mutually exclusive flags, because `drop-zone send file -t alice` reads better
// than `drop-zone -s -f file -t alice` and makes the "cannot be both a sender
// and an accepter" check structural instead of something to remember to write.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dz/protocol.hpp"

namespace dz::client {

enum class Command {
    None,
    Setup,      ///< Create or update the local configuration and identity.
    Accept,     ///< Wait for incoming transfers.
    Send,       ///< Send files to a username.
    WhoAmI,     ///< Print this installation's username and fingerprint.
    Status,     ///< Print the configuration and what this build can do.
    SetServer,          ///< Permanently change the rendezvous server in the config.
    SetOutput,          ///< Permanently change the default directory for received files.
    SetPublicPassword,  ///< Permanently change the public password senders use.
    Help,
    Version,
};

struct CommandLine {
    Command command = Command::None;

    /// Files or directories to send.
    std::vector<std::string> inputs;

    /// Username to send to. Empty when sending to a group instead.
    std::string target;

    /// Ephemeral group to join on accept, or to fan out to on send. Empty means
    /// personal-only. Mutually exclusive with `target` on send.
    std::string group;

    /// Public password from `-p`. On personal send this is the target's; on
    /// group send it is the group's. Empty prompts. On accept it overrides the
    /// stored public password for this run only; empty means use the one sealed
    /// at setup. For joining an existing group, the group password is prompted
    /// separately when needed.
    std::string public_password;

    /// Where received files go. Empty means the configured default, and failing
    /// that the current directory.
    std::string output_directory;

    /// Overrides for what the configuration says. Unset means "use the config".
    bool encrypt = true;
    bool encrypt_set = false;
    bool verify = false;
    bool verify_set = false;
    /// Accept every transfer without asking.
    bool assume_yes = false;

    /// Accept one transfer and exit, rather than staying up for more.
    bool once = false;

    /// Server override, for testing against a local server.
    std::string server_host;
    std::uint16_t server_port = 0;

    /// Skip the transport ladder and insist on one tier. Used by the end-to-end
    /// test to exercise the paths a loopback run would otherwise never reach.
    TransportKind force_transport = TransportKind::None;

    /// Configuration directory override, mainly so two clients can run on one
    /// machine during testing.
    std::string config_directory;

    std::string log_level;
    bool quiet = false;
    /// Show transport attempts and other connection details. Off by default so a
    /// normal run only reports problems, password failures, and accept/reject.
    bool verbose = false;
};

/// Print the help message and exit. A non-null `error` sends it to stderr with
/// the reason first and exits 1, matching the prototype's behaviour.
[[noreturn]] void print_help(const char* error);

CommandLine parse_command_line(int argc, char* argv[]);

}  // namespace dz::client
