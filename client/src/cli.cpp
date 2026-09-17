#include "dz/client/cli.hpp"

#include <getopt.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "dz/error.hpp"

namespace dz::client {
namespace {

/// Long-only options, numbered above every short option's character value.
enum LongOnly {
    kNoEncrypt = 1000,
    kEncrypt,
    kVerify,
    kNoVerify,
    kOnce,
    kServer,
    kForceTransport,
    kConfigDir,
    kLogLevel,
};

Command parse_command(const char* text) {
    if (std::strcmp(text, "setup") == 0) return Command::Setup;
    if (std::strcmp(text, "accept") == 0) return Command::Accept;
    if (std::strcmp(text, "receive") == 0) return Command::Accept;
    if (std::strcmp(text, "send") == 0) return Command::Send;
    if (std::strcmp(text, "whoami") == 0) return Command::WhoAmI;
    if (std::strcmp(text, "status") == 0) return Command::Status;
    if (std::strcmp(text, "set-server") == 0) return Command::SetServer;
    if (std::strcmp(text, "help") == 0) return Command::Help;
    if (std::strcmp(text, "version") == 0) return Command::Version;
    return Command::None;
}

/// Split "host:port" or a bare host. A bare host leaves the port at 0, meaning
/// "whatever the configuration says".
void parse_server(const char* text, std::string& host, std::uint16_t& port) {
    std::string value(text);

    std::size_t colon = value.rfind(':');
    // More than one colon means a bare IPv6 literal, which has no port here.
    bool has_port = colon != std::string::npos &&
                    value.find(':') == colon;

    if (!has_port) {
        host = value;
        return;
    }

    host = value.substr(0, colon);
    std::string port_text = value.substr(colon + 1);

    char* end = nullptr;
    unsigned long parsed = std::strtoul(port_text.c_str(), &end, 10);
    if (end == port_text.c_str() || *end != '\0' || parsed == 0 || parsed > 65535) {
        print_help("--server needs HOST or HOST:PORT");
    }
    port = static_cast<std::uint16_t>(parsed);
}

}  // namespace

void print_help(const char* error) {
    FILE* stream = (error != nullptr) ? stderr : stdout;
    if (error != nullptr) std::fprintf(stream, "Error: %s\n\n", error);

    std::fprintf(stream,
        "Usage: drop-zone COMMAND [OPTION]...\n"
        "Send files straight to another person's terminal, wherever they are.\n"
        "\n"
        "Commands:\n"
        "  setup                    choose a username and passwords, and create an\n"
        "                           identity for this machine.\n"
        "  accept                   wait for incoming files and save them.\n"
        "  send FILE... -t USER     send files or directories to USER.\n"
        "  whoami                   print this machine's username and fingerprint.\n"
        "  status                   print the configuration and what this build can do.\n"
        "  set-server HOST[:PORT]   permanently change the rendezvous server.\n"
        "\n"
        "Send options:\n"
        "  -t, --target=USER        username to send to.\n"
        "  -p, --password=PASSWORD  USER's public password. Omit it and drop-zone will\n"
        "                           ask, which keeps it out of your shell history.\n"
        "\n"
        "Accept options:\n"
        "  -o, --output=DIR         directory to save files in (default: the directory\n"
        "                           you ran the command from).\n"
        "  -y, --yes                accept every transfer without asking.\n"
        "      --once               accept one transfer, then exit.\n"
        "\n"
        "Options for either mode:\n"
        "      --no-encrypt         send file contents unencrypted. Slightly faster on a\n"
        "                           network you trust; refused when the transfer would\n"
        "                           have to go through the server.\n"
        "      --encrypt            encrypt file contents (the default).\n"
        "      --verify             hash every file and compare. Costs an extra read pass\n"
        "                           on both sides.\n"
        "      --server=HOST[:PORT] use a different rendezvous server for this run.\n"
        "                           During setup, this is written into the config.\n"
        "      --force-transport=T  insist on one path: tcp, udp or relay. Without this,\n"
        "                           drop-zone tries all three in that order.\n"
        "      --config-dir=DIR     use a different configuration directory.\n"
        "  -v, --verbose            show transport attempts and connection details.\n"
        "  -q, --quiet              only report problems.\n"
        "      --log-level=LEVEL    error, warn, info or debug.\n"
        "  -h, --help               print this message.\n"
        "  -V, --version            print the version.\n"
        "\n"
        "Files go directly between the two machines. The rendezvous server introduces\n"
        "you to each other and nothing more: it never sees your passwords, your\n"
        "filenames or your file contents, and it keeps no record of either of you.\n"
        "\n"
        "Examples:\n"
        "  drop-zone setup\n"
        "  drop-zone accept -o ~/Downloads\n"
        "  drop-zone send report.pdf -t alice\n"
        "  drop-zone send ./photos -t bob -p hunter2\n"
        "  drop-zone set-server 192.0.2.10\n");

    std::exit((error != nullptr) ? 1 : 0);
}

CommandLine parse_command_line(int argc, char* argv[]) {
    CommandLine parsed;

    if (argc < 2) print_help("no command given");

    // The first non-option argument is the command. Taking it before getopt runs
    // keeps `drop-zone send -t alice file` and `drop-zone send file -t alice`
    // both working.
    parsed.command = parse_command(argv[1]);
    int option_start = 2;

    if (parsed.command == Command::None) {
        // Allow a bare `drop-zone --help` or `--version` with no command.
        if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
            print_help(nullptr);
        }
        if (std::strcmp(argv[1], "-V") == 0 || std::strcmp(argv[1], "--version") == 0) {
            parsed.command = Command::Version;
            return parsed;
        }
        std::string message = std::string("unknown command '") + argv[1] + "'";
        print_help(message.c_str());
    }

    static const option long_options[] = {
        {"target", required_argument, nullptr, 't'},
        {"password", required_argument, nullptr, 'p'},
        {"output", required_argument, nullptr, 'o'},
        {"yes", no_argument, nullptr, 'y'},
        {"quiet", no_argument, nullptr, 'q'},
        {"verbose", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {"no-encrypt", no_argument, nullptr, kNoEncrypt},
        {"encrypt", no_argument, nullptr, kEncrypt},
        {"verify", no_argument, nullptr, kVerify},
        {"no-verify", no_argument, nullptr, kNoVerify},
        {"once", no_argument, nullptr, kOnce},
        {"server", required_argument, nullptr, kServer},
        {"force-transport", required_argument, nullptr, kForceTransport},
        {"config-dir", required_argument, nullptr, kConfigDir},
        {"log-level", required_argument, nullptr, kLogLevel},
        {nullptr, 0, nullptr, 0},
    };

    // getopt_long reads from argv starting at optind, so point it past the
    // command.
    optind = option_start;

    int opt;
    while ((opt = getopt_long(argc, argv, "t:p:o:yqvhV", long_options, nullptr)) != -1) {
        switch (opt) {
            case 't':
                parsed.target = optarg;
                break;
            case 'p':
                parsed.public_password = optarg;
                break;
            case 'o':
                parsed.output_directory = optarg;
                break;
            case 'y':
                parsed.assume_yes = true;
                break;
            case 'q':
                parsed.quiet = true;
                break;
            case 'v':
                parsed.verbose = true;
                break;
            case 'h':
                print_help(nullptr);
                break;
            case 'V':
                parsed.command = Command::Version;
                return parsed;
            case kNoEncrypt:
                parsed.encrypt = false;
                parsed.encrypt_set = true;
                break;
            case kEncrypt:
                parsed.encrypt = true;
                parsed.encrypt_set = true;
                break;
            case kVerify:
                parsed.verify = true;
                parsed.verify_set = true;
                break;
            case kNoVerify:
                parsed.verify = false;
                parsed.verify_set = true;
                break;
            case kOnce:
                parsed.once = true;
                break;
            case kServer:
                parse_server(optarg, parsed.server_host, parsed.server_port);
                break;
            case kForceTransport:
                if (!parse_transport_kind(optarg, parsed.force_transport)) {
                    print_help("--force-transport must be tcp, udp, relay or auto");
                }
                break;
            case kConfigDir:
                parsed.config_directory = optarg;
                break;
            case kLogLevel:
                parsed.log_level = optarg;
                break;
            default:
                print_help("unrecognised option");
                break;
        }
    }

    for (int i = optind; i < argc; ++i) parsed.inputs.emplace_back(argv[i]);

    // Per-command requirements. The prototype checked these too; the difference
    // is that a missing target is now impossible to confuse with a missing
    // output directory, because each command only looks at its own options.
    switch (parsed.command) {
        case Command::Send:
            if (parsed.inputs.empty()) print_help("say which file or directory to send");
            if (parsed.target.empty()) print_help("say who to send it to with --target");
            if (!is_valid_username(parsed.target)) {
                print_help("a username may only contain lowercase letters, digits, '-', '_' "
                           "and '.'");
            }
            break;

        case Command::Accept:
            if (!parsed.inputs.empty()) print_help("`accept` takes no file arguments");
            break;

        case Command::SetServer:
            if (parsed.inputs.size() != 1) {
                print_help("`set-server` needs HOST or HOST:PORT");
            }
            parse_server(parsed.inputs[0].c_str(), parsed.server_host, parsed.server_port);
            if (parsed.server_host.empty()) {
                print_help("`set-server` needs HOST or HOST:PORT");
            }
            break;

        default:
            break;
    }

    return parsed;
}

}  // namespace dz::client
