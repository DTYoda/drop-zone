// drop-zone-server: the rendezvous daemon.
//
// Deployed by whoever runs the service, not by the people using the client.
// server/deploy/ has a systemd unit and a Dockerfile.

#include <getopt.h>
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

#include "dz/cpu.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"
#include "dz/server/server.hpp"

namespace {

/// The running server, so the signal handler can ask it to stop. A handler may
/// only touch async-signal-safe state, so it sets a flag on this rather than
/// doing any work itself.
dz::server::Server* g_server = nullptr;
volatile sig_atomic_t g_stop_requested = 0;

void handle_signal(int) { g_stop_requested = 1; }

void print_help(const char* error) {
    FILE* stream = (error != nullptr) ? stderr : stdout;
    if (error != nullptr) std::fprintf(stream, "Error: %s\n\n", error);

    std::fprintf(stream,
                 "Usage: drop-zone-server [OPTION]...\n"
                 "Introduce drop-zone peers to each other without keeping anything.\n"
                 "\n"
                 "Options:\n"
                 "  -h, --help                  print this message.\n"
                 "  -V, --version               print the version.\n"
                 "  -b, --bind=ADDRESS          address to listen on (default '::', both "
                 "families).\n"
                 "  -p, --port=PORT             port to listen on (default %u).\n"
                 "  -s, --shards=N              event-loop threads (default: one per core).\n"
                 "      --idle-timeout=SECONDS  drop a silent connection after this long "
                 "(default 300).\n"
                 "      --pairing-timeout=SEC   abandon an unfinished introduction (default "
                 "120).\n"
                 "      --no-relay              refuse to forward data; require a direct path.\n"
                 "      --connections-per-min=N per-address connection limit (default 60).\n"
                 "      --requests-per-min=N    per-address introduction limit (default 20).\n"
                 "  -l, --log-level=LEVEL       error, warn, info or debug (default info).\n"
                 "\n"
                 "The server keeps no database and writes nothing to disk. A username is held\n"
                 "only while its owner is connected, addresses live only in the kernel's socket\n"
                 "state, and no log line ever names a peer. See docs/PROTOCOL.md.\n",
                 static_cast<unsigned>(dz::kDefaultServerPort));

    std::exit((error != nullptr) ? 1 : 0);
}

/// Parse a positive integer option, or fail with a message naming the flag.
unsigned long parse_number(const char* text, const char* flag) {
    char* end = nullptr;
    unsigned long value = std::strtoul(text, &end, 10);
    if (end == text || *end != '\0') {
        std::string message = std::string(flag) + " needs a number";
        print_help(message.c_str());
    }
    return value;
}

}  // namespace

int main(int argc, char* argv[]) {
    dz::server::ServerOptions options;

    // Timestamps on by default: a server may be running somewhere without
    // journald in front of it to add them.
    dz::log::set_timestamps(true);

    enum LongOnly {
        kIdleTimeout = 1000,
        kPairingTimeout,
        kNoRelay,
        kConnectionsPerMinute,
        kRequestsPerMinute,
    };

    static const option long_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {"bind", required_argument, nullptr, 'b'},
        {"port", required_argument, nullptr, 'p'},
        {"shards", required_argument, nullptr, 's'},
        {"log-level", required_argument, nullptr, 'l'},
        {"idle-timeout", required_argument, nullptr, kIdleTimeout},
        {"pairing-timeout", required_argument, nullptr, kPairingTimeout},
        {"no-relay", no_argument, nullptr, kNoRelay},
        {"connections-per-min", required_argument, nullptr, kConnectionsPerMinute},
        {"requests-per-min", required_argument, nullptr, kRequestsPerMinute},
        {nullptr, 0, nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hVb:p:s:l:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                print_help(nullptr);
                break;
            case 'V':
                std::printf("drop-zone-server %s\n", DZ_VERSION_STRING);
                return 0;
            case 'b':
                options.bind_address = optarg;
                break;
            case 'p':
                options.port = static_cast<std::uint16_t>(parse_number(optarg, "--port"));
                break;
            case 's':
                options.shards = static_cast<unsigned>(parse_number(optarg, "--shards"));
                break;
            case 'l': {
                dz::log::Level level;
                if (!dz::log::parse_level(optarg, level)) print_help("unknown log level");
                dz::log::set_level(level);
                break;
            }
            case kIdleTimeout:
                options.idle_timeout_seconds =
                    static_cast<std::uint32_t>(parse_number(optarg, "--idle-timeout"));
                break;
            case kPairingTimeout:
                options.pairing_timeout_seconds =
                    static_cast<std::uint32_t>(parse_number(optarg, "--pairing-timeout"));
                break;
            case kNoRelay:
                options.allow_relay = false;
                break;
            case kConnectionsPerMinute:
                options.rate_limits.connections_per_minute =
                    static_cast<double>(parse_number(optarg, "--connections-per-min"));
                break;
            case kRequestsPerMinute:
                options.rate_limits.requests_per_minute =
                    static_cast<double>(parse_number(optarg, "--requests-per-min"));
                break;
            default:
                print_help("unrecognised option");
                break;
        }
    }

    if (optind < argc) print_help("unexpected extra argument");

    try {
        dz::server::Server server(std::move(options));
        g_server = &server;

        struct sigaction action{};
        action.sa_handler = handle_signal;
        (void)::sigaction(SIGINT, &action, nullptr);
        (void)::sigaction(SIGTERM, &action, nullptr);

        server.start();
        dz::log::info(std::string("cipher acceleration available: ") + dz::cpu_features_summary());

        // A separate watcher turns the signal flag into a stop() call, because
        // stop() takes locks and allocates -- neither of which a signal handler
        // may do.
        std::thread watcher([&server] {
            while (g_stop_requested == 0) {
                struct timespec pause{0, 100'000'000};
                (void)::nanosleep(&pause, nullptr);
            }
            dz::log::info("shutting down");
            server.stop();
        });

        server.run_until_stopped();

        g_stop_requested = 1;
        watcher.join();
        g_server = nullptr;
        return 0;
    } catch (const std::exception& error) {
        dz::log::error(error.what());
        return 1;
    }
}
