#include "dz/client/known_peers.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/protocol.hpp"
#include "dz/secure.hpp"
#include "dz/socket.hpp"

namespace dz::client {

KnownPeers::KnownPeers(std::string path) : path_(std::move(path)) {}

void KnownPeers::load() {
    peers_.clear();

    std::ifstream input(path_);
    if (!input) return;  // No peers recorded yet.

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream fields(line);
        std::string username;
        std::string key_hex;
        std::uint64_t first_seen = 0;

        if (!(fields >> username >> key_hex)) continue;
        fields >> first_seen;  // Optional; older files may not have it.

        if (!is_valid_username(username)) continue;

        std::vector<std::uint8_t> key;
        if (!from_hex(key_hex, key) || key.size() != kEd25519PublicKeySize) continue;

        KnownPeer peer;
        peer.username = username;
        std::memcpy(peer.identity_key, key.data(), key.size());
        peer.first_seen = first_seen;
        peers_.push_back(peer);
    }
}

const KnownPeer* KnownPeers::find(const std::string& username) const {
    for (const KnownPeer& peer : peers_) {
        if (peer.username == username) return &peer;
    }
    return nullptr;
}

PinResult KnownPeers::check(const std::string& username,
                            const std::uint8_t identity_key[kEd25519PublicKeySize]) const {
    const KnownPeer* peer = find(username);
    if (peer == nullptr) return PinResult::FirstSight;

    // Constant-time even though the recorded key is public: it costs nothing and
    // keeps the habit uniform, so a later comparison of something secret is not
    // written the wrong way by analogy with this one.
    if (constant_time_equal(peer->identity_key, identity_key, kEd25519PublicKeySize)) {
        return PinResult::Matches;
    }
    return PinResult::Changed;
}

void KnownPeers::remember(const std::string& username,
                          const std::uint8_t identity_key[kEd25519PublicKeySize]) {
    for (KnownPeer& peer : peers_) {
        if (peer.username == username) {
            std::memcpy(peer.identity_key, identity_key, kEd25519PublicKeySize);
            save();
            return;
        }
    }

    KnownPeer peer;
    peer.username = username;
    std::memcpy(peer.identity_key, identity_key, kEd25519PublicKeySize);
    peer.first_seen = static_cast<std::uint64_t>(std::time(nullptr));
    peers_.push_back(peer);
    save();
}

void KnownPeers::save() const {
    std::ostringstream out;
    out << "# drop-zone known peers.\n"
        << "# One line per peer: username, Ed25519 identity key, and when it was first\n"
        << "# seen. Delete a line to forget a peer -- the next transfer will then treat\n"
        << "# them as new. A key that changes unexpectedly means either the peer\n"
        << "# reinstalled or somebody else has taken their username.\n";

    for (const KnownPeer& peer : peers_) {
        out << peer.username << " " << to_hex(peer.identity_key, kEd25519PublicKeySize) << " "
            << peer.first_seen << "\n";
    }

    std::string contents = out.str();
    std::string temporary = path_ + ".tmp";

    make_directories(parent_path(path_));

    int raw = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (raw < 0) fail_errno("cannot create '" + temporary + "'");

    Fd fd(raw);
    write_file_all(fd.get(), contents.data(), contents.size());
    fd.reset();

    if (::rename(temporary.c_str(), path_.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        fail_errno("cannot move '" + temporary + "' into place");
    }
}

}  // namespace dz::client
