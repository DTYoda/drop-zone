// Trust-on-first-use pinning of peer identity keys.
//
// The rendezvous server keeps no accounts, so it cannot tell you that the
// "alice" you are talking to is the alice you talked to last week -- a username
// belongs to whoever claims it while nobody else is holding it. This file closes
// that gap the way SSH does: the first time a peer is seen, its Ed25519 public
// key is written down against its username, and every later session checks the
// key it presents against that record.
//
// The pin is what makes the public password's job possible. Without it, someone
// who learned a public password could claim the username while its owner was
// offline. With it, they would also have to present the identity key the sender
// has already recorded.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dz/crypto.hpp"

namespace dz::client {

enum class PinResult {
    /// Never seen before; the caller should record it.
    FirstSight,
    /// Seen before with the same key.
    Matches,
    /// Seen before with a different key. Either the peer reinstalled, or somebody
    /// else has taken the username.
    Changed,
};

/// One recorded peer.
struct KnownPeer {
    std::string username;
    std::uint8_t identity_key[kEd25519PublicKeySize]{};
    /// Unix time the record was made, so `drop-zone status` can say how long a
    /// peer has been known.
    std::uint64_t first_seen = 0;
};

/// The known_peers file. Line-based and human-readable so that a user can
/// inspect and prune it with an editor, the same reasoning as SSH's
/// known_hosts.
class KnownPeers {
public:
    explicit KnownPeers(std::string path);

    /// Load the file. A missing file is not an error; it means no peer has been
    /// seen yet.
    void load();

    /// Compare `identity_key` against what is recorded for `username`.
    PinResult check(const std::string& username,
                    const std::uint8_t identity_key[kEd25519PublicKeySize]) const;

    /// Record a peer and write the file. Replaces any previous record.
    void remember(const std::string& username,
                  const std::uint8_t identity_key[kEd25519PublicKeySize]);

    /// The recorded key for `username`, or nullptr.
    const KnownPeer* find(const std::string& username) const;

    const std::vector<KnownPeer>& peers() const { return peers_; }

private:
    void save() const;

    std::string path_;
    std::vector<KnownPeer> peers_;
};

}  // namespace dz::client
