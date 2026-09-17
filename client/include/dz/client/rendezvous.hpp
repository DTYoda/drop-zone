// Getting introduced to a peer, and agreeing keys with it through a server that
// is not trusted with either.
//
// The problem this solves: two people who want to exchange files need each other's
// public keys and addresses, and the only thing they have in common is a server
// neither of them wants to trust. A naive introduction lets that server hand each
// peer its own key instead of the other's and read everything that follows.
//
// The way out is the receiver's public password, which the server has never seen.
// Both peers stretch it into a MAC key and MAC their half of the handshake --
// including their X25519 public key -- so a substituted key would need a forged
// MAC. Concretely:
//
//   sender_proof   = HMAC(pw_key, tag_s | sender | receiver | sender_spk | sender_ipk)
//   receiver_proof = HMAC(pw_key, tag_r | ...the same... | receiver_spk | receiver_ipk)
//
// The receiver checks the first, the sender checks the second, and after that both
// know the other's real key. The session secret is X25519 over those keys, salted
// with a hash of the whole transcript, so even an identical pair of peers with an
// identical password derive different keys in a different session.
//
// Ed25519 signatures over the same bytes are carried alongside. They add no
// confidentiality -- the MACs already do that -- but they prove the peer holds the
// identity key rather than merely knowing its public half, which is what makes
// trust-on-first-use pinning meaningful.
//
// The residual weakness is that pw_key comes from a password, so an attacker who
// captures a proof can attack it offline. scrypt makes that expensive rather than
// impossible; docs/SECURITY.md is explicit about it.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dz/client/channel.hpp"
#include "dz/client/config.hpp"
#include "dz/client/identity.hpp"
#include "dz/client/known_peers.hpp"
#include "dz/client/transport.hpp"
#include "dz/crypto.hpp"
#include "dz/frame.hpp"
#include "dz/protocol.hpp"

namespace dz::client {

/// Everything two peers agree during the handshake.
struct SessionKeys {
    /// Key for data this peer sends, and for data it receives. Separate keys per
    /// direction, so a message cannot be reflected back at its own author.
    Key send_key;
    Key receive_key;
    std::uint8_t send_nonce_prefix[4]{};
    std::uint8_t receive_nonce_prefix[4]{};

    /// Key for the sealed offer, which travels before any bulk data.
    Key offer_key;

    /// Key the transport tiers use to prove to each other that a connection or a
    /// UDP path belongs to this session.
    Key handshake_key;

    AeadAlgorithm algorithm = AeadAlgorithm::Aes256Gcm;
};

/// The outcome of a successful introduction.
struct Introduction {
    std::string peer_username;
    std::uint8_t peer_identity_key[kEd25519PublicKeySize]{};
    std::vector<Endpoint> peer_candidates;
    std::uint64_t pairing_id = 0;
    TransportKind transport_hint = TransportKind::None;
    SessionKeys keys;
};

/// A live control connection to the rendezvous server.
class ControlConnection {
public:
    ControlConnection(const Config& config, const std::string& host_override,
                      std::uint16_t port_override);

    FramedStream& stream() { return stream_; }
    int fd() const { return stream_.fd(); }

    /// The server's address, needed for the reflexive UDP probe.
    const Endpoint& server_endpoint() const { return server_; }

    /// Announce this peer. Sending it again as a receiver between transfers
    /// republishes the ports without giving up the username.
    ServerHello say_hello(ClientRole role, const std::string& username, const Identity& identity,
                          const std::uint8_t session_key[kX25519KeySize],
                          const LocalSockets& sockets);

    /// Send a keep-alive, which holds both the username claim and the NAT mapping.
    void keep_alive();

    void say_goodbye();

private:
    Fd socket_;
    FramedStream stream_;
    Endpoint server_;
};

/// The sender's side of the handshake: ask to be introduced to `target`, prove
/// knowledge of its public password, and check what comes back.
///
/// Throws a UserError when the target is not accepting, declines, or fails to
/// prove it knows its own password -- which is what a server trying to impersonate
/// it would look like.
Introduction request_introduction(ControlConnection& control, const Config& config,
                                  const Identity& identity, const X25519KeyPair& session_keys,
                                  const std::string& target_username,
                                  std::string_view public_password, TransportKind transport_hint,
                                  KnownPeers& known_peers);

/// The receiver's side: wait for a sender, check its proof, and answer with this
/// peer's own half.
///
/// `timeout_ms` of 0 waits indefinitely, which is what accept mode does.
/// Returns false on timeout.
bool await_introduction(ControlConnection& control, const Config& config,
                        const Identity& identity, const X25519KeyPair& session_keys,
                        const Key& public_password_key, TransportKind own_transport_hint,
                        KnownPeers& known_peers, std::uint32_t timeout_ms, Introduction& out);

/// Report a pinning result to the user, and decide whether to continue.
///
/// A first sighting is recorded and accepted. An unchanged key passes silently. A
/// changed key stops the transfer, because continuing would defeat the whole point
/// of having recorded it.
void enforce_pinning(KnownPeers& known_peers, const std::string& username,
                     const std::uint8_t identity_key[kEd25519PublicKeySize], bool quiet);

}  // namespace dz::client
