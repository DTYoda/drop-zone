// The transport ladder: three ways to get a byte stream between two peers,
// tried in order of how good the result is rather than how likely it is to work.
//
//   1. Direct TCP. Both peers listen and both connect, to every address the
//      other advertised, and the first connection to complete wins. This is what
//      happens on a shared LAN, behind a port forward, or between two hosts with
//      public addresses. It is the fastest tier because the kernel does the
//      reliability and sendfile() can bypass userspace entirely.
//
//   2. Hole-punched UDP. Both peers send probes to each other's candidates at the
//      same time from the socket whose mapping the server already observed. Most
//      NATs will forward an inbound packet from an address they have just seen an
//      outbound packet to, so the two streams of probes open the path for each
//      other. A reliable protocol then runs over it -- see reliable_udp.hpp.
//
//   3. Server relay. The rendezvous server forwards opaque bytes. Always works,
//      costs the operator bandwidth, and is the only tier where the data leaves
//      the two peers' own path -- which is why the stream is encrypted end to end
//      and why --no-encrypt refuses to use this tier.
//
// Both peers walk the ladder with the same time budget so they arrive at the same
// tier. A tier only counts as succeeded once a two-way authenticated handshake
// has completed over it, so neither peer can end up committed to a path the other
// has already given up on.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dz/client/channel.hpp"
#include "dz/crypto.hpp"
#include "dz/frame.hpp"
#include "dz/protocol.hpp"
#include "dz/socket.hpp"

namespace dz::client {

/// The sockets a peer must open, and advertise, before it says hello.
///
/// The ports have to be in the ClientHello, so they are bound first. TCP and UDP
/// share one port number, which lets a single candidate list serve both tiers.
struct LocalSockets {
    Fd tcp_listener;
    Fd udp_socket;
    std::uint16_t port = 0;

    /// Addresses of this machine's own interfaces, each carrying `port`.
    std::vector<Endpoint> local_candidates;

    /// This peer's address as the server saw its UDP probe, if the probe got
    /// through. The authoritative candidate for punching.
    Endpoint reflexive_udp;
    bool reflexive_known = false;
};

/// Bind a listener and a UDP socket on one shared port and enumerate local
/// addresses. `include_loopback` is what makes two clients on one machine able
/// to find each other, which the end-to-end test relies on.
LocalSockets open_local_sockets(bool include_loopback);

/// Ask the server for this peer's reflexive UDP address, filling in
/// `sockets.reflexive_udp`. Best-effort: a firewall that drops the probe leaves
/// the local candidates to do the work.
void discover_reflexive_address(LocalSockets& sockets, const Endpoint& server_endpoint);

/// Everything the ladder needs, gathered so the sender and receiver paths can
/// share one function.
struct TransportRequest {
    /// True for the peer that initiated: it connects first on the TCP tier and
    /// takes the client role in the punch handshake.
    bool is_sender = false;

    /// Where the peer says it can be reached.
    std::vector<Endpoint> peer_candidates;

    /// Key authenticating the punch and the direct-TCP handshakes, derived from
    /// the session secret. Without it, any host that happened to connect to the
    /// listening port would be adopted as the peer.
    Key handshake_key;

    /// A tier to insist on, or None to walk the whole ladder.
    TransportKind forced = TransportKind::None;

    /// How long to spend on each tier before moving on.
    std::uint32_t tcp_budget_ms = 1500;
    std::uint32_t udp_budget_ms = 4000;

    /// The control connection, used for the relay tier and to tell the server
    /// this peer has given up on a direct path.
    FramedStream* control = nullptr;
    std::uint64_t pairing_id = 0;
};

/// Walk the ladder and return the first channel that works. Throws when every
/// tier fails.
ChannelPtr establish_channel(LocalSockets& sockets, const TransportRequest& request);

// -- Individual tiers, exposed so the tests can drive them directly ---------

/// Tier 1. Returns nullptr if no direct connection completed in the budget.
ChannelPtr try_direct_tcp(LocalSockets& sockets, const TransportRequest& request);

/// Tier 2. Returns nullptr if no UDP path opened in the budget.
ChannelPtr try_hole_punch_udp(LocalSockets& sockets, const TransportRequest& request);

/// Tier 3. Asks the server to relay and waits for it to agree. Throws if the
/// server refuses.
ChannelPtr open_server_relay(const TransportRequest& request);

}  // namespace dz::client
