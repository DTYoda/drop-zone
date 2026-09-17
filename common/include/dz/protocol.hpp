// The drop-zone wire protocol: the structures that cross the network, and the
// rules for authenticating them.
//
// docs/PROTOCOL.md is the prose version of this file and explains why each
// field exists. The short version:
//
//  * The rendezvous server is a switchboard. It learns a username, two public
//    keys and a candidate address list for the duration of a session, forwards
//    them to the other peer, and forgets them when the socket closes. It never
//    sees a password, a filename or a file byte.
//  * The two peers authenticate each other with the receiver's public password.
//    Both sides derive a MAC key from it and MAC the whole handshake transcript,
//    including both X25519 public keys. A server that swapped those keys to sit
//    in the middle would have to forge a MAC under a key it does not have, so
//    the introduction is safe even though it passes through an untrusted party.
//  * Only after the peers are connected directly does either mention a file.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dz/crypto.hpp"
#include "dz/socket.hpp"

namespace dz {

/// Default port for the rendezvous server. Unassigned by IANA.
constexpr std::uint16_t kDefaultServerPort = 47654;

/// Bulk data travels in chunks of this size.
///
/// 1 MiB is large enough that per-chunk costs -- a frame header, a nonce setup,
/// a queue handoff -- vanish against the AEAD work, and small enough that a
/// worker pool stays evenly loaded and a single lost chunk on the UDP transport
/// is cheap to retransmit.
constexpr std::uint32_t kDefaultChunkSize = 1u << 20;

/// Longest username the protocol accepts. Bounded so a hostile client cannot
/// make the server's session table hold megabyte-long keys.
constexpr std::size_t kMaxUsernameLength = 64;

/// Longest relative path inside a manifest.
constexpr std::size_t kMaxPathLength = 1024;

/// Most files one transfer may carry.
constexpr std::size_t kMaxManifestEntries = 200'000;

/// Salt for stretching the private password into the keystore key.
constexpr std::size_t kKeystoreSaltSize = 16;

// ---------------------------------------------------------------------------
// Domain separation
//
// Every derived key and every MAC names its own purpose. Without this, the same
// input bytes could produce the same output in two different roles -- and a
// sender's proof could then be replayed as a receiver's confirmation.
// ---------------------------------------------------------------------------

constexpr const char* kInfoDataKeySenderToReceiver = "drop-zone/v1 data sender->receiver";
constexpr const char* kInfoDataKeyReceiverToSender = "drop-zone/v1 data receiver->sender";
constexpr const char* kInfoNoncePrefixSenderToReceiver = "drop-zone/v1 nonce sender->receiver";
constexpr const char* kInfoNoncePrefixReceiverToSender = "drop-zone/v1 nonce receiver->sender";
constexpr const char* kInfoOfferKey = "drop-zone/v1 sealed offer";
constexpr const char* kMacContextSenderProof = "drop-zone/v1 sender proof";
constexpr const char* kMacContextReceiverProof = "drop-zone/v1 receiver proof";
constexpr const char* kSignContextTranscript = "drop-zone/v1 transcript signature";
constexpr const char* kKeystoreAad = "drop-zone/v1 identity keystore";

/// Fixed salt for stretching a public password into its MAC key.
///
/// Derived from the receiver's username rather than being random, so that both
/// peers can compute the key without an extra round trip and the receiver can
/// compute it once at start-up instead of running scrypt for every incoming
/// request -- which would otherwise be a trivial way to pin its CPU. The cost is
/// that the same password under the same username always yields the same key;
/// docs/SECURITY.md covers what that does and does not expose.
std::string public_password_salt(std::string_view receiver_username);

/// Stretch a public password into the MAC key both peers use for their proofs.
Key derive_public_password_key(std::string_view password, std::string_view receiver_username);

// ---------------------------------------------------------------------------
// Which transport carried the data
// ---------------------------------------------------------------------------

enum class TransportKind : std::uint8_t {
    None = 0,
    DirectTcp = 1,   ///< Tier 1: a real TCP connection between the peers.
    HolePunchUdp = 2,///< Tier 2: reliable stream over a punched UDP path.
    ServerRelay = 3, ///< Tier 3: bytes forwarded by the rendezvous server.
};

const char* transport_kind_name(TransportKind kind);

/// Parse "tcp", "udp", "relay" or "auto" for --force-transport.
bool parse_transport_kind(std::string_view text, TransportKind& out);

// ---------------------------------------------------------------------------
// Reflexive address discovery
//
// A peer behind NAT cannot see the address and port its own packets appear to
// come from, and hole punching needs exactly that. The server answers a
// four-byte probe with the source address it observed, which is the one useful
// thing only an outside observer can report.
//
// This exchange is completely stateless: the reply is computed from the packet's
// own source address and nothing is recorded, so it adds no session state to the
// server and no address to its memory beyond the moment the datagram is handled.
// ---------------------------------------------------------------------------

constexpr std::uint8_t kReflexiveProbeMagic[4] = {'D', 'Z', 'R', '1'};
constexpr std::uint8_t kReflexiveReplyMagic[4] = {'D', 'Z', 'R', '2'};
constexpr std::size_t kReflexiveProbeSize = 4;
constexpr std::size_t kMaxReflexiveReplySize = 32;

/// Build the reply to a reflexive probe: the magic followed by the encoded
/// source endpoint. Returns the number of bytes written.
std::size_t encode_reflexive_reply(const Endpoint& observed, std::uint8_t* out,
                                   std::size_t capacity);

/// Parse a reflexive reply. Returns false if it is not one.
bool decode_reflexive_reply(const std::uint8_t* data, std::size_t len, Endpoint& out);

// ---------------------------------------------------------------------------
// Control-plane messages
// ---------------------------------------------------------------------------

enum class ClientRole : std::uint8_t {
    Receiver = 1,  ///< Entered accept mode; wants to claim a username.
    Sender = 2,    ///< Entered send mode; wants an introduction.
};

/// First message on a control connection.
struct ClientHello {
    ClientRole role = ClientRole::Receiver;
    std::string username;
    /// Long-term Ed25519 identity, pinned by peers on first use.
    std::uint8_t identity_key[kEd25519PublicKeySize]{};
    /// Ephemeral X25519 key for this session only.
    std::uint8_t session_key[kX25519KeySize]{};
    /// Port this peer will listen on for a direct TCP connection.
    std::uint16_t tcp_port = 0;
    /// Port this peer punches from and listens on for UDP.
    std::uint16_t udp_port = 0;
    /// Addresses reachable on this peer's own networks.
    std::vector<Endpoint> local_candidates;

    std::vector<std::uint8_t> encode() const;
    static ClientHello decode(const std::vector<std::uint8_t>& payload);
};

/// The server's reply, carrying the one piece of information a peer cannot work
/// out for itself: how its address looks from outside its NAT.
struct ServerHello {
    bool claim_accepted = true;
    std::string message;
    /// The source address the server saw, i.e. the peer's NAT mapping.
    Endpoint reflexive_tcp;
    /// The reflexive address of the peer's UDP socket, filled in after the peer
    /// sends a UDP probe to the server. Zero until then.
    Endpoint reflexive_udp;
    /// Longest a session may sit idle before the server drops it.
    std::uint32_t idle_timeout_seconds = 300;

    std::vector<std::uint8_t> encode() const;
    static ServerHello decode(const std::vector<std::uint8_t>& payload);
};

/// A sender asking to be introduced. Notably absent: anything about the file.
struct SendRequest {
    std::string target_username;
    /// Proof that the sender knows the target's public password, MAC-ed over the
    /// transcript so it cannot be replayed into another session.
    std::uint8_t proof[kSha256Size]{};
    /// The sender's --force-transport, passed through to the receiver so both
    /// peers run the same ladder. A test knob, not a security control.
    TransportKind transport_hint = TransportKind::None;

    std::vector<std::uint8_t> encode() const;
    static SendRequest decode(const std::vector<std::uint8_t>& payload);
};

/// What the server forwards to a receiver about a waiting sender, and to a
/// sender about the receiver that accepted. Both directions carry the same
/// shape, and the server copies the fields through without interpreting them.
struct PeerIntroduction {
    std::string username;
    std::uint8_t identity_key[kEd25519PublicKeySize]{};
    std::uint8_t session_key[kX25519KeySize]{};
    std::vector<Endpoint> candidates;
    /// Password proof from the peer: the sender's in an Incoming, the
    /// receiver's confirmation in a Matched.
    std::uint8_t proof[kSha256Size]{};
    /// Signature over the transcript hash under the peer's identity key.
    std::uint8_t signature[kEd25519SignatureSize]{};
    /// Opaque token identifying this pairing, used to open a relay.
    std::uint64_t pairing_id = 0;
    /// A transport tier the peer insists on, from its --force-transport. Carried
    /// so both peers run the same ladder; None means "try them all in order".
    /// Not covered by the password proofs because forcing a tier cannot weaken
    /// the session: every tier carries the same end-to-end encrypted stream.
    TransportKind transport_hint = TransportKind::None;

    std::vector<std::uint8_t> encode() const;
    static PeerIntroduction decode(const std::vector<std::uint8_t>& payload);
};

// ---------------------------------------------------------------------------
// Data-plane messages
// ---------------------------------------------------------------------------

/// One file in a transfer.
struct ManifestEntry {
    /// Path relative to the output directory, always with '/' separators, never
    /// absolute and never containing "..".
    std::string path;
    std::uint64_t size = 0;
    /// Permission bits only; ownership and timestamps are deliberately not
    /// carried across machines.
    std::uint32_t mode = 0644;
    /// SHA-256 of the file's contents, checked by the receiver before it reports
    /// success.
    std::uint8_t digest[kSha256Size]{};
};

/// What the sender proposes to send.
///
/// Travels sealed under a key derived from the session secret, so the server
/// forwards a blob it cannot read -- which is how "the server stores no file
/// information" is achieved rather than merely promised.
struct TransferOffer {
    std::string sender_username;
    /// Name to show the user: the file, or the top-level directory.
    std::string display_name;
    std::vector<ManifestEntry> entries;
    std::uint64_t total_bytes = 0;
    /// False when the sender was run with --no-encrypt.
    bool encrypt_payload = true;
    AeadAlgorithm algorithm = AeadAlgorithm::Aes256Gcm;
    std::uint32_t chunk_size = kDefaultChunkSize;
    /// True when the sender hashed every file up front and filled in the digest
    /// fields. Off by default: hashing costs a whole extra read pass, and in
    /// encrypted mode each chunk's authentication tag already proves its bytes
    /// while the authenticated counter sequence proves none are missing. See
    /// docs/SECURITY.md.
    bool digests_present = false;

    std::vector<std::uint8_t> encode() const;
    static TransferOffer decode(const std::uint8_t* data, std::size_t len);
};

/// Header on every chunk frame, and the associated data the AEAD tag covers.
///
/// Authenticating the header is what stops an attacker from moving a chunk to a
/// different offset or file: the ciphertext would still decrypt, but the tag
/// would not verify against the altered header.
struct ChunkHeader {
    std::uint32_t file_index = 0;
    std::uint32_t plaintext_length = 0;
    std::uint64_t offset = 0;
    /// Nonce counter for this chunk. Explicit rather than implied by arrival
    /// order, which is what lets chunks be decrypted out of order.
    std::uint64_t counter = 0;
};

constexpr std::size_t kChunkHeaderSize = 24;

void encode_chunk_header(const ChunkHeader& header, std::uint8_t* out);
ChunkHeader decode_chunk_header(const std::uint8_t* in);

/// The receiver's answer to an offer.
struct TransferDecision {
    bool accepted = false;
    std::string reason;
    /// Where the receiver will put the files, echoed back for the sender's log.
    std::string output_directory;

    std::vector<std::uint8_t> encode() const;
    static TransferDecision decode(const std::vector<std::uint8_t>& payload);
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Usernames are limited to characters that are safe in a filename, a log line
/// and a shell argument: lowercase letters, digits, '-', '_' and '.'.
bool is_valid_username(std::string_view username);

/// Reject anything that could escape the output directory: an absolute path, a
/// ".." component, an empty component, or a backslash that a different
/// filesystem might treat as a separator. This is the check the prototype's
/// directory walk had no equivalent of.
bool is_safe_relative_path(std::string_view path);

/// Turn a path supplied by a peer into one safe to create under the output
/// directory, or throw if it cannot be made safe.
std::string sanitize_relative_path(std::string_view path);

}  // namespace dz
