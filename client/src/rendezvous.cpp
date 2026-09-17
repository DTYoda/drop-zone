#include "dz/client/rendezvous.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include "dz/endian.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

/// Keep-alive interval. Comfortably inside both the server's default idle timeout
/// and the shortest NAT mapping lifetimes seen in practice, which are around 30
/// seconds for UDP and a couple of minutes for TCP.
constexpr std::uint32_t kKeepAliveIntervalMs = 25'000;

/// Pause after a failed password proof.
///
/// The server already limits requests per address, so this is a second line: it
/// caps how fast a receiver will answer guesses even if an attacker has many
/// addresses to spread them across.
constexpr int kWrongPasswordDelayMs = 250;

/// Append a length-prefixed field, so two different splits of the same bytes
/// cannot produce the same proof input. Without the length, ("ab", "c") and
/// ("a", "bc") would hash identically and a proof for one would verify the other.
void append_field(std::vector<std::uint8_t>& out, const void* data, std::size_t len) {
    std::uint8_t length[4];
    store_u32(length, static_cast<std::uint32_t>(len));
    out.insert(out.end(), length, length + 4);

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + len);
}

void append_field(std::vector<std::uint8_t>& out, std::string_view text) {
    append_field(out, text.data(), text.size());
}

/// The bytes the sender's proof and signature cover.
std::vector<std::uint8_t> sender_proof_input(const std::string& sender_username,
                                             const std::string& receiver_username,
                                             const std::uint8_t sender_session_key[kX25519KeySize],
                                             const std::uint8_t sender_identity_key[kEd25519PublicKeySize]) {
    std::vector<std::uint8_t> input;
    append_field(input, kMacContextSenderProof);
    append_field(input, sender_username);
    append_field(input, receiver_username);
    append_field(input, sender_session_key, kX25519KeySize);
    append_field(input, sender_identity_key, kEd25519PublicKeySize);
    return input;
}

/// The bytes the receiver's proof and signature cover: the sender's half plus its
/// own keys, so one message authenticates both peers' keys at once.
std::vector<std::uint8_t> receiver_proof_input(
    const std::string& sender_username, const std::string& receiver_username,
    const std::uint8_t sender_session_key[kX25519KeySize],
    const std::uint8_t sender_identity_key[kEd25519PublicKeySize],
    const std::uint8_t receiver_session_key[kX25519KeySize],
    const std::uint8_t receiver_identity_key[kEd25519PublicKeySize]) {
    std::vector<std::uint8_t> input;
    append_field(input, kMacContextReceiverProof);
    append_field(input, sender_username);
    append_field(input, receiver_username);
    append_field(input, sender_session_key, kX25519KeySize);
    append_field(input, sender_identity_key, kEd25519PublicKeySize);
    append_field(input, receiver_session_key, kX25519KeySize);
    append_field(input, receiver_identity_key, kEd25519PublicKeySize);
    return input;
}

/// Hash of the complete handshake, used as the HKDF salt.
///
/// Including both proofs means the derived keys depend on the password as well as
/// the Diffie-Hellman secret, so an attacker who somehow recovered the private
/// keys still could not derive the session keys without also knowing the password.
Sha256Digest transcript_hash(const std::string& sender_username,
                             const std::string& receiver_username,
                             const std::uint8_t sender_session_key[kX25519KeySize],
                             const std::uint8_t sender_identity_key[kEd25519PublicKeySize],
                             const std::uint8_t receiver_session_key[kX25519KeySize],
                             const std::uint8_t receiver_identity_key[kEd25519PublicKeySize],
                             const std::uint8_t sender_proof[kSha256Size],
                             const std::uint8_t receiver_proof[kSha256Size]) {
    std::vector<std::uint8_t> input;
    append_field(input, kSignContextTranscript);
    append_field(input, sender_username);
    append_field(input, receiver_username);
    append_field(input, sender_session_key, kX25519KeySize);
    append_field(input, sender_identity_key, kEd25519PublicKeySize);
    append_field(input, receiver_session_key, kX25519KeySize);
    append_field(input, receiver_identity_key, kEd25519PublicKeySize);
    append_field(input, sender_proof, kSha256Size);
    append_field(input, receiver_proof, kSha256Size);

    Sha256Digest digest = sha256(input.data(), input.size());
    secure_zero(input.data(), input.size());
    return digest;
}

/// Turn the shared secret and the transcript into every key the session needs.
SessionKeys derive_session_keys(const SecretArray<kX25519KeySize>& shared,
                                const Sha256Digest& transcript, bool is_sender) {
    SessionKeys keys;

    Key sender_to_receiver;
    Key receiver_to_sender;
    std::uint8_t sender_prefix[4];
    std::uint8_t receiver_prefix[4];

    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(),
                kInfoDataKeySenderToReceiver, sender_to_receiver.data(),
                sender_to_receiver.size());
    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(),
                kInfoDataKeyReceiverToSender, receiver_to_sender.data(),
                receiver_to_sender.size());
    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(),
                kInfoNoncePrefixSenderToReceiver, sender_prefix, sizeof(sender_prefix));
    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(),
                kInfoNoncePrefixReceiverToSender, receiver_prefix, sizeof(receiver_prefix));

    if (is_sender) {
        keys.send_key = sender_to_receiver;
        keys.receive_key = receiver_to_sender;
        std::memcpy(keys.send_nonce_prefix, sender_prefix, sizeof(sender_prefix));
        std::memcpy(keys.receive_nonce_prefix, receiver_prefix, sizeof(receiver_prefix));
    } else {
        keys.send_key = receiver_to_sender;
        keys.receive_key = sender_to_receiver;
        std::memcpy(keys.send_nonce_prefix, receiver_prefix, sizeof(receiver_prefix));
        std::memcpy(keys.receive_nonce_prefix, sender_prefix, sizeof(sender_prefix));
    }

    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(), kInfoOfferKey,
                keys.offer_key.data(), keys.offer_key.size());
    hkdf_sha256(shared.data(), shared.size(), transcript.data(), transcript.size(),
                kInfoTransportHandshake, keys.handshake_key.data(), keys.handshake_key.size());

    // Both peers pick the same cipher independently. They can only disagree if
    // their CPUs differ, which is why the sender's choice is also carried in the
    // offer and the receiver follows it.
    keys.algorithm = preferred_aead();
    return keys;
}

}  // namespace

// ---------------------------------------------------------------------------
// ControlConnection
// ---------------------------------------------------------------------------

ControlConnection::ControlConnection(const Config& config, const std::string& host_override,
                                     std::uint16_t port_override) {
    std::string host = host_override.empty() ? config.server_host : host_override;
    std::uint16_t port = (port_override != 0) ? port_override : config.server_port;

    std::vector<Endpoint> candidates = Endpoint::resolve(host, port);

    std::string last_error;
    for (const Endpoint& candidate : candidates) {
        Fd attempt(::socket(candidate.family(), SOCK_STREAM, 0));
        if (!attempt.valid()) continue;

        set_close_on_exec(attempt.get());
        set_tcp_nodelay(attempt.get());
        set_no_sigpipe(attempt.get());

        if (::connect(attempt.get(), candidate.sockaddr_ptr(), candidate.sockaddr_len()) == 0) {
            socket_ = std::move(attempt);
            server_ = candidate;
            stream_.set_fd(socket_.get());
            log::debug("connected to the rendezvous server at " + candidate.to_string());
            return;
        }
        last_error = std::strerror(errno);
    }

    // A published server may have both an A and an AAAA record while only one of
    // them works from here, so every candidate is tried before giving up.
    fail_user("cannot reach the rendezvous server at " + host + ":" + std::to_string(port) +
              (last_error.empty() ? "" : (" (" + last_error + ")")));
}

ServerHello ControlConnection::say_hello(ClientRole role, const std::string& username,
                                         const Identity& identity,
                                         const std::uint8_t session_key[kX25519KeySize],
                                         const LocalSockets& sockets) {
    ClientHello hello;
    hello.role = role;
    hello.username = username;
    std::memcpy(hello.identity_key, identity.keys.public_key, sizeof(hello.identity_key));
    std::memcpy(hello.session_key, session_key, kX25519KeySize);
    hello.tcp_port = sockets.port;
    hello.udp_port = sockets.port;
    hello.local_candidates = sockets.local_candidates;

    // The address the server saw our UDP probe come from is the candidate that
    // matters behind NAT, and only we know it -- the server sees our control
    // connection, not our UDP socket.
    if (sockets.reflexive_known) hello.local_candidates.push_back(sockets.reflexive_udp);

    stream_.write_frame(MessageType::ClientHello, hello.encode());

    Frame frame;
    stream_.read_expected(MessageType::ServerHello, frame);
    ServerHello reply = ServerHello::decode(frame.payload);

    if (!reply.claim_accepted) {
        fail_user(reply.message.empty() ? "the server refused this username" : reply.message);
    }
    return reply;
}

void ControlConnection::keep_alive() { stream_.write_empty(MessageType::KeepAlive); }

void ControlConnection::say_goodbye() {
    try {
        stream_.write_empty(MessageType::Bye);
    } catch (const Error&) {
        // Already gone. Nothing to report.
    }
}

// ---------------------------------------------------------------------------
// Pinning
// ---------------------------------------------------------------------------

void enforce_pinning(KnownPeers& known_peers, const std::string& username,
                     const std::uint8_t identity_key[kEd25519PublicKeySize], bool quiet) {
    switch (known_peers.check(username, identity_key)) {
        case PinResult::Matches:
            return;

        case PinResult::FirstSight:
            if (!quiet) {
                std::fprintf(stderr, "First time seeing %s. Their fingerprint is %s\n",
                             username.c_str(), fingerprint_of(identity_key).c_str());
            }
            known_peers.remember(username, identity_key);
            return;

        case PinResult::Changed: {
            const KnownPeer* previous = known_peers.find(username);
            std::string previous_fingerprint =
                (previous != nullptr) ? fingerprint_of(previous->identity_key) : "unknown";

            // Refusing rather than asking. The whole value of the record is that it
            // stops silently, and a prompt here is a prompt people learn to accept.
            fail_user("'" + username + "' presented a different identity than last time.\n" +
                      "  recorded:  " + previous_fingerprint + "\n" + "  presented: " +
                      fingerprint_of(identity_key) + "\n" +
                      "Either they reinstalled drop-zone, or somebody else has taken their "
                      "username.\nIf you are sure it is them, remove their line from " +
                      "known_peers and try again.");
        }
    }
}

// ---------------------------------------------------------------------------
// The sender's side
// ---------------------------------------------------------------------------

Introduction request_introduction(ControlConnection& control, const Config& config,
                                  const Identity& identity, const X25519KeyPair& session_keys,
                                  const std::string& target_username,
                                  std::string_view public_password, TransportKind transport_hint,
                                  KnownPeers& known_peers) {
    // Stretching the password is the slow part of a send, on the order of a tenth
    // of a second. That cost is the point: it is what an attacker guessing the
    // password would have to pay per guess.
    Key password_key = derive_public_password_key(public_password, target_username);

    std::vector<std::uint8_t> proof_input = sender_proof_input(
        config.username, target_username, session_keys.public_key, identity.keys.public_key);

    SendRequest request;
    request.target_username = target_username;
    request.transport_hint = transport_hint;
    hmac_sha256(password_key.data(), password_key.size(), proof_input.data(), proof_input.size(),
                request.proof);
    ed25519_sign(identity.keys.secret, proof_input.data(), proof_input.size(), request.signature);

    control.stream().write_frame(MessageType::SendRequest, request.encode());

    Frame frame;
    control.stream().read_expected(MessageType::Matched, frame);
    PeerIntroduction peer = PeerIntroduction::decode(frame.payload);

    if (peer.username != target_username) {
        fail("the server introduced us to '" + peer.username + "' instead of '" + target_username +
             "'");
    }

    // Check that the peer proved knowledge of its own public password over both
    // sets of keys. This is the step that makes the introduction safe: a server
    // that had swapped the keys could not produce this MAC.
    std::vector<std::uint8_t> expected_input =
        receiver_proof_input(config.username, target_username, session_keys.public_key,
                             identity.keys.public_key, peer.session_key, peer.identity_key);

    std::uint8_t expected_proof[kSha256Size];
    hmac_sha256(password_key.data(), password_key.size(), expected_input.data(),
                expected_input.size(), expected_proof);

    if (!constant_time_equal(peer.proof, expected_proof, kSha256Size)) {
        fail_user("the reply from '" + target_username +
                  "' did not match the public password.\nEither the password is wrong, or "
                  "something between you altered the introduction.");
    }

    if (!ed25519_verify(peer.identity_key, expected_input.data(), expected_input.size(),
                        peer.signature)) {
        fail_user("'" + target_username +
                  "' could not prove it holds the identity key it presented");
    }

    enforce_pinning(known_peers, target_username, peer.identity_key, false);

    SecretArray<kX25519KeySize> shared = x25519_shared(session_keys.secret, peer.session_key);
    Sha256Digest transcript =
        transcript_hash(config.username, target_username, session_keys.public_key,
                        identity.keys.public_key, peer.session_key, peer.identity_key,
                        request.proof, peer.proof);

    Introduction introduction;
    introduction.peer_username = peer.username;
    std::memcpy(introduction.peer_identity_key, peer.identity_key,
                sizeof(introduction.peer_identity_key));
    introduction.peer_candidates = peer.candidates;
    introduction.pairing_id = peer.pairing_id;
    introduction.transport_hint = peer.transport_hint;
    introduction.keys = derive_session_keys(shared, transcript, true);
    return introduction;
}

// ---------------------------------------------------------------------------
// The receiver's side
// ---------------------------------------------------------------------------

bool await_introduction(ControlConnection& control, const Config& config,
                        const Identity& identity, const X25519KeyPair& session_keys,
                        const Key& password_key, TransportKind own_transport_hint,
                        KnownPeers& known_peers, std::uint32_t timeout_ms, Introduction& out) {
    std::uint64_t deadline =
        (timeout_ms == 0) ? 0 : (monotonic_millis() + timeout_ms);
    std::uint64_t next_keep_alive = monotonic_millis() + kKeepAliveIntervalMs;

    Frame frame;

    for (;;) {
        if (deadline != 0 && monotonic_millis() >= deadline) return false;

        if (!wait_readable(control.fd(), 1000)) {
            if (monotonic_millis() >= next_keep_alive) {
                control.keep_alive();
                next_keep_alive = monotonic_millis() + kKeepAliveIntervalMs;
            }
            continue;
        }

        control.stream().read_frame(frame);

        if (frame.header.type == MessageType::KeepAlive) continue;

        if (frame.header.type == MessageType::Reject ||
            frame.header.type == MessageType::RelayClose) {
            std::string reason(reinterpret_cast<const char*>(frame.payload.data()),
                               frame.payload.size());
            fail_user("the server closed this session: " +
                      (reason.empty() ? std::string("no reason given") : reason));
        }

        if (frame.header.type != MessageType::Incoming) {
            fail(std::string("the server sent an unexpected ") +
                 message_type_name(frame.header.type) + " frame while waiting for a sender");
        }

        PeerIntroduction peer = PeerIntroduction::decode(frame.payload);

        std::vector<std::uint8_t> sender_input = sender_proof_input(
            peer.username, config.username, peer.session_key, peer.identity_key);

        std::uint8_t expected_proof[kSha256Size];
        hmac_sha256(password_key.data(), password_key.size(), sender_input.data(),
                    sender_input.size(), expected_proof);

        if (!constant_time_equal(peer.proof, expected_proof, kSha256Size)) {
            log::warn("'" + peer.username + "' tried to send files with the wrong public password");

            // Sleep before answering, so a run of guesses is throttled here as
            // well as at the server.
            std::this_thread::sleep_for(std::chrono::milliseconds(kWrongPasswordDelayMs));

            static const std::string kReason = "wrong public password";
            control.stream().write_frame(MessageType::Reject, kReason.data(), kReason.size());
            continue;
        }

        if (!ed25519_verify(peer.identity_key, sender_input.data(), sender_input.size(),
                            peer.signature)) {
            static const std::string kReason = "the sender could not prove its identity";
            control.stream().write_frame(MessageType::Reject, kReason.data(), kReason.size());
            continue;
        }

        // Only now, with the password proved, is the peer worth pinning. Doing it
        // before would let anybody create a record for any username.
        enforce_pinning(known_peers, peer.username, peer.identity_key, false);

        // Answer with this peer's own keys, MAC-ed and signed over both halves.
        PeerIntroduction reply;
        reply.username = config.username;
        std::memcpy(reply.identity_key, identity.keys.public_key, sizeof(reply.identity_key));
        std::memcpy(reply.session_key, session_keys.public_key, sizeof(reply.session_key));
        reply.pairing_id = peer.pairing_id;
        reply.transport_hint = (peer.transport_hint != TransportKind::None) ? peer.transport_hint
                                                                          : own_transport_hint;

        std::vector<std::uint8_t> reply_input =
            receiver_proof_input(peer.username, config.username, peer.session_key,
                                 peer.identity_key, session_keys.public_key,
                                 identity.keys.public_key);

        hmac_sha256(password_key.data(), password_key.size(), reply_input.data(),
                    reply_input.size(), reply.proof);
        ed25519_sign(identity.keys.secret, reply_input.data(), reply_input.size(), reply.signature);

        control.stream().write_frame(MessageType::Accept, reply.encode());

        SecretArray<kX25519KeySize> shared = x25519_shared(session_keys.secret, peer.session_key);
        Sha256Digest transcript = transcript_hash(
            peer.username, config.username, peer.session_key, peer.identity_key,
            session_keys.public_key, identity.keys.public_key, peer.proof, reply.proof);

        out.peer_username = peer.username;
        std::memcpy(out.peer_identity_key, peer.identity_key, sizeof(out.peer_identity_key));
        out.peer_candidates = peer.candidates;
        out.pairing_id = peer.pairing_id;
        out.transport_hint = reply.transport_hint;
        out.keys = derive_session_keys(shared, transcript, false);
        return true;
    }
}

}  // namespace dz::client
