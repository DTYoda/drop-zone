#include "dz/protocol.hpp"

#include <cstring>

#include "dz/endian.hpp"
#include "dz/error.hpp"
#include "dz/frame.hpp"

namespace dz {

// ---------------------------------------------------------------------------
// Key derivation from the public password
// ---------------------------------------------------------------------------

std::string public_password_salt(std::string_view receiver_username) {
    return std::string("drop-zone/v1 public-password/") + std::string(receiver_username);
}

Key derive_public_password_key(std::string_view password, std::string_view receiver_username) {
    std::string salt = public_password_salt(receiver_username);

    Key key;
    scrypt_derive(password, salt.data(), salt.size(), ScryptParams{}, key.data(), key.size());
    return key;
}

// ---------------------------------------------------------------------------
// Transport naming
// ---------------------------------------------------------------------------

const char* transport_kind_name(TransportKind kind) {
    switch (kind) {
        case TransportKind::None: return "none";
        case TransportKind::DirectTcp: return "direct TCP";
        case TransportKind::HolePunchUdp: return "hole-punched UDP";
        case TransportKind::ServerRelay: return "server relay";
    }
    return "unknown";
}

bool parse_transport_kind(std::string_view text, TransportKind& out) {
    if (text == "auto" || text == "any") { out = TransportKind::None; return true; }
    if (text == "tcp" || text == "direct") { out = TransportKind::DirectTcp; return true; }
    if (text == "udp" || text == "punch") { out = TransportKind::HolePunchUdp; return true; }
    if (text == "relay" || text == "server") { out = TransportKind::ServerRelay; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> ClientHello::encode() const {
    PayloadWriter writer;
    writer.put_u8(static_cast<std::uint8_t>(role));
    writer.put_string(username);
    writer.put_bytes(identity_key, sizeof(identity_key));
    writer.put_bytes(session_key, sizeof(session_key));
    writer.put_u16(tcp_port);
    writer.put_u16(udp_port);
    writer.put_endpoints(local_candidates);
    return writer.take();
}

ClientHello ClientHello::decode(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);

    ClientHello hello;
    std::uint8_t role = reader.take_u8();
    if (role != 1 && role != 2) fail("ClientHello carries an unknown role");
    hello.role = static_cast<ClientRole>(role);

    hello.username = reader.take_string();
    if (!is_valid_username(hello.username)) fail("ClientHello carries an invalid username");

    reader.take_fixed(hello.identity_key, sizeof(hello.identity_key));
    reader.take_fixed(hello.session_key, sizeof(hello.session_key));
    hello.tcp_port = reader.take_u16();
    hello.udp_port = reader.take_u16();
    hello.local_candidates = reader.take_endpoints();
    return hello;
}

// ---------------------------------------------------------------------------
// ServerHello
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> ServerHello::encode() const {
    PayloadWriter writer;
    writer.put_bool(claim_accepted);
    writer.put_string(message);
    writer.put_endpoint(reflexive_tcp);
    writer.put_endpoint(reflexive_udp);
    writer.put_u32(idle_timeout_seconds);
    return writer.take();
}

ServerHello ServerHello::decode(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);

    ServerHello hello;
    hello.claim_accepted = reader.take_bool();
    hello.message = reader.take_string();
    hello.reflexive_tcp = reader.take_endpoint();
    hello.reflexive_udp = reader.take_endpoint();
    hello.idle_timeout_seconds = reader.take_u32();
    return hello;
}

// ---------------------------------------------------------------------------
// SendRequest
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> SendRequest::encode() const {
    PayloadWriter writer;
    writer.put_string(target_username);
    writer.put_bytes(proof, sizeof(proof));
    writer.put_u8(static_cast<std::uint8_t>(transport_hint));
    return writer.take();
}

SendRequest SendRequest::decode(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);

    SendRequest request;
    request.target_username = reader.take_string();
    if (!is_valid_username(request.target_username)) {
        fail("SendRequest names an invalid username");
    }
    reader.take_fixed(request.proof, sizeof(request.proof));

    std::uint8_t hint = reader.take_u8();
    if (hint > static_cast<std::uint8_t>(TransportKind::ServerRelay)) {
        fail("SendRequest names an unknown transport");
    }
    request.transport_hint = static_cast<TransportKind>(hint);
    return request;
}

// ---------------------------------------------------------------------------
// PeerIntroduction
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> PeerIntroduction::encode() const {
    PayloadWriter writer;
    writer.put_string(username);
    writer.put_bytes(identity_key, sizeof(identity_key));
    writer.put_bytes(session_key, sizeof(session_key));
    writer.put_endpoints(candidates);
    writer.put_bytes(proof, sizeof(proof));
    writer.put_bytes(signature, sizeof(signature));
    writer.put_u64(pairing_id);
    writer.put_u8(static_cast<std::uint8_t>(transport_hint));
    return writer.take();
}

PeerIntroduction PeerIntroduction::decode(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);

    PeerIntroduction introduction;
    introduction.username = reader.take_string();
    if (!is_valid_username(introduction.username)) {
        fail("peer introduction carries an invalid username");
    }
    reader.take_fixed(introduction.identity_key, sizeof(introduction.identity_key));
    reader.take_fixed(introduction.session_key, sizeof(introduction.session_key));
    introduction.candidates = reader.take_endpoints();
    reader.take_fixed(introduction.proof, sizeof(introduction.proof));
    reader.take_fixed(introduction.signature, sizeof(introduction.signature));
    introduction.pairing_id = reader.take_u64();

    std::uint8_t hint = reader.take_u8();
    if (hint > static_cast<std::uint8_t>(TransportKind::ServerRelay)) {
        fail("peer introduction names an unknown transport");
    }
    introduction.transport_hint = static_cast<TransportKind>(hint);
    return introduction;
}

// ---------------------------------------------------------------------------
// Reflexive address discovery
// ---------------------------------------------------------------------------

std::size_t encode_reflexive_reply(const Endpoint& observed, std::uint8_t* out,
                                  std::size_t capacity) {
    PayloadWriter writer;
    writer.put_raw(kReflexiveReplyMagic, sizeof(kReflexiveReplyMagic));
    writer.put_endpoint(observed);

    const std::vector<std::uint8_t>& bytes = writer.bytes();
    if (bytes.size() > capacity) fail("reflexive reply does not fit in the datagram buffer");

    std::memcpy(out, bytes.data(), bytes.size());
    return bytes.size();
}

bool decode_reflexive_reply(const std::uint8_t* data, std::size_t len, Endpoint& out) {
    if (len < sizeof(kReflexiveReplyMagic)) return false;
    if (std::memcmp(data, kReflexiveReplyMagic, sizeof(kReflexiveReplyMagic)) != 0) return false;

    try {
        PayloadReader reader(data + sizeof(kReflexiveReplyMagic),
                            len - sizeof(kReflexiveReplyMagic));
        out = reader.take_endpoint();
        return true;
    } catch (const Error&) {
        // A malformed reply is just a probe that did not work; the caller falls
        // back to its local candidates.
        return false;
    }
}

// ---------------------------------------------------------------------------
// TransferOffer
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> TransferOffer::encode() const {
    PayloadWriter writer;
    writer.put_string(sender_username);
    writer.put_string(display_name);
    writer.put_bool(encrypt_payload);
    writer.put_u8(static_cast<std::uint8_t>(algorithm));
    writer.put_bool(digests_present);
    writer.put_u32(chunk_size);
    writer.put_u64(total_bytes);
    writer.put_u32(static_cast<std::uint32_t>(entries.size()));

    for (const ManifestEntry& entry : entries) {
        writer.put_string(entry.path);
        writer.put_u64(entry.size);
        writer.put_u32(entry.mode);
        writer.put_bytes(entry.digest, sizeof(entry.digest));
    }
    return writer.take();
}

TransferOffer TransferOffer::decode(const std::uint8_t* data, std::size_t len) {
    PayloadReader reader(data, len);

    TransferOffer offer;
    offer.sender_username = reader.take_string();
    if (!is_valid_username(offer.sender_username)) fail("offer carries an invalid sender username");

    offer.display_name = reader.take_string();
    offer.encrypt_payload = reader.take_bool();

    std::uint8_t algorithm = reader.take_u8();
    if (algorithm != 1 && algorithm != 2) fail("offer names an unknown cipher");
    offer.algorithm = static_cast<AeadAlgorithm>(algorithm);

    offer.digests_present = reader.take_bool();
    offer.chunk_size = reader.take_u32();
    if (offer.chunk_size == 0 || offer.chunk_size > kMaxFrameLength - kChunkHeaderSize - kAeadTagSize) {
        fail("offer names an unusable chunk size");
    }

    offer.total_bytes = reader.take_u64();

    std::uint32_t count = reader.take_u32();
    if (count > kMaxManifestEntries) {
        fail("offer lists " + std::to_string(count) + " files, more than the " +
             std::to_string(kMaxManifestEntries) + " allowed");
    }

    offer.entries.reserve(count);
    std::uint64_t summed = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        ManifestEntry entry;
        entry.path = sanitize_relative_path(reader.take_string());
        entry.size = reader.take_u64();
        entry.mode = reader.take_u32();
        reader.take_fixed(entry.digest, sizeof(entry.digest));

        // Keep only permission bits: a peer must not be able to ask for a
        // setuid file to be created.
        entry.mode &= 0777;

        summed += entry.size;
        offer.entries.push_back(std::move(entry));
    }

    if (summed != offer.total_bytes) {
        fail("offer's declared total does not match the sum of its files");
    }
    return offer;
}

// ---------------------------------------------------------------------------
// ChunkHeader
// ---------------------------------------------------------------------------

void encode_chunk_header(const ChunkHeader& header, std::uint8_t* out) {
    store_u32(out, header.file_index);
    store_u32(out + 4, header.plaintext_length);
    store_u64(out + 8, header.offset);
    store_u64(out + 16, header.counter);
}

ChunkHeader decode_chunk_header(const std::uint8_t* in) {
    ChunkHeader header;
    header.file_index = load_u32(in);
    header.plaintext_length = load_u32(in + 4);
    header.offset = load_u64(in + 8);
    header.counter = load_u64(in + 16);
    return header;
}

// ---------------------------------------------------------------------------
// TransferDecision
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> TransferDecision::encode() const {
    PayloadWriter writer;
    writer.put_bool(accepted);
    writer.put_string(reason);
    writer.put_string(output_directory);
    return writer.take();
}

TransferDecision TransferDecision::decode(const std::vector<std::uint8_t>& payload) {
    PayloadReader reader(payload);

    TransferDecision decision;
    decision.accepted = reader.take_bool();
    decision.reason = reader.take_string();
    decision.output_directory = reader.take_string();
    return decision;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

bool is_valid_username(std::string_view username) {
    if (username.empty() || username.size() > kMaxUsernameLength) return false;

    for (char c : username) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                  c == '.';
        if (!ok) return false;
    }

    // A leading dot would make the name a hidden file if it ever reached a
    // path, and "." or ".." would be worse.
    return username.front() != '.';
}

bool is_safe_relative_path(std::string_view path) {
    if (path.empty() || path.size() > kMaxPathLength) return false;
    if (path.front() == '/') return false;

    // A backslash is an ordinary character on POSIX but a separator elsewhere;
    // rejecting it keeps a path that is safe here from becoming unsafe if the
    // files are later copied to a system where it separates components.
    if (path.find('\\') != std::string_view::npos) return false;

    // NUL would truncate the path when it reaches a C API.
    if (path.find('\0') != std::string_view::npos) return false;

    std::size_t start = 0;
    while (start <= path.size()) {
        std::size_t slash = path.find('/', start);
        std::string_view component = path.substr(
            start, (slash == std::string_view::npos) ? std::string_view::npos : slash - start);

        // An empty component means a leading, trailing or doubled slash.
        if (component.empty()) return false;
        if (component == "." || component == "..") return false;

        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }

    return true;
}

std::string sanitize_relative_path(std::string_view path) {
    if (!is_safe_relative_path(path)) {
        fail("the peer sent an unsafe path and the transfer was stopped: '" + std::string(path) +
             "'");
    }
    return std::string(path);
}

}  // namespace dz
