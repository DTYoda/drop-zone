// The framing layer shared by the control protocol and the data protocol.
//
// Everything drop-zone sends is a frame: an 8-byte header followed by exactly
// `length` bytes of payload.
//
//     offset  size  field
//     0       1     version   protocol version, kProtocolVersion
//     1       1     type      MessageType
//     2       2     flags     type-specific, little-endian
//     4       4     length    payload bytes that follow, little-endian
//
// The prototype terminated messages with a blank line and scanned for "\n\n",
// which cannot carry a file's bytes (they contain newlines), silently truncates
// at a fixed 1 KiB buffer, and gives a receiver no way to know how much to
// expect. An explicit length fixes all three and lets the receiver size its
// read in one call.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dz {

class Endpoint;

constexpr std::uint8_t kProtocolVersion = 1;

constexpr std::size_t kFrameHeaderSize = 8;

/// Largest payload any single frame may declare.
///
/// Bulk data travels in kDefaultChunkSize (1 MiB) chunks plus AEAD overhead, so
/// 2 MiB leaves generous headroom while still bounding the allocation a
/// malicious peer can provoke with a forged header.
constexpr std::uint32_t kMaxFrameLength = 2u * 1024 * 1024;

enum class MessageType : std::uint8_t {
    // -- Control plane: client to rendezvous server, and back ---------------
    ClientHello = 1,   ///< Receiver or sender announces itself.
    ServerHello = 2,   ///< Reflexive address plus the outcome of the name claim.
    SendRequest = 3,   ///< Sender asks to be introduced to a username.
    Incoming = 4,      ///< Server forwards a sender's introduction to a receiver.
    Accept = 5,        ///< Receiver agrees to be introduced.
    Reject = 6,        ///< Receiver declines, or the server refuses.
    Matched = 7,       ///< Server forwards the receiver's half to the sender.
    RelayOpen = 8,     ///< Both peers failed to punch; fall back to the server.
    RelayData = 9,     ///< Opaque bytes the server forwards without inspecting.
    RelayClose = 10,   ///< Orderly end of a relayed byte stream.
    KeepAlive = 11,    ///< Holds the control connection and its NAT mapping open.
    Bye = 12,          ///< Orderly shutdown of a control connection.

    // -- Data plane: peer to peer over whichever transport won --------------
    Offer = 32,        ///< Sealed manifest: what the sender wants to send.
    Decision = 33,     ///< Receiver's accept or reject of that manifest.
    Chunk = 34,        ///< One chunk of file data, encrypted or not.
    TransferEnd = 35,  ///< Sender has emitted every chunk.
    TransferAck = 36,  ///< Receiver verified every digest and committed the files.
    Abort = 37,        ///< Either side is giving up; payload is a reason string.
};

const char* message_type_name(MessageType type);

struct FrameHeader {
    std::uint8_t version = kProtocolVersion;
    MessageType type = MessageType::KeepAlive;
    std::uint16_t flags = 0;
    std::uint32_t length = 0;
};

/// Serialise a header into exactly kFrameHeaderSize bytes.
void encode_frame_header(const FrameHeader& header, std::uint8_t* out);

/// Parse a header. Throws if the version is unknown or the length exceeds
/// kMaxFrameLength, so a bad first byte cannot become a huge allocation.
FrameHeader decode_frame_header(const std::uint8_t* in);

/// A frame in memory.
struct Frame {
    FrameHeader header;
    std::vector<std::uint8_t> payload;
};

/// Blocking framed reader/writer over a connected socket or socketpair.
///
/// Used by the client for its control connection and by the direct-TCP data
/// path. The server does not use it: it multiplexes thousands of connections in
/// one event loop and needs the non-blocking buffering in server/src/connection.
class FramedStream {
public:
    FramedStream() = default;
    explicit FramedStream(int fd) : fd_(fd) {}

    void set_fd(int fd) { fd_ = fd; }
    int fd() const { return fd_; }

    void write_frame(MessageType type, const void* payload, std::size_t length,
                     std::uint16_t flags = 0);
    void write_frame(MessageType type, const std::vector<std::uint8_t>& payload,
                     std::uint16_t flags = 0) {
        write_frame(type, payload.data(), payload.size(), flags);
    }
    void write_empty(MessageType type, std::uint16_t flags = 0) {
        write_frame(type, nullptr, 0, flags);
    }

    /// Read one frame, reusing `into.payload`'s capacity across calls so a long
    /// transfer does not allocate once per chunk.
    void read_frame(Frame& into);

    Frame read_frame() {
        Frame frame;
        read_frame(frame);
        return frame;
    }

    /// Read one frame, requiring it to be of `expected` type. A frame of any
    /// other type is a protocol violation, except Abort, which is reported as a
    /// UserError carrying the peer's reason string.
    void read_expected(MessageType expected, Frame& into);

private:
    int fd_ = -1;
};

/// Append-only builder for frame payloads.
///
/// Length-prefixing strings and byte blobs here is what keeps the parser on the
/// other side from having to trust the sender: put_bytes writes a u32 length so
/// take_bytes can reject a blob that runs past the end of the frame, which the
/// prototype's strtok()-based parsing could not do.
class PayloadWriter {
public:
    void put_u8(std::uint8_t value);
    void put_u16(std::uint16_t value);
    void put_u32(std::uint32_t value);
    void put_u64(std::uint64_t value);
    void put_bool(bool value) { put_u8(value ? 1u : 0u); }
    void put_raw(const void* data, std::size_t len);
    void put_bytes(const void* data, std::size_t len);
    void put_bytes(const std::vector<std::uint8_t>& data) { put_bytes(data.data(), data.size()); }
    void put_string(std::string_view text);
    void put_endpoint(const Endpoint& endpoint);
    void put_endpoints(const std::vector<Endpoint>& endpoints);

    const std::vector<std::uint8_t>& bytes() const { return buffer_; }
    std::vector<std::uint8_t> take() { return std::move(buffer_); }
    std::size_t size() const { return buffer_.size(); }
    void clear() { buffer_.clear(); }

private:
    std::vector<std::uint8_t> buffer_;
};

/// Bounds-checked reader for frame payloads. Every take_* throws rather than
/// reading past the end, so a truncated or hostile frame fails cleanly.
class PayloadReader {
public:
    PayloadReader(const std::uint8_t* data, std::size_t len) : data_(data), len_(len) {}
    explicit PayloadReader(const std::vector<std::uint8_t>& data)
        : data_(data.data()), len_(data.size()) {}

    std::uint8_t take_u8();
    std::uint16_t take_u16();
    std::uint32_t take_u32();
    std::uint64_t take_u64();
    bool take_bool() { return take_u8() != 0; }
    void take_raw(void* out, std::size_t len);
    std::vector<std::uint8_t> take_bytes();
    /// Read a length-prefixed blob and require it to be exactly `expected_len`.
    void take_fixed(void* out, std::size_t expected_len);
    std::string take_string();
    Endpoint take_endpoint();
    std::vector<Endpoint> take_endpoints();

    std::size_t remaining() const { return len_ - offset_; }
    bool empty() const { return remaining() == 0; }
    /// Everything consumed so far, which is what the handshake MACs cover.
    const std::uint8_t* consumed_begin() const { return data_; }
    std::size_t consumed() const { return offset_; }

private:
    void need(std::size_t count) const;

    const std::uint8_t* data_;
    std::size_t len_;
    std::size_t offset_ = 0;
};

}  // namespace dz
