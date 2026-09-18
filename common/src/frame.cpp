#include "dz/frame.hpp"

#include <sys/uio.h>

#include <cstring>

#include "dz/endian.hpp"
#include "dz/error.hpp"
#include "dz/socket.hpp"

namespace dz {

const char* message_type_name(MessageType type) {
    switch (type) {
        case MessageType::ClientHello: return "ClientHello";
        case MessageType::ServerHello: return "ServerHello";
        case MessageType::SendRequest: return "SendRequest";
        case MessageType::Incoming: return "Incoming";
        case MessageType::Accept: return "Accept";
        case MessageType::Reject: return "Reject";
        case MessageType::Matched: return "Matched";
        case MessageType::RelayOpen: return "RelayOpen";
        case MessageType::RelayData: return "RelayData";
        case MessageType::RelayClose: return "RelayClose";
        case MessageType::KeepAlive: return "KeepAlive";
        case MessageType::Bye: return "Bye";
        case MessageType::GroupQuery: return "GroupQuery";
        case MessageType::GroupStatus: return "GroupStatus";
        case MessageType::GroupJoin: return "GroupJoin";
        case MessageType::GroupResult: return "GroupResult";
        case MessageType::GroupSendRequest: return "GroupSendRequest";
        case MessageType::GroupRoster: return "GroupRoster";
        case MessageType::Offer: return "Offer";
        case MessageType::Decision: return "Decision";
        case MessageType::Chunk: return "Chunk";
        case MessageType::TransferEnd: return "TransferEnd";
        case MessageType::TransferAck: return "TransferAck";
        case MessageType::Abort: return "Abort";
    }
    return "unknown";
}

void encode_frame_header(const FrameHeader& header, std::uint8_t* out) {
    out[0] = header.version;
    out[1] = static_cast<std::uint8_t>(header.type);
    store_u16(out + 2, header.flags);
    store_u32(out + 4, header.length);
}

FrameHeader decode_frame_header(const std::uint8_t* in) {
    FrameHeader header;
    header.version = in[0];
    header.type = static_cast<MessageType>(in[1]);
    header.flags = load_u16(in + 2);
    header.length = load_u32(in + 4);

    if (header.version != kProtocolVersion) {
        fail("peer speaks drop-zone protocol version " + std::to_string(header.version) +
             ", this build speaks " + std::to_string(kProtocolVersion));
    }
    // Checking the length before it is used to size a buffer is what stops a
    // forged 4 GiB header from becoming a 4 GiB allocation.
    if (header.length > kMaxFrameLength) {
        fail("frame length " + std::to_string(header.length) + " exceeds the " +
             std::to_string(kMaxFrameLength) + " byte limit");
    }
    return header;
}

// ---------------------------------------------------------------------------
// FramedStream
// ---------------------------------------------------------------------------

void FramedStream::write_frame(MessageType type, const void* payload, std::size_t length,
                               std::uint16_t flags) {
    if (length > kMaxFrameLength) fail("refusing to send an oversized frame");

    FrameHeader header;
    header.type = type;
    header.flags = flags;
    header.length = static_cast<std::uint32_t>(length);

    std::uint8_t header_bytes[kFrameHeaderSize];
    encode_frame_header(header, header_bytes);

    if (length == 0) {
        write_all(fd_, header_bytes, sizeof(header_bytes));
        return;
    }

    // One writev() instead of two write() calls: the header and the payload
    // reach the wire in the same segment, which for a 1 MiB chunk saves a
    // syscall and, more importantly, stops the 8-byte header from being sent as
    // its own tiny packet.
    iovec parts[2];
    parts[0].iov_base = header_bytes;
    parts[0].iov_len = sizeof(header_bytes);
    parts[1].iov_base = const_cast<void*>(payload);
    parts[1].iov_len = length;

    std::size_t total = sizeof(header_bytes) + length;
    std::size_t sent = 0;
    int index = 0;

    while (sent < total) {
        ssize_t written = ::writev(fd_, parts + index, 2 - index);
        if (written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!wait_writable(fd_, 30'000)) fail("frame write timed out");
                continue;
            }
            fail_errno("writev to socket failed");
        }

        sent += static_cast<std::size_t>(written);

        // Advance past whichever parts were fully consumed, then trim the one
        // that was partly consumed.
        auto consumed = static_cast<std::size_t>(written);
        while (index < 2 && consumed >= parts[index].iov_len) {
            consumed -= parts[index].iov_len;
            ++index;
        }
        if (index < 2 && consumed > 0) {
            parts[index].iov_base = static_cast<std::uint8_t*>(parts[index].iov_base) + consumed;
            parts[index].iov_len -= consumed;
        }
    }
}

void FramedStream::read_frame(Frame& into) {
    std::uint8_t header_bytes[kFrameHeaderSize];
    read_exact(fd_, header_bytes, sizeof(header_bytes));

    into.header = decode_frame_header(header_bytes);

    // resize() on a vector that is already large enough does not reallocate, so
    // reusing one Frame across a whole transfer allocates once.
    into.payload.resize(into.header.length);
    if (into.header.length > 0) {
        read_exact(fd_, into.payload.data(), into.payload.size());
    }
}

void FramedStream::read_expected(MessageType expected, Frame& into) {
    read_frame(into);

    if (into.header.type == expected) return;

    if (into.header.type == MessageType::Abort || into.header.type == MessageType::Reject) {
        std::string reason(reinterpret_cast<const char*>(into.payload.data()), into.payload.size());
        if (reason.empty()) reason = "no reason given";
        fail_user("peer aborted the transfer: " + reason);
    }

    fail(std::string("expected a ") + message_type_name(expected) + " frame but received a " +
         message_type_name(into.header.type));
}

// ---------------------------------------------------------------------------
// PayloadWriter
// ---------------------------------------------------------------------------

void PayloadWriter::put_u8(std::uint8_t value) { buffer_.push_back(value); }

void PayloadWriter::put_u16(std::uint16_t value) {
    std::uint8_t bytes[2];
    store_u16(bytes, value);
    put_raw(bytes, sizeof(bytes));
}

void PayloadWriter::put_u32(std::uint32_t value) {
    std::uint8_t bytes[4];
    store_u32(bytes, value);
    put_raw(bytes, sizeof(bytes));
}

void PayloadWriter::put_u64(std::uint64_t value) {
    std::uint8_t bytes[8];
    store_u64(bytes, value);
    put_raw(bytes, sizeof(bytes));
}

void PayloadWriter::put_raw(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    buffer_.insert(buffer_.end(), bytes, bytes + len);
}

void PayloadWriter::put_bytes(const void* data, std::size_t len) {
    put_u32(static_cast<std::uint32_t>(len));
    put_raw(data, len);
}

void PayloadWriter::put_string(std::string_view text) { put_bytes(text.data(), text.size()); }

void PayloadWriter::put_endpoint(const Endpoint& endpoint) {
    // Family, port and the raw address bytes, rather than a printable string:
    // fixed-width fields are cheaper to parse and cannot be ambiguous.
    if (endpoint.family() == AF_INET) {
        put_u8(4);
        put_u16(endpoint.port());
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(endpoint.sockaddr_ptr());
        put_raw(&v4->sin_addr, 4);
    } else if (endpoint.family() == AF_INET6) {
        put_u8(6);
        put_u16(endpoint.port());
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(endpoint.sockaddr_ptr());
        put_raw(&v6->sin6_addr, 16);
    } else {
        put_u8(0);
        put_u16(0);
    }
}

void PayloadWriter::put_endpoints(const std::vector<Endpoint>& endpoints) {
    put_u16(static_cast<std::uint16_t>(endpoints.size()));
    for (const Endpoint& endpoint : endpoints) put_endpoint(endpoint);
}

// ---------------------------------------------------------------------------
// PayloadReader
// ---------------------------------------------------------------------------

void PayloadReader::need(std::size_t count) const {
    if (remaining() < count) {
        fail("frame payload is truncated: needed " + std::to_string(count) + " more bytes, have " +
             std::to_string(remaining()));
    }
}

std::uint8_t PayloadReader::take_u8() {
    need(1);
    return data_[offset_++];
}

std::uint16_t PayloadReader::take_u16() {
    need(2);
    std::uint16_t value = load_u16(data_ + offset_);
    offset_ += 2;
    return value;
}

std::uint32_t PayloadReader::take_u32() {
    need(4);
    std::uint32_t value = load_u32(data_ + offset_);
    offset_ += 4;
    return value;
}

std::uint64_t PayloadReader::take_u64() {
    need(8);
    std::uint64_t value = load_u64(data_ + offset_);
    offset_ += 8;
    return value;
}

void PayloadReader::take_raw(void* out, std::size_t len) {
    need(len);
    std::memcpy(out, data_ + offset_, len);
    offset_ += len;
}

std::vector<std::uint8_t> PayloadReader::take_bytes() {
    std::uint32_t len = take_u32();
    need(len);
    std::vector<std::uint8_t> out(data_ + offset_, data_ + offset_ + len);
    offset_ += len;
    return out;
}

void PayloadReader::take_fixed(void* out, std::size_t expected_len) {
    std::uint32_t len = take_u32();
    if (len != expected_len) {
        fail("expected a " + std::to_string(expected_len) + " byte field but the frame declares " +
             std::to_string(len));
    }
    take_raw(out, expected_len);
}

std::string PayloadReader::take_string() {
    std::uint32_t len = take_u32();
    need(len);
    std::string out(reinterpret_cast<const char*>(data_ + offset_), len);
    offset_ += len;
    return out;
}

Endpoint PayloadReader::take_endpoint() {
    std::uint8_t family = take_u8();
    std::uint16_t port = take_u16();

    if (family == 4) {
        sockaddr_in v4{};
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        take_raw(&v4.sin_addr, 4);
        return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&v4), sizeof(v4));
    }
    if (family == 6) {
        sockaddr_in6 v6{};
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        take_raw(&v6.sin6_addr, 16);
        return Endpoint::from_sockaddr(reinterpret_cast<sockaddr*>(&v6), sizeof(v6));
    }
    if (family == 0) return Endpoint();

    fail("unknown address family tag " + std::to_string(family) + " in frame");
}

std::vector<Endpoint> PayloadReader::take_endpoints() {
    std::uint16_t count = take_u16();
    // Each encoded endpoint costs at least 3 bytes, so a count that could not
    // possibly fit in what is left is rejected before any allocation.
    if (static_cast<std::size_t>(count) * 3 > remaining()) {
        fail("endpoint list count " + std::to_string(count) + " does not fit in the frame");
    }

    std::vector<Endpoint> endpoints;
    endpoints.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) endpoints.push_back(take_endpoint());
    return endpoints;
}

}  // namespace dz
