#include "dz/client/channel.hpp"

#include "dz/error.hpp"

namespace dz::client {

void Channel::write_pair(const void* first, std::size_t first_len, const void* second,
                         std::size_t second_len) {
    write_bytes(first, first_len);
    if (second_len > 0) write_bytes(second, second_len);
}

void Channel::write_frame(MessageType type, const void* payload, std::size_t length,
                          std::uint16_t flags) {
    if (length > kMaxFrameLength) fail("refusing to send an oversized frame");

    FrameHeader header;
    header.type = type;
    header.flags = flags;
    header.length = static_cast<std::uint32_t>(length);

    std::uint8_t header_bytes[kFrameHeaderSize];
    encode_frame_header(header, header_bytes);

    write_pair(header_bytes, sizeof(header_bytes), payload, length);
}

void Channel::read_frame(Frame& into) {
    std::uint8_t header_bytes[kFrameHeaderSize];
    read_exactly(header_bytes, sizeof(header_bytes));

    into.header = decode_frame_header(header_bytes);
    into.payload.resize(into.header.length);
    if (into.header.length > 0) read_exactly(into.payload.data(), into.payload.size());
}

void Channel::read_expected(MessageType expected, Frame& into) {
    read_frame(into);

    if (into.header.type == expected) return;

    if (into.header.type == MessageType::Abort) {
        std::string reason(reinterpret_cast<const char*>(into.payload.data()), into.payload.size());
        if (reason.empty()) reason = "no reason given";
        fail_user("the other side stopped the transfer: " + reason);
    }

    fail(std::string("expected a ") + message_type_name(expected) + " frame but the peer sent a " +
         message_type_name(into.header.type));
}

}  // namespace dz::client
