// The interface the data plane sees, whichever transport tier won.
//
// A Channel is a reliable, ordered, bidirectional byte stream between the two
// peers. All three tiers present the same interface, so the sender and receiver
// code is written once:
//
//   TcpChannel    a real TCP connection. The only tier that can hand its
//                 descriptor to sendfile(), which is why sendfile_fd() exists on
//                 the interface at all.
//   UdpChannel    the custom reliable protocol over a hole-punched UDP path.
//   RelayChannel  frames tunnelled through the rendezvous server.
//
// Frame reading and writing are non-virtual, built on the three virtual byte
// operations, so a new transport only has to move bytes.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "dz/frame.hpp"
#include "dz/protocol.hpp"

namespace dz::client {

class Channel {
public:
    virtual ~Channel() = default;

    virtual TransportKind kind() const = 0;

    /// A short description for the progress output, e.g. "direct TCP to
    /// 192.168.1.7:47001".
    virtual std::string describe() const = 0;

    /// Read exactly `len` bytes, or throw. Throws PeerClosed when the peer hangs
    /// up at a message boundary.
    virtual void read_exactly(void* data, std::size_t len) = 0;

    /// Write `len` bytes.
    virtual void write_bytes(const void* data, std::size_t len) = 0;

    /// Write two buffers as one logical unit. Transports that can do this in a
    /// single syscall override it; the default just writes them in turn.
    ///
    /// This exists for the chunk path, where writing an 8-byte frame header and a
    /// 1 MiB payload separately would put the header in a packet of its own.
    virtual void write_pair(const void* first, std::size_t first_len, const void* second,
                            std::size_t second_len);

    /// Push anything buffered to the peer.
    virtual void flush() {}

    /// The socket zero-copy sends may target, or -1 when the transport cannot
    /// accept one. Only meaningful for a transport that puts application bytes on
    /// the wire unmodified.
    virtual int sendfile_fd() const { return -1; }

    /// Finish the conversation politely, so the peer sees an orderly end rather
    /// than a timeout.
    virtual void close_gracefully() {}

    // -- Framing, shared by every transport ---------------------------------

    void write_frame(MessageType type, const void* payload, std::size_t length,
                     std::uint16_t flags = 0);
    void write_frame(MessageType type, const std::vector<std::uint8_t>& payload,
                     std::uint16_t flags = 0) {
        write_frame(type, payload.data(), payload.size(), flags);
    }
    void write_empty(MessageType type, std::uint16_t flags = 0) {
        write_frame(type, nullptr, 0, flags);
    }

    /// Read one frame, reusing `into`'s payload capacity between calls.
    void read_frame(Frame& into);

    /// Read one frame and require it to be `expected`. An Abort is reported as
    /// the peer's own reason so the user sees why the transfer stopped.
    void read_expected(MessageType expected, Frame& into);
};

using ChannelPtr = std::unique_ptr<Channel>;

}  // namespace dz::client
