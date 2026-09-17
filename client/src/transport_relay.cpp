// Tier 3 of the ladder: the rendezvous server forwards the bytes.
//
// Reached only when both peers have failed to open a direct path -- typically two
// symmetric NATs, which rewrite the source port per destination and so defeat
// hole punching. The stream is tunnelled inside RelayData frames on the control
// connection each peer already has open, which means no new connection, no second
// authentication and no extra port to get through a firewall.
//
// The server cannot read any of it. What travels here is the same AEAD-protected
// stream the other tiers carry, and the server has no key for it. That is also why
// --no-encrypt refuses this tier: without encryption the operator's machine would
// see the file contents, which is not a trade the user made knowingly.

#include <cstring>

#include "dz/client/transport.hpp"
#include "dz/error.hpp"
#include "dz/log.hpp"

namespace dz::client {
namespace {

/// Payload per RelayData frame.
///
/// Well under kMaxFrameLength so that the server's per-connection output buffer
/// holds several frames rather than one, which is what lets its back-pressure act
/// smoothly instead of in megabyte steps.
constexpr std::size_t kRelayPayloadSize = 256 * 1024;

}  // namespace

/// A Channel that tunnels through the control connection.
class RelayChannel : public Channel {
public:
    explicit RelayChannel(FramedStream* control) : control_(control) {}

    TransportKind kind() const override { return TransportKind::ServerRelay; }

    std::string describe() const override { return "relayed by the rendezvous server"; }

    void read_exactly(void* data, std::size_t len) override {
        auto* out = static_cast<std::uint8_t*>(data);
        std::size_t copied = 0;

        while (copied < len) {
            std::size_t available = inbox_.size() - inbox_consumed_;
            if (available > 0) {
                std::size_t take = (available < len - copied) ? available : (len - copied);
                std::memcpy(out + copied, inbox_.data() + inbox_consumed_, take);
                inbox_consumed_ += take;
                copied += take;

                if (inbox_consumed_ == inbox_.size()) {
                    inbox_.clear();
                    inbox_consumed_ = 0;
                }
                continue;
            }

            if (closed_) throw PeerClosed();
            receive_frame();
        }
    }

    void write_bytes(const void* data, std::size_t len) override {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        std::size_t offset = 0;

        while (offset < len) {
            std::size_t batch = (len - offset < kRelayPayloadSize) ? (len - offset)
                                                                  : kRelayPayloadSize;
            control_->write_frame(MessageType::RelayData, bytes + offset, batch);
            offset += batch;
        }
    }

    void close_gracefully() override {
        try {
            control_->write_empty(MessageType::RelayClose);
        } catch (const Error&) {
            // The peer or the server has already gone; nothing useful to add.
        }
    }

private:
    /// Pull one frame off the control connection and add its payload to the inbox.
    void receive_frame() {
        control_->read_frame(scratch_);

        switch (scratch_.header.type) {
            case MessageType::RelayData:
                // Compact before appending so a long transfer does not carry the
                // whole already-read prefix around with it.
                if (inbox_consumed_ > 0) {
                    inbox_.erase(inbox_.begin(),
                                 inbox_.begin() + static_cast<std::ptrdiff_t>(inbox_consumed_));
                    inbox_consumed_ = 0;
                }
                inbox_.insert(inbox_.end(), scratch_.payload.begin(), scratch_.payload.end());
                return;

            case MessageType::RelayClose:
                closed_ = true;
                return;

            case MessageType::KeepAlive:
                return;

            case MessageType::Reject: {
                std::string reason(reinterpret_cast<const char*>(scratch_.payload.data()),
                                   scratch_.payload.size());
                fail_user("the relay was closed: " +
                          (reason.empty() ? std::string("no reason given") : reason));
            }

            default:
                fail(std::string("the server sent a ") + message_type_name(scratch_.header.type) +
                     " frame in the middle of a relayed transfer");
        }
    }

    FramedStream* control_;
    Frame scratch_;
    std::vector<std::uint8_t> inbox_;
    std::size_t inbox_consumed_ = 0;
    bool closed_ = false;
};

ChannelPtr open_server_relay(const TransportRequest& request) {
    if (request.control == nullptr) fail("cannot relay without a control connection");

    PayloadWriter writer;
    writer.put_u64(request.pairing_id);
    request.control->write_frame(MessageType::RelayOpen, writer.bytes());

    log::debug("relay: asked the server to forward, waiting for the other peer to agree");

    // The server only opens the relay once both peers have asked, so this waits
    // for the other side to finish its own ladder. Generous, because the peer may
    // still be spending its full UDP budget.
    Frame frame;
    std::uint64_t deadline = monotonic_millis() + 30'000;

    while (monotonic_millis() < deadline) {
        if (!wait_readable(request.control->fd(), 1000)) continue;

        request.control->read_frame(frame);

        if (frame.header.type == MessageType::RelayOpen) {
            log::debug("relay: open");
            return std::make_unique<RelayChannel>(request.control);
        }
        if (frame.header.type == MessageType::Reject) {
            std::string reason(reinterpret_cast<const char*>(frame.payload.data()),
                               frame.payload.size());
            fail_user("the server would not relay: " +
                      (reason.empty() ? std::string("no reason given") : reason));
        }
        if (frame.header.type == MessageType::RelayClose) {
            fail_user("the other peer gave up before the relay opened");
        }
        // Anything else, a keep-alive included, is ignored while waiting.
    }

    fail("the relay did not open within 30 seconds");
}

}  // namespace dz::client
