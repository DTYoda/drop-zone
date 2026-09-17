// The data plane: moving the bytes once a channel exists.
//
// The layout on the wire is the same on every transport tier:
//
//   Offer        sealed under a key only the two peers have. Carries the manifest,
//                so the server -- which may be forwarding these very bytes on the
//                relay tier -- learns nothing about what is being sent.
//   Decision     the receiver's answer, after asking its user.
//   Chunk...     a 24-byte authenticated header and up to a megabyte of payload.
//   TransferEnd  every chunk has been sent.
//   TransferAck  every chunk has been written and flushed to disk.
//
// Two things about the encrypted path are worth understanding, because they are why
// it keeps up with the network rather than becoming the bottleneck:
//
//   Each chunk is an independent AEAD message whose nonce comes from a counter in
//   its own header, not from its position in the stream. Chunks therefore have no
//   ordering dependency and a pool of workers can encrypt or decrypt them
//   concurrently; the receiver commits each one with pwrite at its own offset, so
//   they need not even be written in order.
//
//   The chunk header is the AEAD's associated data. Its file index and offset are
//   therefore covered by the authentication tag, so a chunk cannot be moved to a
//   different place in a different file by anybody who cannot forge the tag.
//
// The plaintext path exists for a trusted network where throughput matters more
// than confidentiality. On direct TCP it uses sendfile, so the file's bytes go from
// the page cache to the network card without entering this process at all -- the
// fastest possible path, and one that is only available because there is nothing to
// transform on the way.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dz/client/channel.hpp"
#include "dz/client/manifest.hpp"
#include "dz/client/rendezvous.hpp"
#include "dz/protocol.hpp"

namespace dz::client {

struct SendOptions {
    bool encrypt = true;
    bool compute_digests = false;
    bool quiet = false;
    std::uint32_t chunk_size = kDefaultChunkSize;
    /// Worker threads for encryption. 0 means one per core.
    unsigned workers = 0;
};

struct SendResult {
    std::uint64_t bytes_sent = 0;
    double seconds = 0.0;
    std::string output_directory;
};

/// Send everything in `manifest` over `channel`.
///
/// Throws a UserError if the receiver declines, or if the requested encryption
/// setting is not allowed on this transport.
SendResult send_transfer(Channel& channel, const Manifest& manifest, const SessionKeys& keys,
                         const std::string& own_username, const SendOptions& options);

struct ReceiveOptions {
    std::string output_directory;
    /// Ask the user before accepting.
    bool prompt = true;
    /// Refuse a transfer that would put file contents on the wire unencrypted.
    bool require_encryption = false;
    bool verify_digests = false;
    bool quiet = false;
    unsigned workers = 0;
};

struct ReceiveResult {
    bool accepted = false;
    std::uint64_t bytes_received = 0;
    double seconds = 0.0;
    std::string display_name;
    std::vector<std::string> written_paths;
};

/// Receive one transfer over `channel`.
ReceiveResult receive_transfer(Channel& channel, const SessionKeys& keys,
                               const std::string& peer_username, const ReceiveOptions& options);

}  // namespace dz::client
