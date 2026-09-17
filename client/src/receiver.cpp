// The receiving half of the data plane.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>

#include "dz/aead_pool.hpp"
#include "dz/client/pipeline.hpp"
#include "dz/client/progress.hpp"
#include "dz/client/transfer.hpp"
#include "dz/cpu.hpp"
#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/log.hpp"
#include "dz/secure.hpp"

namespace dz::client {
namespace {

/// One file being received.
struct OutputFile {
    std::string path;
    Fd fd;
    std::uint64_t expected_size = 0;
    std::uint32_t mode = 0644;
    /// Bytes committed so far. Atomic because several workers commit chunks of the
    /// same file concurrently.
    std::atomic<std::uint64_t> written{0};
};

/// Read the offer and open it. The algorithm travels in the frame's flags because
/// the receiver needs it before it can decrypt anything.
TransferOffer read_offer(Channel& channel, const SessionKeys& keys) {
    Frame frame;
    channel.read_expected(MessageType::Offer, frame);

    std::uint16_t tag = frame.header.flags;
    if (tag != 1 && tag != 2) fail("the sender named an unknown cipher for its offer");
    auto algorithm = static_cast<AeadAlgorithm>(tag);

    SecretBytes plain;
    if (!open_standalone(algorithm, keys.offer_key, kInfoOfferKey, frame.payload, plain)) {
        // The offer key comes from the handshake, so a failure here means the peer
        // is not who the handshake said it was.
        fail("could not open the sender's offer; the session keys do not match");
    }

    return TransferOffer::decode(plain.data(), plain.size());
}

/// Show the user what is on offer and ask.
bool confirm_with_user(const TransferOffer& offer, const std::string& peer_username,
                       const std::string& output_directory, const ReceiveOptions& options) {
    if (!options.prompt) return true;

    std::fprintf(stderr, "\n%s wants to send you %s (%s", peer_username.c_str(),
                 offer.display_name.c_str(), format_bytes(offer.total_bytes).c_str());
    if (offer.entries.size() > 1) {
        std::fprintf(stderr, " across %zu files", offer.entries.size());
    }
    std::fprintf(stderr, ")\n");

    std::fprintf(stderr, "  into:       %s\n", output_directory.c_str());
    std::fprintf(stderr, "  encryption: %s\n",
                 offer.encrypt_payload ? aead_algorithm_name(offer.algorithm) : "none");

    // Listing every path in a large transfer would bury the prompt, so a sample is
    // shown and the rest counted.
    std::size_t shown = std::min<std::size_t>(offer.entries.size(), 8);
    for (std::size_t i = 0; i < shown; ++i) {
        std::fprintf(stderr, "  %s (%s)\n", offer.entries[i].path.c_str(),
                     format_bytes(offer.entries[i].size).c_str());
    }
    if (offer.entries.size() > shown) {
        std::fprintf(stderr, "  ... and %zu more\n", offer.entries.size() - shown);
    }

    return read_yes_no("Accept? (y/n) ", false);
}

/// Create the directories and open every output file, reserving its space.
std::vector<std::unique_ptr<OutputFile>> open_outputs(const TransferOffer& offer,
                                                      const std::vector<std::string>& paths) {
    std::vector<std::unique_ptr<OutputFile>> files;
    files.reserve(offer.entries.size());

    for (std::size_t i = 0; i < offer.entries.size(); ++i) {
        const ManifestEntry& entry = offer.entries[i];

        auto file = std::make_unique<OutputFile>();
        file->path = paths[i];
        file->expected_size = entry.size;
        file->mode = entry.mode;

        make_directories(parent_path(file->path));

        // Created 0600 and widened at the end, so a file is never briefly readable
        // by others while it is still partly written.
        int raw = ::open(file->path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (raw < 0) fail_errno("cannot create '" + file->path + "'");
        file->fd.reset(raw);

        // Reserved now so that a transfer which will not fit fails here rather than
        // at 90%, and so the filesystem can pick contiguous extents.
        preallocate_file(file->fd.get(), entry.size);

        files.push_back(std::move(file));
    }
    return files;
}

/// Check a chunk header against the manifest before trusting any of it.
void validate_chunk(const ChunkHeader& header, const std::vector<std::unique_ptr<OutputFile>>& files,
                    std::uint64_t expected_counter, std::uint32_t max_chunk_size) {
    if (header.file_index >= files.size()) {
        fail("the sender referred to a file that is not in its own manifest");
    }
    if (header.plaintext_length > max_chunk_size) {
        fail("the sender sent a chunk larger than the size it declared");
    }

    // A counter that is not the next one means a chunk went missing. Because the
    // counter is inside the authenticated header, this check also cannot be
    // defeated by an attacker dropping chunks from the stream.
    if (header.counter != expected_counter) {
        fail("chunk " + std::to_string(header.counter) + " arrived where " +
             std::to_string(expected_counter) + " was expected; the transfer is incomplete");
    }

    const OutputFile& file = *files[header.file_index];
    if (header.offset + header.plaintext_length > file.expected_size) {
        fail("the sender sent a chunk that runs past the end of '" + file.path + "'");
    }
}

/// Re-read every file and compare against the manifest's digests.
void verify_digests(const TransferOffer& offer,
                    const std::vector<std::unique_ptr<OutputFile>>& files, bool quiet) {
    if (!quiet) std::fprintf(stderr, "verifying %zu files...\n", files.size());

    for (std::size_t i = 0; i < files.size(); ++i) {
        const OutputFile& file = *files[i];

        MappedFile mapped(file.path);
        Sha256Digest digest = (mapped.size() > 0)
                                  ? sha256(mapped.data(), static_cast<std::size_t>(mapped.size()))
                                  : sha256("", 0);

        if (!constant_time_equal(digest.data(), offer.entries[i].digest, kSha256Size)) {
            fail("'" + file.path + "' does not match the digest the sender sent");
        }
    }
}

/// Finish each file: flush it, widen its permissions to what was offered, close it.
void finalise_outputs(std::vector<std::unique_ptr<OutputFile>>& files) {
    for (std::unique_ptr<OutputFile>& file : files) {
        if (file->written.load() != file->expected_size) {
            fail("'" + file->path + "' received " + std::to_string(file->written.load()) +
                 " of " + std::to_string(file->expected_size) + " bytes");
        }

        // Flushed before the sender is told the transfer succeeded, so "done" means
        // the bytes survive a power cut rather than merely having reached the page
        // cache.
        fsync_file(file->fd.get());

        // Only permission bits, and never setuid or setgid: those were masked off
        // when the manifest was parsed.
        (void)::fchmod(file->fd.get(), static_cast<mode_t>(file->mode & 0777u));
        file->fd.reset();
    }
}

}  // namespace

ReceiveResult receive_transfer(Channel& channel, const SessionKeys& keys,
                               const std::string& peer_username, const ReceiveOptions& options) {
    ReceiveResult result;

    TransferOffer offer = read_offer(channel, keys);
    result.display_name = offer.display_name;

    std::string output_directory =
        options.output_directory.empty() ? current_directory() : options.output_directory;

    auto decline = [&channel](const std::string& reason) {
        TransferDecision decision;
        decision.accepted = false;
        decision.reason = reason;
        channel.write_frame(MessageType::Decision, decision.encode());
    };

    // Two reasons to refuse before even asking the user.
    if (!offer.encrypt_payload && channel.kind() == TransportKind::ServerRelay) {
        decline("this transfer would pass through the rendezvous server, so it must be encrypted");
        fail_user(peer_username +
                  " tried to send unencrypted files over the relay, which drop-zone refuses");
    }
    if (!offer.encrypt_payload && options.require_encryption) {
        decline("this receiver requires encrypted transfers");
        fail_user(peer_username + " tried to send unencrypted files, which this receiver refuses");
    }

    std::vector<std::string> paths = resolve_output_paths(offer.entries, output_directory);

    if (!confirm_with_user(offer, peer_username, output_directory, options)) {
        decline("declined");
        result.accepted = false;
        return result;
    }

    std::vector<std::unique_ptr<OutputFile>> files = open_outputs(offer, paths);

    TransferDecision decision;
    decision.accepted = true;
    decision.output_directory = output_directory;
    channel.write_frame(MessageType::Decision, decision.encode());
    channel.flush();

    result.accepted = true;

    std::string label = "receiving " + offer.display_name;
    Progress progress(label, offer.total_bytes, !options.quiet);

    unsigned workers = (options.workers == 0) ? hardware_threads() : options.workers;
    std::size_t queue_depth = static_cast<std::size_t>(workers) * 2;

    // Only built for an encrypted transfer: in plaintext there is nothing to
    // decrypt and the frames can be written straight out.
    std::unique_ptr<AeadPool> pool;
    std::unique_ptr<BufferPool> ciphertext_buffers;
    std::unique_ptr<BufferPool> plaintext_buffers;

    if (offer.encrypt_payload) {
        pool = std::make_unique<AeadPool>(offer.algorithm, keys.receive_key, workers, queue_depth);
        ciphertext_buffers =
            std::make_unique<BufferPool>(kChunkHeaderSize + Aead::sealed_size(offer.chunk_size));
        plaintext_buffers = std::make_unique<BufferPool>(offer.chunk_size);
    }

    std::uint64_t expected_counter = 0;
    Frame frame;

    for (;;) {
        channel.read_frame(frame);

        if (frame.header.type == MessageType::TransferEnd) break;

        if (frame.header.type == MessageType::Abort) {
            std::string reason(reinterpret_cast<const char*>(frame.payload.data()),
                               frame.payload.size());
            fail_user("the sender stopped the transfer: " +
                      (reason.empty() ? std::string("no reason given") : reason));
        }

        if (frame.header.type != MessageType::Chunk) {
            fail(std::string("expected a chunk but the sender sent a ") +
                 message_type_name(frame.header.type));
        }

        if (frame.payload.size() < kChunkHeaderSize) fail("a chunk frame is too short to parse");

        ChunkHeader header = decode_chunk_header(frame.payload.data());
        validate_chunk(header, files, expected_counter, offer.chunk_size);
        ++expected_counter;

        // A raw pointer rather than a reference, because the decryption job below
        // outlives this loop iteration and capturing a reference variable by
        // reference would leave the job holding a dangling one.
        OutputFile* target = files[header.file_index].get();
        OutputFile& file = *target;

        if (!offer.encrypt_payload) {
            // Plaintext: the payload is the file's bytes, so it goes straight to
            // disk at its own offset with no transformation and no worker hop.
            std::size_t payload_length = frame.payload.size() - kChunkHeaderSize;
            if (payload_length != header.plaintext_length) {
                fail("a chunk's length does not match its header");
            }

            pwrite_all(file.fd.get(), frame.payload.data() + kChunkHeaderSize, payload_length,
                       header.offset);
            file.written.fetch_add(payload_length);
            progress.advance(payload_length);
            continue;
        }

        // Encrypted: hand the chunk to a worker. The payload is moved into a
        // pooled buffer because `frame` is reused for the next read while the
        // worker is still using this one.
        std::vector<std::uint8_t> sealed = ciphertext_buffers->acquire();
        sealed.resize(frame.payload.size());
        std::memcpy(sealed.data(), frame.payload.data(), frame.payload.size());

        std::size_t sealed_length = sealed.size() - kChunkHeaderSize;

        pool->submit([&, target, header, sealed = std::move(sealed),
                      sealed_length](Aead& aead) mutable {
            std::vector<std::uint8_t> plain = plaintext_buffers->acquire();
            plain.resize(header.plaintext_length);

            std::uint8_t nonce[kAeadNonceSize];
            build_nonce(keys.receive_nonce_prefix, header.counter, nonce);

            std::size_t produced = 0;
            bool ok = aead.open(nonce, sealed.data(), kChunkHeaderSize,
                                sealed.data() + kChunkHeaderSize, sealed_length, plain.data(),
                                &produced);

            if (!ok) {
                // The tag covers the header as well as the contents, so this fires
                // for a corrupted chunk and for one that has been moved to a
                // different offset alike.
                fail("chunk " + std::to_string(header.counter) +
                     " failed authentication; it was corrupted or tampered with");
            }
            if (produced != header.plaintext_length) {
                fail("chunk " + std::to_string(header.counter) + " decrypted to the wrong length");
            }

            // pwrite at an explicit offset is what makes this safe to do from
            // several workers at once: there is no shared file position to race on.
            pwrite_all(target->fd.get(), plain.data(), produced, header.offset);
            target->written.fetch_add(produced);

            progress.advance(produced);

            ciphertext_buffers->release(std::move(sealed));
            plaintext_buffers->release(std::move(plain));
        });
    }

    if (pool != nullptr) pool->drain();

    finalise_outputs(files);

    if (options.verify_digests) {
        if (!offer.digests_present) {
            log::warn("--verify was asked for but the sender did not send digests");
        } else {
            verify_digests(offer, files, options.quiet);
        }
    }

    channel.write_empty(MessageType::TransferAck);
    channel.flush();

    result.bytes_received = progress.transferred();
    result.seconds = progress.elapsed_seconds();
    result.written_paths = std::move(paths);

    std::string suffix;
    if (log::enabled(log::Level::Info)) {
        suffix = std::string("over ") + transport_kind_name(channel.kind());
    }
    if (offer.encrypt_payload) {
        suffix += (suffix.empty() ? "" : ", ") + std::string(aead_algorithm_name(offer.algorithm));
    } else {
        suffix += (suffix.empty() ? "" : ", ") + std::string("not encrypted");
    }
    progress.finish(suffix);

    return result;
}

}  // namespace dz::client
