// The sending half of the data plane.

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <thread>

#include "dz/aead_pool.hpp"
#include "dz/client/pipeline.hpp"
#include "dz/client/progress.hpp"
#include "dz/client/transfer.hpp"
#include "dz/cpu.hpp"
#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/log.hpp"

namespace dz::client {
namespace {

/// Where a given chunk of the transfer comes from.
struct ChunkPlan {
    std::uint32_t file_index = 0;
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
};

/// Enumerate every chunk of every file, in order.
///
/// Built up front rather than computed as the transfer runs, so that the workers
/// need no shared cursor and the total is known in advance -- which is what lets
/// the ordered emitter tell when it is finished.
std::vector<ChunkPlan> plan_chunks(const Manifest& manifest, std::uint32_t chunk_size) {
    std::vector<ChunkPlan> plan;

    std::uint64_t estimate = (manifest.total_bytes / chunk_size) + manifest.files.size() + 1;
    plan.reserve(static_cast<std::size_t>(estimate));

    for (std::size_t i = 0; i < manifest.files.size(); ++i) {
        const LocalFile& file = manifest.files[i];

        // An empty file produces no chunks at all; the manifest entry alone tells
        // the receiver to create it.
        for (std::uint64_t offset = 0; offset < file.size; offset += chunk_size) {
            ChunkPlan chunk;
            chunk.file_index = static_cast<std::uint32_t>(i);
            chunk.offset = offset;
            chunk.length =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(chunk_size, file.size - offset));
            plan.push_back(chunk);
        }
    }
    return plan;
}

/// Send the manifest, sealed so that nothing on the path -- including the relay --
/// learns what is in it.
void send_offer(Channel& channel, const Manifest& manifest, const SessionKeys& keys,
                const std::string& own_username, const SendOptions& options) {
    TransferOffer offer;
    offer.sender_username = own_username;
    offer.display_name = manifest.display_name;
    offer.entries = to_wire_entries(manifest);
    offer.total_bytes = manifest.total_bytes;
    offer.encrypt_payload = options.encrypt;
    offer.algorithm = keys.algorithm;
    offer.chunk_size = options.chunk_size;
    offer.digests_present = options.compute_digests;

    if (options.compute_digests) {
        Manifest copy = manifest;
        compute_digests(copy, offer.entries);
    }

    std::vector<std::uint8_t> plain = offer.encode();
    std::vector<std::uint8_t> sealed =
        seal_standalone(keys.algorithm, keys.offer_key, kInfoOfferKey, plain.data(), plain.size());

    // The algorithm tag travels in the clear because the receiver needs it to open
    // the very message that would otherwise carry it.
    channel.write_frame(MessageType::Offer, sealed, static_cast<std::uint16_t>(keys.algorithm));
}

/// Wait for the receiver's answer.
TransferDecision await_decision(Channel& channel) {
    Frame frame;
    channel.read_expected(MessageType::Decision, frame);
    return TransferDecision::decode(frame.payload);
}

/// The plaintext path.
///
/// On direct TCP each chunk's payload is spliced from the page cache straight to
/// the socket with sendfile, so the only bytes this process touches are the 32
/// bytes of framing per megabyte. On the other tiers there is no descriptor to
/// splice to, so the payload is copied out of the mapping instead.
void send_plaintext(Channel& channel, const Manifest& manifest,
                    const std::vector<ChunkPlan>& plan, Progress& progress) {
    int socket_fd = channel.sendfile_fd();
    bool can_splice = socket_fd >= 0 && sendfile_supported();

    std::uint32_t current_file = 0xffffffffu;
    MappedFile mapped;
    Fd plain_fd;

    std::uint64_t counter = 0;

    for (const ChunkPlan& chunk : plan) {
        if (chunk.file_index != current_file) {
            current_file = chunk.file_index;
            const LocalFile& file = manifest.files[current_file];

            if (can_splice) {
                // sendfile needs a descriptor, not a mapping.
                int raw = ::open(file.source_path.c_str(), O_RDONLY | O_CLOEXEC);
                if (raw < 0) fail_errno("cannot open '" + file.source_path + "'");
                plain_fd.reset(raw);
#if defined(POSIX_FADV_SEQUENTIAL)
                (void)::posix_fadvise(plain_fd.get(), 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
            } else {
                mapped = MappedFile(file.source_path);
                mapped.advise_sequential();
            }
        }

        ChunkHeader header;
        header.file_index = chunk.file_index;
        header.plaintext_length = chunk.length;
        header.offset = chunk.offset;
        header.counter = counter++;

        std::uint8_t chunk_header[kChunkHeaderSize];
        encode_chunk_header(header, chunk_header);

        if (can_splice) {
            // The frame header has to declare the payload sendfile is about to
            // supply, not just the chunk header written here, or the receiver would
            // stop reading 1 MiB short and treat the file's bytes as the next frame.
            FrameHeader frame;
            frame.type = MessageType::Chunk;
            frame.flags = 1;
            frame.length = static_cast<std::uint32_t>(kChunkHeaderSize) + chunk.length;

            std::uint8_t frame_bytes[kFrameHeaderSize];
            encode_frame_header(frame, frame_bytes);

            // Both headers in one write, then the payload straight from the page
            // cache to the socket without entering this address space at all.
            channel.write_pair(frame_bytes, sizeof(frame_bytes), chunk_header,
                               sizeof(chunk_header));
            sendfile_all(socket_fd, plain_fd.get(), chunk.offset, chunk.length);
        } else {
            std::vector<std::uint8_t> payload(kChunkHeaderSize + chunk.length);
            std::memcpy(payload.data(), chunk_header, sizeof(chunk_header));
            std::memcpy(payload.data() + kChunkHeaderSize, mapped.data() + chunk.offset,
                        chunk.length);
            channel.write_frame(MessageType::Chunk, payload, /*flags=*/1);
        }

        progress.advance(chunk.length);
    }
}

/// The encrypted path: a worker pool sealing chunks and one writer emitting them in
/// order.
void send_encrypted(Channel& channel, const Manifest& manifest,
                    const std::vector<ChunkPlan>& plan, const SessionKeys& keys,
                    std::uint32_t chunk_size, unsigned worker_count, Progress& progress) {
    unsigned workers = (worker_count == 0) ? hardware_threads() : worker_count;

    // Each queued job holds a chunk-sized buffer, so the depths here are what bound
    // the pipeline's memory: roughly (queue depth + slots) times the chunk size.
    std::size_t queue_depth = static_cast<std::size_t>(workers) * 2;
    std::size_t slots = queue_depth + workers + 4;

    AeadPool pool(keys.algorithm, keys.send_key, workers, queue_depth);
    OrderedEmitter emitter(slots);
    BufferPool buffers(kChunkHeaderSize + Aead::sealed_size(chunk_size));

    // Every file mapped up front. A mapping costs address space rather than memory
    // -- the pages arrive on demand -- so this is cheap even for a large tree, and
    // it means a worker never has to open anything.
    std::vector<MappedFile> mappings;
    mappings.reserve(manifest.files.size());
    for (const LocalFile& file : manifest.files) {
        mappings.emplace_back(file.source_path);
        mappings.back().advise_sequential();

        if (mappings.back().size() != file.size) {
            fail_user("'" + file.source_path + "' changed size while being sent");
        }
    }

    // The writer runs on its own thread so the main thread can keep the pool fed.
    // If they shared a thread, submitting would stall whenever the socket blocked.
    std::exception_ptr writer_error;
    std::thread writer([&] {
        try {
            std::vector<std::uint8_t> chunk;
            while (emitter.consume(chunk)) {
                channel.write_frame(MessageType::Chunk, chunk.data(), chunk.size());

                // Counted here rather than at submission, so the figure the user
                // sees is bytes that have actually left rather than bytes queued.
                progress.advance(chunk.size() - kChunkHeaderSize - kAeadTagSize);
                buffers.release(std::move(chunk));
            }
            channel.flush();
        } catch (...) {
            writer_error = std::current_exception();
            // Unblock any worker waiting for a slot this thread will never free.
            emitter.abort(writer_error);
        }
    });

    try {
        for (std::uint64_t index = 0; index < plan.size(); ++index) {
            const ChunkPlan& chunk = plan[index];
            const std::uint8_t* source = mappings[chunk.file_index].data() + chunk.offset;

            pool.submit([&, index, chunk, source](Aead& aead) {
                ChunkHeader header;
                header.file_index = chunk.file_index;
                header.plaintext_length = chunk.length;
                header.offset = chunk.offset;
                // The chunk's own index is its nonce counter, which is what makes
                // the chunk self-describing and therefore reorderable.
                header.counter = index;

                std::vector<std::uint8_t> out = buffers.acquire();
                encode_chunk_header(header, out.data());

                // The nonce is the session's random prefix and this chunk's
                // counter, so no (key, nonce) pair is ever reused -- the one
                // mistake that would break either AEAD outright.
                std::uint8_t nonce[kAeadNonceSize];
                build_nonce(keys.send_nonce_prefix, header.counter, nonce);

                // The header is the associated data, so the tag covers where this
                // chunk claims to belong as well as its contents.
                std::size_t written =
                    aead.seal(nonce, out.data(), kChunkHeaderSize, source, chunk.length,
                              out.data() + kChunkHeaderSize);
                out.resize(kChunkHeaderSize + written);

                if (!emitter.publish(index, std::move(out))) return;
            });
        }

        pool.drain();
        emitter.set_total(plan.size());
    } catch (...) {
        emitter.abort(std::current_exception());
        writer.join();
        throw;
    }

    writer.join();
    if (writer_error != nullptr) std::rethrow_exception(writer_error);
}

}  // namespace

SendResult send_transfer(Channel& channel, const Manifest& manifest, const SessionKeys& keys,
                         const std::string& own_username, const SendOptions& options) {
    if (!options.encrypt && channel.kind() == TransportKind::ServerRelay) {
        // The relay is the operator's machine. Sending plaintext through it would
        // hand the file contents to a third party, which is not what somebody
        // asking for speed on their own network meant.
        fail_user("this transfer has to go through the rendezvous server, so it cannot be "
                  "sent unencrypted. Remove --no-encrypt and try again.");
    }

    send_offer(channel, manifest, keys, own_username, options);

    TransferDecision decision = await_decision(channel);
    if (!decision.accepted) {
        fail_user(decision.reason.empty() ? "the other side declined the transfer"
                                         : ("the other side declined: " + decision.reason));
    }

    std::vector<ChunkPlan> plan = plan_chunks(manifest, options.chunk_size);

    std::string label = "sending " + manifest.display_name;
    Progress progress(label, manifest.total_bytes, !options.quiet);

    if (options.encrypt) {
        send_encrypted(channel, manifest, plan, keys, options.chunk_size, options.workers,
                       progress);
    } else {
        send_plaintext(channel, manifest, plan, progress);
    }

    channel.write_empty(MessageType::TransferEnd);
    channel.flush();

    // Wait for the receiver to confirm it has the files on disk, so "sent" means
    // the same thing to both sides.
    Frame frame;
    channel.read_expected(MessageType::TransferAck, frame);

    SendResult result;
    result.bytes_sent = progress.transferred();
    result.seconds = progress.elapsed_seconds();
    result.output_directory = decision.output_directory;

    std::string suffix = std::string("over ") + transport_kind_name(channel.kind());
    if (options.encrypt) {
        suffix += std::string(", ") + aead_algorithm_name(keys.algorithm);
    } else {
        suffix += ", not encrypted";
    }
    progress.finish(suffix);

    return result;
}

}  // namespace dz::client
