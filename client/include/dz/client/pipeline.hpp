// The two pieces of plumbing that let encryption run on every core without
// letting the transfer come out in the wrong order.
//
// A chunk can be encrypted by any worker, because each one is an independent AEAD
// message. But the stream they go into is ordered, so something has to put them
// back in sequence between the worker pool and the socket. OrderedEmitter is that
// something: workers publish chunks by index, one writer thread consumes them in
// index order, and a fixed number of slots bounds how far ahead the workers may
// run.
//
// BufferPool exists because the alternative -- allocating a chunk-sized buffer per
// chunk -- means a megabyte of malloc and free for every megabyte transferred, and
// at multi-gigabyte-per-second rates that allocator traffic is measurable.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <mutex>
#include <vector>

namespace dz::client {

/// A recycling pool of byte buffers.
class BufferPool {
public:
    explicit BufferPool(std::size_t buffer_size) : buffer_size_(buffer_size) {}

    /// Take a buffer, resized to the pool's buffer size.
    std::vector<std::uint8_t> acquire();

    /// Give a buffer back. Buffers larger than the pool's size are dropped rather
    /// than kept, so one unusually large chunk does not permanently inflate the
    /// pool's footprint.
    void release(std::vector<std::uint8_t>&& buffer);

private:
    std::mutex mutex_;
    std::vector<std::vector<std::uint8_t>> free_;
    std::size_t buffer_size_;
};

/// Reassembles out-of-order completions into an ordered stream.
///
/// The slot count is the bound on lookahead: a worker holding chunk N cannot
/// publish it until the writer has consumed chunk N - capacity, so memory use is
/// capacity multiplied by the chunk size regardless of how large the transfer is
/// or how many workers there are.
class OrderedEmitter {
public:
    explicit OrderedEmitter(std::size_t capacity);

    /// Publish the chunk at `index`. Blocks while the writer is more than
    /// `capacity` chunks behind. Returns false once the emitter has been aborted,
    /// so a worker does not sit waiting for a writer that has already failed.
    bool publish(std::uint64_t index, std::vector<std::uint8_t>&& data);

    /// Take the next chunk in order. Blocks until it is available. Returns false
    /// when every chunk has been consumed, and rethrows if a publisher or the
    /// writer failed.
    bool consume(std::vector<std::uint8_t>& out);

    /// Declare how many chunks there will be in total. Called once the producer
    /// has submitted them all, which is what lets consume() know when to stop.
    void set_total(std::uint64_t total);

    /// Wake everybody with an error, so neither side of the queue can hang after
    /// the other has given up.
    void abort(std::exception_ptr error);

private:
    struct Slot {
        std::vector<std::uint8_t> data;
        bool ready = false;
    };

    std::mutex mutex_;
    std::condition_variable slot_ready_;
    std::condition_variable slot_free_;

    std::vector<Slot> slots_;
    std::uint64_t next_to_consume_ = 0;
    std::uint64_t total_ = 0;
    bool total_known_ = false;
    std::exception_ptr error_;
};

}  // namespace dz::client
