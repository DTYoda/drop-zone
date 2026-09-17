#include "dz/client/pipeline.hpp"

#include <utility>

namespace dz::client {

// ---------------------------------------------------------------------------
// BufferPool
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> BufferPool::acquire() {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!free_.empty()) {
            std::vector<std::uint8_t> buffer = std::move(free_.back());
            free_.pop_back();
            buffer.resize(buffer_size_);
            return buffer;
        }
    }

    // Allocated outside the lock: a fresh buffer is the slow path and there is no
    // reason to make every other thread wait for the allocator.
    std::vector<std::uint8_t> buffer;
    buffer.resize(buffer_size_);
    return buffer;
}

void BufferPool::release(std::vector<std::uint8_t>&& buffer) {
    if (buffer.capacity() < buffer_size_) return;

    std::lock_guard<std::mutex> guard(mutex_);
    // Keeping a bounded number of buffers is enough: the pipeline only ever has
    // as many in flight as the emitter has slots.
    if (free_.size() < 64) free_.push_back(std::move(buffer));
}

// ---------------------------------------------------------------------------
// OrderedEmitter
// ---------------------------------------------------------------------------

OrderedEmitter::OrderedEmitter(std::size_t capacity) : slots_(capacity == 0 ? 1 : capacity) {}

bool OrderedEmitter::publish(std::uint64_t index, std::vector<std::uint8_t>&& data) {
    std::unique_lock<std::mutex> lock(mutex_);

    // Wait until this index is inside the window the writer has room for. The
    // chunk the writer is actually waiting for always satisfies this immediately,
    // so a worker holding it can never be the one that blocks -- which is what
    // rules out a deadlock between the pool and the writer.
    slot_free_.wait(lock, [this, index] {
        return error_ != nullptr || index < next_to_consume_ + slots_.size();
    });

    if (error_ != nullptr) return false;

    Slot& slot = slots_[index % slots_.size()];
    slot.data = std::move(data);
    slot.ready = true;

    slot_ready_.notify_all();
    return true;
}

bool OrderedEmitter::consume(std::vector<std::uint8_t>& out) {
    std::unique_lock<std::mutex> lock(mutex_);

    slot_ready_.wait(lock, [this] {
        if (error_ != nullptr) return true;
        if (total_known_ && next_to_consume_ >= total_) return true;
        return slots_[next_to_consume_ % slots_.size()].ready;
    });

    if (error_ != nullptr) {
        std::exception_ptr error = error_;
        lock.unlock();
        std::rethrow_exception(error);
    }

    if (total_known_ && next_to_consume_ >= total_) return false;

    Slot& slot = slots_[next_to_consume_ % slots_.size()];
    out = std::move(slot.data);
    slot.ready = false;
    ++next_to_consume_;

    slot_free_.notify_all();
    return true;
}

void OrderedEmitter::set_total(std::uint64_t total) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        total_ = total;
        total_known_ = true;
    }
    slot_ready_.notify_all();
}

void OrderedEmitter::abort(std::exception_ptr error) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (error_ == nullptr) error_ = error;
    }
    slot_ready_.notify_all();
    slot_free_.notify_all();
}

}  // namespace dz::client
