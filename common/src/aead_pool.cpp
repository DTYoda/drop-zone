#include "dz/aead_pool.hpp"

#include <utility>

namespace dz {

AeadPool::AeadPool(AeadAlgorithm algorithm, const Key& key, unsigned workers,
                   std::size_t queue_depth)
    : algorithm_(algorithm), queue_depth_(queue_depth == 0 ? 1 : queue_depth) {
    if (workers == 0) workers = 1;

    workers_.reserve(workers);
    for (unsigned i = 0; i < workers; ++i) {
        // The key is copied into each thread's own Aead inside run_worker, so a
        // worker never touches another worker's cipher state.
        workers_.emplace_back([this, key] { run_worker(key); });
    }
}

AeadPool::~AeadPool() { shutdown(); }

void AeadPool::submit(Job job) {
    std::unique_lock<std::mutex> lock(mutex_);

    space_available_.wait(lock, [this] {
        return queue_.size() < queue_depth_ || stopping_ || first_error_ != nullptr;
    });

    if (first_error_ != nullptr) {
        std::exception_ptr error = first_error_;
        lock.unlock();
        std::rethrow_exception(error);
    }
    if (stopping_) return;

    queue_.push_back(std::move(job));
    work_available_.notify_one();
}

void AeadPool::drain() {
    std::unique_lock<std::mutex> lock(mutex_);
    all_idle_.wait(lock, [this] { return (queue_.empty() && active_jobs_ == 0) || stopping_; });

    if (first_error_ != nullptr) {
        std::exception_ptr error = first_error_;
        // Cleared so that a caller which recovers from this failure and reuses
        // the pool is not handed the same stale error again.
        first_error_ = nullptr;
        lock.unlock();
        std::rethrow_exception(error);
    }
}

void AeadPool::shutdown() {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (stopping_) return;
        stopping_ = true;
    }
    work_available_.notify_all();
    space_available_.notify_all();
    all_idle_.notify_all();

    for (std::thread& worker : workers_) {
        if (worker.joinable()) worker.join();
    }
    workers_.clear();
}

void AeadPool::run_worker(const Key& key) {
    // One context per worker, built once. This is the whole reason the pool owns
    // threads rather than being a bare task queue.
    Aead aead(algorithm_, key);

    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            work_available_.wait(lock, [this] { return !queue_.empty() || stopping_; });

            if (queue_.empty()) return;  // stopping_ with nothing left to do.

            job = std::move(queue_.front());
            queue_.pop_front();
            ++active_jobs_;
        }
        space_available_.notify_one();

        std::exception_ptr error;
        try {
            job(aead);
        } catch (...) {
            error = std::current_exception();
        }

        {
            std::lock_guard<std::mutex> guard(mutex_);
            --active_jobs_;
            if (error != nullptr && first_error_ == nullptr) first_error_ = error;
            if (queue_.empty() && active_jobs_ == 0) all_idle_.notify_all();
            if (error != nullptr) {
                // Wake the producer so it stops queueing work behind a failure.
                space_available_.notify_all();
                all_idle_.notify_all();
            }
        }
    }
}

void AeadPool::record_failure(std::exception_ptr error) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (first_error_ == nullptr) first_error_ = error;
}

}  // namespace dz
