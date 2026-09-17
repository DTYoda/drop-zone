// A pool of worker threads, each owning its own AEAD context.
//
// This is where the throughput work in drop-zone actually lives. AES-256-GCM on
// one core runs at a few gigabytes a second, which sounds like plenty until a
// 25 Gb link or a fast NVMe array is on the other side; and ChaCha20-Poly1305 on
// a machine without AES instructions is several times slower again. Because
// every chunk is an independent AEAD message with its counter carried in its
// header, chunks have no ordering dependency on each other and the work spreads
// across cores linearly.
//
// Two design points matter:
//
//  * Each worker constructs one dz::Aead and keeps it for its lifetime, so the
//    key schedule is built once per worker rather than once per chunk.
//  * The job queue is bounded. An unbounded queue would let a fast reader
//    allocate a buffer per chunk faster than the workers retire them, so a
//    transfer of a large file would balloon into memory; blocking the producer
//    instead is exactly the back-pressure the pipeline wants.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "dz/crypto.hpp"

namespace dz {

class AeadPool {
public:
    /// A unit of work. Receives the calling worker's own cipher context.
    using Job = std::function<void(Aead&)>;

    /// Start `workers` threads, each with its own context over `key`.
    /// `queue_depth` jobs may be waiting before submit() starts blocking.
    AeadPool(AeadAlgorithm algorithm, const Key& key, unsigned workers, std::size_t queue_depth);
    ~AeadPool();

    AeadPool(const AeadPool&) = delete;
    AeadPool& operator=(const AeadPool&) = delete;

    unsigned worker_count() const { return static_cast<unsigned>(workers_.size()); }
    AeadAlgorithm algorithm() const { return algorithm_; }

    /// Queue a job, blocking while the queue is full. Rethrows immediately if a
    /// previously submitted job has already failed, so a transfer stops at the
    /// first error instead of queueing thousands more chunks behind it.
    void submit(Job job);

    /// Wait for every submitted job to finish, then rethrow the first exception
    /// any of them raised.
    void drain();

    /// Stop the workers. Called by the destructor; safe to call twice.
    void shutdown();

private:
    void run_worker(const Key& key);
    void record_failure(std::exception_ptr error);

    AeadAlgorithm algorithm_;
    std::size_t queue_depth_;

    std::mutex mutex_;
    std::condition_variable work_available_;
    std::condition_variable space_available_;
    std::condition_variable all_idle_;

    std::deque<Job> queue_;
    std::size_t active_jobs_ = 0;
    bool stopping_ = false;
    std::exception_ptr first_error_;

    std::vector<std::thread> workers_;
};

}  // namespace dz
