# Performance

drop-zone is built so the CPU-bound work (AEAD) and the I/O-bound work
(sockets, disk) do not trip over each other, and so a single Homebrew bottle
runs the fast cipher on hardware that has it without `SIGILL` on hardware
that does not.

Numbers at the bottom were measured on the machine that built this tree.
They are loopback figures — they show the implementation's ceiling, not
what a WAN path will do. Re-run `tests/e2e_loopback.sh` on your own
hardware before treating them as a promise.

## Where the time goes

A transfer is three pipelines sharing one process:

1. **Read.** Encrypted sends `mmap` the source and `posix_madvise` /
   `FADV_SEQUENTIAL` so readahead runs ahead of the workers. Plaintext
   direct-TCP uses `sendfile`, so the file bytes never enter this address
   space at all; the process touches 32 bytes of framing per megabyte.
2. **Seal / open.** `AeadPool` — one OpenSSL `EVP_CIPHER_CTX` per worker,
   kept for the life of the transfer, so the key schedule is built once.
   Jobs are 1 MiB independent AEAD messages. The queue is bounded: an
   unbounded one would let a fast reader allocate faster than the workers
   retire, and a large file would balloon into memory.
3. **Emit.** Workers finish out of order. `OrderedEmitter` has a fixed
   number of slots and a single writer thread that consumes them in
   counter order onto the socket. The slot count is the bound on
   lookahead, so memory use is `slots × chunk size` regardless of how
   large the transfer is.

On receive the inverse: a worker pool opens chunks, `pwrite` commits them
at the offset the header names (no shared file position), `fsync` once per
file before TransferAck.

## Cipher dispatch

`common/src/cpu.cpp` looks at the running CPU, not the build flags.

| CPU | Cipher |
| --- | --- |
| AES-NI + PCLMULQDQ (x86), or FEAT_AES + FEAT_PMULL (arm64) | AES-256-GCM |
| Anything else | ChaCha20-Poly1305 |

Both halves are required before AES-GCM is preferred. AES instructions
without carry-less multiply leave GHASH in software, and a software GHASH
is slower than all of ChaCha20-Poly1305.

VAES is reported by `drop-zone status` and used internally by libcrypto
when present; drop-zone does not dispatch on it itself. `-march=native`
is off by default for the same reason: a bottle built with AVX-512 would
crash on an older CPU, and run-time dispatch already takes the fast path
where it exists.

OpenSSL's assembly is used rather than hand-written intrinsics. The
throughput work is the layer above: independent chunks, a reused context
per worker, and no extra copies.

## Transport ceilings

**Direct TCP** is the fast path. The kernel does reliability, and with
`--no-encrypt` `sendfile` removes the userspace copy. Encrypted TCP is
limited by the AEAD pool and by how fast the writer can `write` 1 MiB
frames; on loopback that is still multiple gigabytes per second on a
modern desktop.

**Hole-punched UDP** runs a userspace reliable layer: NewReno, RFC 6298
RTO, a token-bucket pacer, `sendmmsg`/`recvmmsg`. The knobs that dominate
loopback throughput:

- `max_cwnd = 2048` packets × 1200 B ≈ 2.4 MiB in flight. Enough for a
  400 Mb/s path with a 50 ms RTT. Raising it further mostly overruns the
  kernel socket buffer.
- `max_burst = 48` packets. Linux's default UDP receive buffer is often
  ~208 KiB, about 170 datagrams. Dumping more than that between two of
  the receiver's drains loses the tail of the window, where the SACK
  bitmap cannot see it, and recovery costs a full RTO.
- Pacing at cwnd packets per RTT, with `ppoll` waits in microseconds
  rather than a 1 ms poll floor, so a window refill is spread instead of
  dumped.
- Batch scratch for `recvmmsg` is allocated once. Allocating it per call
  was measured to cost more than the syscall it prepared.

**Server relay** is two legs of TCP through the daemon. Each RelayData
frame carries 256 KiB. The server pauses reading a source whose peer has
more than 4 MiB queued, and resumes below 1 MiB, so a fast sender cannot
fill the daemon's memory. Shards communicate through a mutex-protected
output buffer and a wake pipe; `Connection::state` and the relay peer
pointer are published with acquire/release so the first RelayData after
open cannot land on a connection the other shard has not yet marked
Relaying.

## Framing and copies

The C prototype scanned for `"\n\n"` in a 1 KiB buffer. The rewrite uses
an explicit length, so a receiver sizes its read in one call and a file
byte that happens to be a newline cannot truncate a message.

Copies that were removed on the hot path:

- Config and identity files go through `write()`, not `send()`. `send()`
  on a regular file fails with `ENOTSOCK`.
- Reliable UDP data packets are pointed at from the retransmission buffer
  rather than copied into a staging buffer for `sendmmsg`.
- Plaintext TCP payload is spliced with `sendfile`; only the 8-byte frame
  header and 24-byte chunk header are written from userspace.

## Loopback measurements

Machine: recorded by the cloud builder that produced this tree. Loopback
only; `DROP_ZONE_ALLOW_LOOPBACK=1`. Payload is `/dev/urandom` so the AEAD
is not compressing zeros.

| Path | Encryption | Size | Throughput | Notes |
| --- | --- | --- | --- | --- |
| direct TCP | AES-256-GCM | 64 MiB | *(filled by e2e)* | |
| direct TCP | none (sendfile) | 64 MiB | *(filled by e2e)* | |
| hole-punched UDP | AES-256-GCM | 64 MiB | *(filled by e2e)* | |
| hole-punched UDP | none | 64 MiB | *(filled by e2e)* | |
| server relay | AES-256-GCM | 64 MiB | *(filled by e2e)* | |
| auto ladder | AES-256-GCM | 64 MiB | *(filled by e2e)* | should pick TCP on loopback |

A multi-GiB run per tier is in the verification notes below the table
once `tests/e2e_loopback.sh build <size>` has been run at a larger size.

To reproduce:

```sh
make
./tests/e2e_loopback.sh build 64
./tests/e2e_loopback.sh build 2048    # multi-GiB, several minutes
```

`drop-zone status` prints the cipher this CPU will use and whether
`sendfile` is available.
