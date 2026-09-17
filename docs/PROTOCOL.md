# Protocol

Wire format and conversation for drop-zone v1. The structures in
`common/include/dz/protocol.hpp` are the machine-readable copy of this file.

Nothing here is TLS. The rendezvous server is an untrusted introduction service:
it learns a username, two public keys and a candidate address list for the
duration of a socket, forwards them, and forgets them when the socket closes.
Authentication is between the two peers, using the receiver's public password
and each peer's Ed25519 identity.

## Framing

Every message on a TCP connection — control or data — is an 8-byte header
followed by exactly `length` bytes of payload:

```
offset  size  field
0       1     version     1
1       1     type        MessageType
2       2     flags       little-endian, type-specific
4       4     length      payload bytes that follow, little-endian
```

Maximum payload is 2 MiB. A header that names a larger length is refused before
any allocation. Bulk file data travels in 1 MiB chunks plus AEAD overhead, so
the cap is headroom rather than a working size.

UDP uses its own 24-byte datagram header, documented under [Reliable UDP](#reliable-udp).
Reflexive address probes are a separate four-byte datagram, documented under
[Reflexive discovery](#reflexive-discovery).

## Control-plane messages

Sent on the long-lived TCP connection each client opens to the rendezvous
server.

| Type | Value | Direction | Purpose |
| --- | --- | --- | --- |
| ClientHello | 1 | client → server | Role, username, identity key, ephemeral X25519, listen ports, local candidates |
| ServerHello | 2 | server → client | Claim result, reflexive addresses, idle timeout |
| SendRequest | 3 | sender → server | Target username, password proof, identity signature, optional transport hint |
| Incoming | 4 | server → receiver | The sender's introduction |
| Accept | 5 | receiver → server | The receiver's half of the introduction |
| Reject | 6 | either way | Decline, or a server refusal. Payload is a UTF-8 reason. |
| Matched | 7 | server → sender | The receiver's introduction |
| RelayOpen | 8 | both ways | Ask the server to forward; the server echoes it once both sides have asked |
| RelayData | 9 | both ways | Opaque bytes the server copies without inspecting |
| RelayClose | 10 | both ways | Orderly end of a relayed stream |
| KeepAlive | 11 | client → server | Holds the claim and the NAT mapping. Default idle timeout is 300 s; clients send every 25 s. |
| Bye | 12 | client → server | Orderly hang-up |
| GroupQuery | 13 | client → server | Does this ephemeral group currently exist? |
| GroupStatus | 14 | server → client | Exists, and how many members |
| GroupJoin | 15 | receiver → server | Create or join with a password verifier |
| GroupResult | 16 | server → client | Created, joined, or why not |
| GroupSendRequest | 17 | sender → server | Ask for currently idle members |
| GroupRoster | 18 | server → sender | Usernames of members currently accepting |

A receiver may send a second ClientHello on the same connection to refresh its
ports and ephemeral key between transfers without dropping the username claim
or group membership.

## Groups

Groups are ephemeral and storage-free, like username claims. A receiver that
runs `accept --group=NAME` still claims its personal username, then creates or
joins `NAME`. Membership lasts only while that control connection is open: the
last member to disconnect destroys the group and its verifier.

The first joiner's public password becomes the group password. Both peers stretch
it with scrypt using the **group name** as salt (not a username), then the
joiner sends `verifier = HMAC(password_key, "drop-zone/v1 group verifier/" +
name)`. The server stores only that verifier. Later joiners must present the
same verifier; the server never sees the password.

`send --group=NAME` asks for a `GroupRoster` of members currently in
`ReceiverIdle`, then runs one ordinary 1:1 introduction and transfer per
member in parallel. Each `SendRequest` carries an optional trailing
`group_name` so the receiver knows to check the group password proof
(`"drop-zone/v1 group sender proof"` / `"drop-zone/v1 group receiver proof"`,
including the group name) rather than the personal one. Personal
`send -t USER` keeps working on the same accept session.

Membership is capped at 32. An empty roster is a user-visible failure: nobody
in the group is accepting right now.

## Handshake

### 1. Claim

The receiver connects, sends ClientHello with `role = Receiver`, and the server
either grants the username or replies that it is already held. Usernames are
`[a-z0-9._-]{1,64}`. There is no account registry: the name belongs to whoever
is currently connected.

The sender connects, sends ClientHello with `role = Sender`, and does not claim
anything. Its username is only a label the receiver will see.

### 2. Introduction

The sender sends SendRequest:

- `proof` — HMAC-SHA256 under the public-password key, over
  `"drop-zone/v1 sender proof"`, both usernames, the sender's X25519 public key
  and the sender's Ed25519 public key. Each field is length-prefixed so two
  different splits of the same bytes cannot collide.
- `signature` — Ed25519 over the same bytes, proving the sender holds the
  private half of the identity it presented.

The server does not check the proof. It cannot: it has never seen the password.
It rate-limits introduction attempts per hashed address and forwards the
request to the receiver as Incoming.

The receiver:

1. Stretches the public password with scrypt (N=2¹⁵, r=8, p=1, salt
   `"drop-zone/v1 public-password/" + username`) into the MAC key. This happens
   once at start-up, not per request.
2. Recomputes the sender's proof and compares it in constant time. A mismatch
   is a Reject, after a 250 ms pause.
3. Pins the sender's identity key, or refuses if it has changed since last time.
4. Computes its own proof over both peers' keys
   (`"drop-zone/v1 receiver proof"` plus both usernames and both key pairs) and
   signs it.
5. Sends Accept. The server forwards that as Matched to the sender, who
   performs the symmetric checks.

A server that swapped either X25519 key would have to forge a MAC under a key
derived from the public password. That is the MITM resistance; see
[SECURITY.md](SECURITY.md) for what it does and does not cover.

### 3. Session keys

Both peers do X25519 with the ephemeral keys they advertised. The shared secret
is expanded with HKDF-SHA256, using the transcript hash as salt:

| Info string | Output |
| --- | --- |
| `drop-zone/v1 data sender->receiver` | AEAD key, sender to receiver |
| `drop-zone/v1 data receiver->sender` | AEAD key, the other way |
| `drop-zone/v1 nonce sender->receiver` | 4-byte nonce prefix |
| `drop-zone/v1 nonce receiver->sender` | 4-byte nonce prefix |
| `drop-zone/v1 sealed offer` | Key that seals the manifest |
| `drop-zone/v1 transport handshake` | Key that authenticates the TCP and UDP punches |

The transcript hash covers both usernames, both ephemeral keys, both identity
keys, and both proofs, under `"drop-zone/v1 transcript signature"`. Derived
keys therefore depend on the password as well as Diffie-Hellman.

Each chunk's 12-byte nonce is the 4-byte prefix followed by the chunk's 8-byte
counter in little endian. Counters start at zero in each direction and never
repeat for the life of the key.

## Transport ladder

Both peers walk the same ladder with the same time budget, so they arrive at
the same tier. A `--force-transport` on the sender is forwarded in SendRequest
and Incoming so the receiver runs the same choice.

A tier only counts as succeeded once a two-way handshake authenticated under
the transport key has completed over it. Connecting to a listening port is not
enough: any host that happened to connect would otherwise be adopted as the
peer.

### Tier 1 — direct TCP

Default budget 1500 ms. The sender dials every candidate; the receiver listens
on the port it advertised. (Both sides connecting at once deadlocks behind
many NATs, so the roles are not symmetric.) The first connection to complete
the transport handshake wins. On this tier with `--no-encrypt`, the sender
can `sendfile` from the page cache to the socket.

### Tier 2 — hole-punched UDP

Default budget 4000 ms. Both peers send authenticated probes to every candidate
from the UDP socket whose mapping the server already observed. Most NATs
forward an inbound packet from an address they have just seen an outbound
packet to, so the two streams of probes open the path for each other.

Probes are distinct from the reliable stream. A sender probe cannot be
reflected as a receiver answer: the two directions MAC different tags
(`drop-zone/v1 udp punch sender` / `... receiver`).

Once both sides have a verified reply, they run the reliable UDP protocol below.

### Tier 3 — server relay

Reached only when both peers send RelayOpen. The server waits for the second
ask so it does not strand a peer still punching. It then forwards RelayData
frames verbatim. Payload per frame is 256 KiB, well under the 2 MiB cap, so
the server's per-connection output buffer holds several frames and its
back-pressure can act smoothly.

`--no-encrypt` is refused on this tier: the bytes would otherwise be the file.

## Reflexive discovery

A peer behind NAT cannot see the address and port its own packets appear to
come from, and hole punching needs exactly that. The client sends a four-byte
UDP datagram `DZR1` to the server. The server replies `DZR2` plus the encoded
source endpoint and records nothing. The exchange is stateless: the reply is
computed from the packet's own source address.

## Reliable UDP

Custom, not QUIC. One bidirectional stream, one path, no crypto of its own —
the AEAD already covering the payload is end to end, and adding a second layer
would cost a copy on the hot path for no extra confidentiality.

Datagram header, 24 bytes:

```
offset  size  field
0       2     magic       "DQ"
2       1     type        data / ack / handshake / fin
3       1     flags
4       4     sequence    little-endian
8       4     ack         next sequence the sender has delivered
12      8     ack_bits    selective ACK bitmap for the 64 sequences before `ack`
20      2     length      payload bytes that follow
22      2     reserved
```

Payload is 1200 bytes, inside a typical 1280-byte IPv6 minimum MTU after
headers.

Reliability:

- Selective ACK via the 64-bit bitmap. A hole in the window is visible without
  waiting for the retransmission timer.
- RTO per RFC 6298 (srtt / rttvar), with a 5 ms floor rather than TCP's 1 s —
  both ends are this program, SACK recovers most loss, and a floor far above
  the real RTT turns each loss the bitmap cannot see into a stall.
- NewReno congestion control, cwnd capped at 2048 packets (~2.4 MiB in flight).
- Token-bucket pacing at cwnd packets per RTT, burst capped at 48. Without
  this a window refill overruns the receiver's socket buffer (often ~208 KiB
  on Linux) and the resulting tail loss costs a full RTO.
- `sendmmsg` / `recvmmsg` on Linux, with the batch scratch allocated once.

The receive window is enforced by not draining the reorder buffer once 8 MiB
is delivered but unread. The acknowledged sequence stops advancing, the
sender's window fills, and it stops. There is no window field in the header.

## Data plane

Sent over whichever Channel the ladder returned. Same framing as the control
plane.

| Type | Value | Purpose |
| --- | --- | --- |
| Offer | 32 | Sealed manifest. Flags hold the AEAD algorithm tag, because the receiver needs it to open the message that would otherwise carry it. |
| Decision | 33 | Accept or reject, plus the output directory for the sender's log. |
| Chunk | 34 | One chunk. Flags = 1 means plaintext (the `--no-encrypt` path). |
| TransferEnd | 35 | The sender has emitted every chunk. |
| TransferAck | 36 | The receiver has fsync'd every file. "Sent" means the same thing on both sides. |
| Abort | 37 | Either side giving up. Payload is a reason. |

### Manifest

A TransferOffer names every file: a relative path, size, mode bits (no owner,
no timestamp), and an optional SHA-256. Paths are sanitised before anything is
created: no absolute path, no `..`, no empty component, no backslash.

The offer is sealed under the offer key. The server, if it is relaying, sees a
blob.

### Chunks

1 MiB, or the tail of a file. Header, 24 bytes, is the AEAD associated data:

```
offset  size  field
0       4     file index
4       4     plaintext length
8       8     file offset
16      8     nonce counter
```

Authenticating the header is what stops an attacker from moving a chunk to a
different offset or file: the ciphertext would still decrypt, but the tag
would not verify against the altered header.

Chunks are independent AEAD messages. Workers encrypt and decrypt them in
parallel; an ordered emitter puts them back on the wire in counter order. The
receiver may `pwrite` them out of order into a preallocated file.

Empty files produce no chunks. The manifest entry alone tells the receiver to
create them.

## What the server never sees

- Passwords. Proofs are MACs; the key never leaves the two clients.
- Filenames and file bytes. The offer is sealed; chunks are sealed (or refused
  on the relay if they would not be).
- A durable record of anyone. Claims and pairings are in-process maps. A
  username is released the moment its socket closes. `RLIMIT_CORE` is 0 so a
  crash cannot write the table to disk. Log lines use an opaque connection
  id, never an address or a username.
