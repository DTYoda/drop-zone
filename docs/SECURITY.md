# Security

What drop-zone protects, what it does not, and why the public password is the
weakest link in a design that otherwise keeps the rendezvous server out of the
trusted computing base.

## Threat model

Assume:

- The network is hostile. An on-path attacker can read, drop, delay, replay
  and inject packets.
- The rendezvous server is hostile or compromised. It can swap introductions,
  log everything it sees, and try to join a transfer as a peer.
- The two endpoints are honest and their copies of drop-zone are not tampered
  with.
- An attacker may later steal `~/.config/drop-zone/` from disk.

Do not assume:

- The public password is a high-entropy secret. Users pick it, tell it to
  people they want to receive from, and reuse it. The rest of this file is
  largely about what that implies.
- Physical security of an unlocked session. `drop-zone accept --yes` will
  take files from anyone who knows the public password and whose identity
  pin matches.

## What an introduction proves

A sender who produces a valid proof of the receiver's public password has
demonstrated knowledge of that password, and has bound that knowledge to
**this** pair of ephemeral X25519 keys. The receiver's matching proof binds
the same password to both keys at once.

A server that swapped either ephemeral key to sit in the middle would have to
forge a MAC under a key it does not have. The introduction is therefore
MITM-resistant even though it passes through an untrusted party.

After the proofs, both peers do X25519 and mix the transcript — including
both proofs — into HKDF. Session keys therefore depend on the password as
well as Diffie-Hellman. Recovering a later-recorded X25519 private key is
not enough to decrypt a captured transfer.

Each peer also signs its proof under its long-term Ed25519 identity. That is
what makes the pin in `known_peers` worth keeping: the next session must
present the same key, and must still know the password.

## Trust on first use

The server has no accounts, so it cannot tell you that today's "alice" is
last week's alice. A username belongs to whoever claims it while nobody else
is holding it.

`known_peers` closes that gap the way SSH's `known_hosts` does. The first
time a username is seen, its Ed25519 public key is recorded. Every later
session checks the key it presents against that record. A mismatch is a hard
failure: either the peer reinstalled, or somebody else has the username.

Without the pin, someone who learned a public password could claim the
username while its owner was offline and receive files in their place. With
the pin they would also need the identity key.

The pin does nothing the first time. A sender who has never talked to alice
will accept whoever currently answers as alice, provided they know the
public password. That is the TOFU caveat, identical to SSH's.

## The public password is guessable

This is the residual risk the rest of the design cannot remove.

The password is chosen by a person, shared with the people they want to
receive from, and stretched with scrypt (N=2¹⁵, r=8, p=1 — about 32 MiB and
100 ms) into the MAC key. An attacker who captures a single SendRequest can
take that proof offline and try dictionaries against it. scrypt makes each
guess expensive rather than trivial; it does not make a short or reused
password safe.

Salt is `"drop-zone/v1 public-password/" + username`, not random. Both peers
must compute the key without an extra round trip, and the receiver must
compute it once at start-up rather than running scrypt for every incoming
request — which would otherwise be a trivial way to pin its CPU. The cost is
that the same password under the same username always yields the same key.
Two captured proofs for the same user can be recognised as such. They cannot
be reversed any faster for it.

Mitigations that **are** in place:

- The server rate-limits introduction attempts per salted-hash of the source
  address (IPv4 address, IPv6 /64), so online guessing through the server is
  slow. The salt lives only in the process's memory; the logs never contain
  the address itself.
- The receiver pauses 250 ms on a wrong proof, even if the attacker has many
  addresses to spread guesses across.
- A stolen proof is bound to one session's keys. Replaying it into another
  introduction fails.
- After the first successful transfer, TOFU pinning means a guesser who
  later claims the username still cannot impersonate the recorded identity.

Mitigations that are **not** in place, on purpose:

- The server does not check the proof. Checking it would require the server
  to know the password, or a verifier for it, which is exactly the storage
  the design refuses to have.
- There is no PAKE. A PAKE would close the offline-dictionary window at the
  cost of another round trip and a larger protocol; v1 keeps the handshake
  small and treats "pick a long public password" as an operational
  requirement. If you need the password to survive capture, use a generated
  secret, not a word.

The **private** password is a different object. It never leaves the machine.
It seals `identity.key` with the same scrypt parameters and a random
per-install salt, so two people with the same private password do not share
a keystore key. An attacker with the file still has to run scrypt once per
guess, and a wrong guess is indistinguishable from a tampered file.

## Payload encryption

Default: every chunk is an independent AEAD message, AES-256-GCM or
ChaCha20-Poly1305, with the 24-byte chunk header as associated data. The
header names the file index, offset, length and nonce counter, so an
attacker who reorders or splices chunks produces a tag mismatch rather than
a silently rearranged file.

`--no-encrypt` sends the bytes as they are. Integrity then rests on TCP (or
the reliable UDP checksums, which are not cryptographic) plus, if `--verify`
is on, a SHA-256 of each file. Use it on a network you already trust. The
client will refuse it when the transfer would have to go through the relay:
that would put the file contents on the operator's machine, which is not a
trade `--no-encrypt` was meant to make.

`--verify` is off by default. In encrypted mode each chunk's tag already
proves its bytes, and the authenticated counter sequence proves none are
missing. Hashing every file up front costs a whole extra read pass for a
property the AEAD already gives.

## Identity and files on disk

`config.toml` holds no secrets. The public password is not in it. Reading it
tells an attacker the username and the server, not how to receive as this
user.

`identity.key` is version byte + algorithm tag + AEAD of the Ed25519
private key, associated data `"drop-zone/v1 identity keystore"`. Created
0600, written to a temporary and renamed, fsync'd before the rename. The
public half is recomputed on unlock so the two cannot disagree.

`known_peers` is line-based and human-readable, like `known_hosts`. Treat a
changed pin as you would an SSH host-key warning.

Passwords read from the terminal are kept in a buffer that is wiped on
destruction. `explicit_bzero` / `OPENSSL_cleanse` is used on the server's
connection buffers so a later heap allocation cannot hand another part of
the process a window into a session that has ended.

## The server's promise

The operator of `drop-zone-server` is not a party to the transfer. The
daemon:

- Has no database, no accounts, no on-disk state.
- Holds a username only while its socket is open.
- Hashes addresses under a per-process random salt for rate limiting, and
  never writes the address itself.
- Logs an opaque connection id, never a username, never a path.
- Sets `RLIMIT_CORE` to 0 so a crash cannot spill the session table.
- Forwards relay bytes without a key for them.

A compromised server can still deny service, delay introductions, and lie
about reflexive addresses (which at worst pushes peers onto the relay). It
cannot read a transfer, and it cannot impersonate a pinned peer.

## What this is not

- Not an anonymous system. The server sees source addresses for as long as
  the socket is open; a peer you send to learns your candidates.
- Not a substitute for encrypting the files themselves before you send
  them, if the receiver's machine is the threat.
- Not forward-secret against a stolen public password plus a recorded
  handshake: the password is an input to HKDF. A stolen identity key
  without the password is not enough.
- Not a defence against a sender you chose to trust. `accept --yes` will
  write whatever they send, inside the sanitised relative paths.
