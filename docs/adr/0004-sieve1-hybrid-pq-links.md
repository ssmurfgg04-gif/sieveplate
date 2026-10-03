# ADR-0004: SIEVE1 secure links with hybrid post-quantum crypto

Date: 2026-10-04
Status: accepted

## Context

Host-to-host transport was framed TCP with an unauthenticated `__hello`
announcement. Any TCP peer could announce any host name and inject
envelopes; all traffic was plaintext. Two gaps, both severe:

1. **Identity**: nothing verified *which* host is on the other end of the
   socket, so the capability model ended at the NIC.
2. **Harvest now, decrypt later**: the plan's identities and key exchange
   were classical (Ed25519 + X25519-shaped). A future large quantum
   computer breaks those retroactively for traffic recorded today.
   SHA-256-style hashes are effectively fine (Grover halves their
   strength; 256 → 128 bits of margin remains).

## Decision

Every TCP link runs **SIEVE1** before a single envelope flows:

- **Key exchange, hybrid**: X25519 ephemeral DH ‖ ML-KEM-768 (FIPS 203)
  encapsulation, joined as `ikm = ss_x25519 ‖ ss_mlkem`, expanded with
  HKDF-SHA256 (salt = transcript hash). Neither classical ECDLP nor a
  lattice break alone yields the session key.
- **Identity, hybrid catena**: every host has an Ed25519 key *and* an
  ML-DSA-65 (FIPS 204) key. Handshake transcripts are signed with BOTH;
  a peer is authenticated only when both verify. There is no downgrade
  path — either algorithm alone is never sufficient.
- **Frames**: ChaCha20-Poly1305, per-direction nonce bases XORed with a
  64-bit sequence counter, and the sequence is bound into the AEAD
  associated data together with the transcript hash. Replays, reorders
  and cross-session frame smuggling all fail authentication.
- **Trust**: SSH-style TOFU (`known_peers.json` with key fingerprints);
  strict mode (`deny_unknown`) for pinned-only deployments; key change
  on a pinned host is a loud error (`PeerKeyChanged`).
- **No plaintext mode.** The old transport is gone, not feature-flagged.

Measured cost: ~3.6 ms p50 per handshake (release, this repo's
BENCHMARKS.md). Frames add one AEAD seal/open each.

## Post-quantum storage note (seal-now-decrypt-later)

The CAS is encrypted at the link layer in transit but stored in the
clear by design (content addressing requires hashability). Operators who
must defend recorded state against future quantum attackers should apply
at-rest encryption themselves with hybrid-PQ-wrapped keys; the store's
hash layer is compatible with any client-side encryption because it
addresses ciphertext bytes. Identity rotation for ML-DSA is designed
(seed-based keys) but the on-disk identity format is NOT yet frozen;
treat identity files as disposable until it is.

## Quantum as a device class (deliberately NOT a phase)

A QPU fits the model as one more capability-guarded peripheral: a cell
holding a "submit quantum job" capability posts a circuit and gets a
promise that resolves in seconds-to-minutes — promise pipelining already
covers the shape, and a seL4/OS capability gates who may hold it. This
is recorded as a Layer-0 note next to the PIM item. It adds nothing to
the core design today, so it is documented, not built.

## Consequences

- Crypto crates are pure Rust (RustCrypto `ml-kem`, `ml-dsa`,
  `dalek`, `chacha20poly1305`) — no C toolchain in the build.
- The protocol is deliberately small enough to audit line-by-line
  (`fabric/src/secure.rs`). For hostile public networks prefer rustls;
  SIEVE1 targets the fabric where identities are pinned.
- Identity/peer files live under `<runtime>/fabric/` and are part of the
  operator's backup story.
