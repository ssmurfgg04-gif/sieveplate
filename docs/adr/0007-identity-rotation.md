# ADR-0007: Identity key format freeze (v1) and ML-DSA rotation

Status: implemented
Date: 2026-10

## Context

The user directive: *"ML-DSA identity rotation once the key format
freezes."* Rotation cannot be bolted onto an unstable format — the wire
shape must be pinned first, with tests that treat it as contractual.

## Decision

### 1. The key format is FROZEN at v1

```json
{"format":"sieveplate-identity","version":1,"host":"…",
 "generation":0,"ed_seed_hex":"…","pq_seed_hex":"…"}
```

- Field names, semantics and serialization ORDER are contractual.
  `identity_format_is_frozen_v1` pins them with a golden test.
- Legacy files (pre-freeze, missing the new fields) load unchanged via
  serde defaults (`format` defaults to the tag, `generation` to 0).
- Every identity carries a monotonic **generation** counter.

### 2. Rotation = a four-signature crossover statement

```json
RotationStatement {
  core: { host, old_generation, new_generation,
          old_ed_public, old_pq_vk, new_ed_public, new_pq_vk,
          rotated_at_ms },
  sig_old_ed, sig_old_pq, sig_new_ed, sig_new_pq
}
```

All four signatures cover `sieveplate-rotation-v1 ‖ bincode(core)`:

- **old keys sign** — proves the legitimate owner authorizes the change;
- **new keys sign** — proves the destination key pair is real and owned.

An attacker needs BOTH algorithms for BOTH key generations. A future
quantum break of Ed25519 alone (or a classical break of ML-DSA alone)
cannot forge or steer a rotation — the same no-downgrade rule SIEVE1
applies to handshakes.

Guards:

- `new_generation == old_generation + 1` (exactly one step, no gaps);
- peers only re-pin when the statement bridges THEIR pinned keys to the
  presented keys **and** advances their recorded generation by 1 — so
  **replays and downgrades are rejected**;
- strict (`deny_unknown`) mode never accepts a statement for a host it
  has not explicitly pinned.

### 3. Handshake integration

A host that rotated attaches its latest statement (persisted at
`fabric/rotation-<gen>.json`, loaded automatically by `LinkConfig::open`)
to its handshake auth frames. The statement is transcript-bound. A peer
whose pin still names the old keys verifies the statement and re-pins
**during the handshake** — no operator intervention, no downtime.
Impostors without statements still fail with the same loud
`PeerKeyChanged` as before.

## Operations

```bash
sieve identity show   --root ./runtime     # fingerprint, generation, pins
sieve identity rotate --root ./runtime     # new keys + statement, printed
```

Rotation is offline-tolerant: peers that missed the statement receive it
on the next handshake they participate in.

## Alternatives rejected

- **Certification hierarchy / PKI**: overkill for pinned, long-lived
  fabric peers; adds a trust root this design deliberately lacks.
- **Rotation without old-key signature** (new key self-certifies):
  enables an attacker who stole the new keys (e.g. via a partial break)
  to rotate freely — rejected.
- **SSH-style `known_hosts` manual re-pinning on rotation**: operationally
  hostile and invites blindly accepting new keys.

## Consequences

- Tests: `identity_format_is_frozen_v1`, `rotation_statement_lifecycle`
  (verify, re-pin, downgrade rejection, tamper rejection) in
  `sieveplate-fabric/src/identity.rs`; `identity_rotation_repins_peers_
  and_rejects_impostors` end-to-end in `crates/sieveplate-ctl/tests/`.
- The frozen format means changing ANY identity field is now a
  breaking protocol change requiring a `version` bump and a migration —
  by design.
