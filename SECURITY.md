# Security model — guarantees and their exact scope

This document is deliberately specific. Each claim names the mechanism
that enforces it and the scope in which it holds.

## 1. Capability model (language level)

- Cells hold `CapTable`s: unforgeable-authority tokens (target port +
  rights mask). No ambient authority: `send`/`call` without a grant fail.
- Authorities flow only by explicit mint/attenuate/copy; `revoke` is
  immediate.
- **Scope**: this is in-process enforcement. It routes authority and
  keeps cells from addressing each other, but a buggy cell shares the
  process it lives in. For kernel-enforced isolation see §2.

## 2. Process cells (kernel-enforced, `isolation = "process"`)

A cell can run in its own OS process whose sandbox is applied before any
cell code runs:

| mechanism | blocks | availability |
|---|---|---|
| seccomp default-deny allowlist | `open`/`openat`, entire socket family, `clone`/`fork`/`execve`, `prctl` (further filter changes), everything not explicitly allowed → `EPERM` | unprivileged, Linux ≥ 3.17 — **enforced everywhere, adversarially tested** |
| Landlock FS (read-only on granted paths) | filesystem view | kernel ≥ 5.13; reported `Unsupported` below that, never silently assumed |
| empty environment + rlimits | ambient paths, address space | any Linux |
| mediated stdio pipe | the worker's only channel out; every envelope re-checked against the parent CapTable | always |

Verification: `cargo test -p sieveplate-ctl --test jail` spawns real
workers and asserts that `socket()` and `open()` are denied inside them;
`--test adversarial` checks capability denial at the parent boundary.

## 3. Secure host links (SIEVE1)

See [ADR-0004](docs/adr/0004-sieve1-hybrid-pq-links.md). Every TCP link:

- **Hybrid post-quantum key exchange**: X25519 ‖ ML-KEM-768 → HKDF-SHA256.
  Defends recorded traffic against future quantum attackers (harvest-now-
  decrypt-later).
- **Hybrid identity signatures**: Ed25519 **and** ML-DSA-65 over the
  handshake transcript; both must verify. No downgrade path.
- **Frame protection**: ChaCha20-Poly1305, sequence-bound AEAD → replay,
  reorder, and cross-session frame reuse are rejected (the link is torn
  down when a frame fails authentication).
- **Trust model**: TOFU pinning with fingerprints; strict `deny_unknown`
  mode available; pinned-key change is a loud failure.
- **No plaintext transport exists.**

Not yet provided: post-quantum **at-rest** encryption (see ADR-0004 §
"Post-quantum storage note"), ML-DSA identity rotation (format not
frozen), a general TLS replacement (SIEVE1 targets pinned fabric peers).

## 4. Tamper evidence

- **Event log**: hash-chained; opening verifies every record and the
  chain; forged/rewritten/replayed records fail verification (tested).
- **CAS**: verify-on-read; a flipped byte on disk is refused (tested).
- **Hearth deltas**: applying a delta verifies the reconstructed content
  hash; a wrong base or tampered delta cannot materialize silently.

## 5. Failure containment

- Transactional turns: `Err`/panic → rollback (thread cells).
- Peer crash: link teardown fails all in-flight calls to that peer fast —
  callers get an error, not a silent hang (tested).
- Worker crash: pipe EOF is observed; in-flight calls fail; scale-to-zero
  respawn rebuilds from the CAS.

## 6. What is NOT claimed

- **No formal verification of this repository's code.** seL4's proofs
  cover the seL4 kernel on specified hardware (multicore is the weak
  spot) — not our integration, runtime, or bridge code. The port target
  documents the exact scope (`platforms/sel4/README.md`).
- **The eBPF verifier is not a proof.** It is a kernel-side checker with
  a real bug history; our loader treats a verifier rejection as an error
  and surfaces the kernel's log.
- **Side channels** (timing, allocation, IPC shaping) are out of scope.
- **Denial of service** between hosts (flow control, rate limits) is not
  yet implemented.

## 7. Reporting

See CONTRIBUTING.md for the disclosure process. Security-relevant files:
`fabric/src/secure.rs` (protocol), `fabric/src/identity.rs` (trust),
`jail/src/sandbox.rs` (seccomp/Landlock), `jail/src/worker.rs` (mediated
worker), `engine/src/proc_cell.rs` (parent-side mediation).
