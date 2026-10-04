<div align="center">

# sieveplate

**A living cell-grid runtime — signals flow through capability-gated channels between sleeping, transactional cells.**

*A sieve plate is the perforated end-wall between two living plant cells:
only what fits through the perforations passes. Every boundary in this
runtime works the same way.*

[![CI](https://github.com/ssmurfgg04-gif/sieveplate/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

</div>

---

## What it is

Sieveplate is a **cell-based operating runtime** built as a Rust workspace.
Its fundamental unit of computation is the **cell**: a self-contained,
transactional, persistent actor. Cells live in **vats** (single-threaded
event loops with atomic rollback), sleep when idle (zero CPU, state in a
content-addressed store), and hold **capability tables** (no ambient
authority — every send is checked, every grant is explicit).

Cells come in three isolation levels, measured and reported honestly:

| level | what runs | kernel enforcement | cost (p50, release) |
|---|---|---|---|
| `thread` (default) | actor in a host process | language capability checks | 15 µs turn |
| `process` | a dedicated OS process per cell | **seccomp default-deny allowlist** (no `open`, no `socket`, no `exec`), Landlock FS (kernel ≥ 5.13), mediated pipe | 1.1 ms spawn, 71 µs turn |
| `microvm` | a Firecracker / cloud-hypervisor VM | hardware virtualization | gated on KVM — refuses to run where it can't |

Host-to-host links are always encrypted and authenticated (SIEVE1:
hybrid post-quantum, see below). There is no plaintext transport to
disable.

```
┌─────────────────────────────────────────────────────────────────┐
│  L7  sysdef    declarative DNA — spec → closure hash → plan      │
│  L6  fabric    nervous system — SIEVE1 secure links, pipelining  │
│  L5  core      tissue — cells, vats, transactional turns         │
│  L4  engine    membrane — thread/process/microvm cell lifecycle  │
│  L3  store     memory — content-addressed + Datalog + event log  │
│  L3b hearth    versioning — snapshots, branches, diff, ddiff     │
│  L2  (core/cap) skeleton — capability tables (seL4 mapping)      │
│  L1  senses    nerves — timer / TCP / inotify / eBPF (root)      │
│  L0  (future)  memory-centric hardware — abstraction is ready    │
└─────────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
# the vertical slice, live: sleep → wake → transact → persist → restore
cargo run -p sieveplate-ctl --release -- demo

# declarative system: validate → closure hash → run until Ctrl-C
cargo run -p sieveplate-ctl -- run -f examples/system.toml --root ./runtime

# benchmarks — each row states what it measures and what it does not
cargo run -p sieveplate-ctl --release -- bench --suite all
```

### A declarative system

```toml
[system]
name = "demo"

[[sense]]
name = "tick"
kind = "timer"
period_ms = 500

[[cell]]
name = "counter"
vat = "core"
template = "builtin:counter"
sleep_after_ms = 250        # scale to zero after idle
[[cell.caps]]
to = "core/counter"
rights = ["send", "call"]   # no ambient authority

# a jailed cell: its own OS process, seccomp-sandboxed
[[cell]]
name = "untrusted"
vat = "core"
template = "builtin:kv"
isolation = "process"

[[route]]
from = "sense:tick"
to = "core/counter"
name = "add"
```

The system is a **pure function of content-addressed inputs**: the closure
hash covers the spec *and* the content descriptors of every template —
change a cell's semantics and the closure changes. Plans are stored in the
CAS, so `sieve rollback` is applying the previous plan.

## The guarantees (and their exact scope)

| Property | Mechanism | Scope |
|---|---|---|
| Atomic state change | Transactional turns: pre-turn snapshot, rollback on `Err` **or panic** | thread cells in-process |
| Zero idle cost | Sleeping actors: evict → CAS, live references stay valid, wake on message | in-process; process cells kill the whole child and respawn from the CAS |
| No ambient authority | Capability tables checked in the turn context **and re-checked at the process-cell boundary** | language-level; process cells additionally constrained by the OS sandbox |
| Kernel-enforced cell sandbox | seccomp default-deny allowlist (no `open`/`socket`/`exec`), Landlock FS on ≥ 5.13, empty environment, rlimits | `isolation = "process"` cells — enforced, tested |
| Calls never hang | Promise failure on rollback; **peer crash detection fails in-flight calls fast** (link teardown → `peer_disconnected` → promise failure) | thread + process cells, TCP links |
| Authenticated + encrypted links | SIEVE1: hybrid **X25519 ‖ ML-KEM-768** key exchange, hybrid **Ed25519 ∧ ML-DSA-65** signatures, ChaCha20-Poly1305 frames, sequence-bound AEAD (replay rejected) | every TCP link, always on |
| Tamper-evident history | Hash-chained event log, verified on open, projected into Datalog | local log |
| Corruption detection | CAS verify-on-read: a flipped byte on disk refuses to load | local store |
| Versioned state | **Hearth**: content-addressed snapshots, branches, logical `diff` (branch level), byte-level `ddiff` (snapshot level, copy/insert delta with hash-verified apply) | hearth layer |
| Multi-hop mesh | Distance-vector routing over sealed links: envelopes relay through hosts with no direct socket; poison-withdrawal on relay death, TTL loop guard, in-flight calls fail fast at ANY depth (`__fault` routed back to the caller) | `crates/sieveplate-ctl/tests/mesh.rs` |
| WASM cells | Any `wasm32-wasip1` program as a cell: Wasmtime + WASI p1, one turn per instance, state in one preopened dir, outgoing messages capability-rechecked; scale-to-zero is structural (ADR-0008) | `crates/sieveplate-ctl/tests/wasm.rs` |
| Identity rotation | Key format frozen at v1; rotation = statement signed by Ed25519+ML-DSA-65 under old AND new keys; peers re-pin on the next handshake; replays/downgrades rejected | `crates/sieveplate-ctl/tests/identity_rotation.rs` |
| Searchable by meaning | Embedded Datalog over the event log | local log |
| Reproducible systems | Closure hash = f(spec, template descriptors); content-addressed plans; rollback | declarative layer |

Not guaranteed (yet): formal verification of anything beyond what seL4
itself proves on its port target (and seL4's proofs cover the kernel, not
this integration code); post-quantum **at-rest** encryption (transport is
hybrid-PQ, storage is not).

## Workspace

| crate | layer | role |
|---|---|---|
| [`sieveplate-store`](crates/sieveplate-store) | L3 | content-addressed store, hash-chained event log, Datalog engine |
| [`sieveplate-hearth`](crates/sieveplate-hearth) | L3b | versioned snapshots, branches, diff/ddiff |
| [`sieveplate-core`](crates/sieveplate-core) | L5 (+L2) | cells, vats, transactional turns, sleeping actors, caps, promises |
| [`sieveplate-cells`](crates/sieveplate-cells) | — | reference cells: counter, greeter, echo, kv, sandbox-probe |
| [`sieveplate-fabric`](crates/sieveplate-fabric) | L6 | fabric router, promise pipelining, SIEVE1 secure multi-host links, crash detection |
| [`sieveplate-jail`](crates/sieveplate-jail) | — | process cells: seccomp + Landlock sandbox, mediated worker protocol |
| [`sieveplate-microvm`](crates/sieveplate-microvm) | — | microVM cell kind: Firecracker/cloud-hypervisor configs, honest capability gating |
| [`sieveplate-engine`](crates/sieveplate-engine) | L4 | host, cell lifecycle (create/snapshot/restore/scale-to-zero) |
| [`sieveplate-senses`](crates/sieveplate-senses) | L1 | timer/TCP/inotify sources, real eBPF socket-filter loader |
| [`sieveplate-sysdef`](crates/sieveplate-sysdef) | L7 | TOML spec, closure hash, plan diff, content-addressed rollback |
| [`sieveplate-ctl`](crates/sieveplate-ctl) | — | `sieve` CLI: demo / run / top (Catppuccin Mocha live dashboard) / apply / plan / rollback / bench / store / hearth / identity (show · rotate) |

Documentation: [ARCHITECTURE.md](ARCHITECTURE.md) ·
[PHASES.md](PHASES.md) · [BENCHMARKS.md](BENCHMARKS.md) ·
[SECURITY.md](SECURITY.md) · [ADRs](docs/adr/) ·
[seL4 port target](platforms/sel4/README.md) · [eBPF bridge](ebpf/README.md)

## Why "sieveplate"

In plant anatomy the **sieve plate** is the perforated shared wall between
two sieve-tube cells — living cells that pass sugars and *signals* to each
other through those holes, and can seal them on demand. It is the whole
architecture in one word: living cells, gated channels, flowing signals.
The name has no prior software collision on GitHub (verified 2026-10).

## Status & roadmap

- **Phases 0–4 implemented** (vertical slice, multi-cell, sense-driven
  wakes, multi-host transport — now with authenticated/encrypted links —
  and declarative management).
- **Phase 5 (hardening) — this revision**: kernel-enforced process cells,
  hybrid post-quantum links, crash-failure detection, hearth versioning,
  adversarial test suite, honest benchmarks/docs.
- **Port targets**: `platforms/sel4/` maps vats/caps onto seL4 Microkit
  protection domains (CI builds a Microkit system and boots seL4 under
  QEMU as a smoke test); `ebpf/` carries the kernel-event bridge
  (root-gated, CI-verified).

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Licensed under [Apache-2.0](LICENSE).
