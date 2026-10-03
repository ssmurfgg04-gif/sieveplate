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

It is the working implementation of a 7-layer architecture assembled from
proven patterns — verified-kernel capability discipline, actor-model
transactional turns, sleeping actors, content-addressed memory, semantic
(Datalog) querying, promise-pipelined dataflow, and declarative,
hash-addressed system definition.

```
┌─────────────────────────────────────────────────────────────────┐
│  L7  sysdef    declarative DNA — spec → closure hash → plan      │
│  L6  fabric    nervous system — promise pipelining, TCP grid     │
│  L5  core      tissue — cells, vats, transactional turns        │
│  L4  engine    membrane — create / snapshot / scale-to-zero     │
│  L3  store     memory — content-addressed + Datalog + event log │
│  L2  (core/cap) skeleton — capability tables (seL4 mapping)      │
│  L1  senses    nerves — timer / TCP / inotify / eBPF bridge     │
│  L0  (future)  memory-centric hardware — abstraction is ready    │
└─────────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
# the vertical slice, live: sleep → wake → transact → persist → restore
cargo run -p sieveplate-ctl --release -- demo

# declarative system: validate → closure hash → run until Ctrl-C
cargo run -p sieveplate-ctl -- run -f examples/system.toml --root ./runtime

# benchmarks (release build recommended)
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

[[route]]
from = "sense:tick"
to = "core/counter"
name = "add"
```

The system is a **pure function of content-addressed inputs**: the closure
hash covers the spec *and* the content descriptors of every template —
change a cell's semantics and the closure changes. Plans are stored in the
CAS, so `sieve rollback` is applying the previous plan.

## The guarantees

| Property | Mechanism |
|---|---|
| Atomic state change | Transactional turns: pre-turn snapshot, rollback on `Err` **or panic** |
| Zero idle cost | Sleeping actors: evict → CAS, live references stay valid, wake on message |
| No ambient authority | Capability tables: `send`/`call` checked in the turn context; attenuate/revoke |
| Calls never hang | Promise failure: rolled-back turns resolve the caller's promise with an error |
| Composition without blocking | Promise pipelining: continuations registered before the first hop resolves |
| Tamper-evident history | Hash-chained event log, verified on open, projected into Datalog |
| Searchable by meaning | Embedded Datalog over the event log ("what happened", not "where is it") |
| Reproducible systems | Closure hash = f(spec, template descriptors); content-addressed plans; rollback |

## Benchmarks (release, Linux x86-64, containerized CI-class core)

| benchmark | n | p50 | p95 |
|---|---|---|---|
| turn: call round-trip (in-proc) | 2000 | **15 µs** | 22 µs |
| wake: scale-to-zero → wake cycle | 200 | **34 µs** | 41 µs |
| store: put 4 KiB (content-addressed) | 1000 | **3 µs** | 3 µs |
| store: get + verify 4 KiB | 1000 | **5 µs** | 6 µs |
| cells: create (template instantiation) | 200 | **20 µs** | 27 µs |
| cells: scale-to-zero (snapshot → CAS) | 200 | **18 µs** | 27 µs |

Spec targets: millisecond-class cell lifecycle, scale-to-zero < 10 ms —
met with two to three orders of magnitude of headroom in-process.

## Workspace

| crate | layer | role |
|---|---|---|
| [`sieveplate-store`](crates/sieveplate-store) | L3 | content-addressed store, hash-chained event log, Datalog engine |
| [`sieveplate-core`](crates/sieveplate-core) | L5 (+L2) | cells, vats, transactional turns, sleeping actors, caps, promises |
| [`sieveplate-cells`](crates/sieveplate-cells) | — | reference cells: counter, greeter, echo, kv |
| [`sieveplate-fabric`](crates/sieveplate-fabric) | L6 | fabric router, promise pipelining, framed-TCP multi-host |
| [`sieveplate-engine`](crates/sieveplate-engine) | L4 | host, cell lifecycle (create/snapshot/restore/scale-to-zero) |
| [`sieveplate-senses`](crates/sieveplate-senses) | L1 | timer/TCP/inotify sources, eBPF event bridge, signal pump |
| [`sieveplate-sysdef`](crates/sieveplate-sysdef) | L7 | TOML spec, closure hash, plan diff, content-addressed rollback |
| [`sieveplate-ctl`](crates/sieveplate-ctl) | — | `sieve` CLI: demo / run / apply / plan / rollback / bench / store |

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

- **Phase 0-4: implemented** (vertical slice, multi-cell, sense-driven
  wakes, multi-host transport, declarative management).
- **Phase 5 (ongoing)**: observability, security hardening, docs, CI —
  this repository.
- **Port targets**: `platforms/sel4/` maps vats/caps onto seL4 Microkit
  protection domains; `ebpf/` carries the reference kernel-event bridge.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Licensed under [Apache-2.0](LICENSE).
