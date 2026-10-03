# Phased Build Plan — Implementation Status

The guiding specification defined six phases. This document states, for
each phase, what was built, where it lives, and **how to verify it** with
commands that run in this repository.

---

## Phase 0 — Literature Foundation ✅

The research specification itself (prior art: seL4/LionsOS, Nanvix,
Unikraft/KraftCloud, Spritely Goblins, WASI, Nix/Guix, Pathways). The
composition it proposed is what this codebase implements.

---

## Phase 1 — Single-Node Vertical Slice ✅

**Spec goal**: prove the core "cell" lifecycle on one machine.

| Spec task | Implementation | Verify |
|---|---|---|
| Capability-based isolation | `sieveplate-core::cap` — CapTable with insert/attenuate/revoke; enforced in `TurnCtx::send/call` | `cargo test -p sieveplate-core` |
| Actor with transactional turn + rollback | `sieveplate-core::vat::turn` — pre-turn snapshot, rollback on Err **and panic** | `cargo test -p sieveplate-ctl --test vertical_slice` |
| Sleeping actors (evict → wake, measure latency) | `Vat::evict` / `rebuild_from_stub`, kernel-level `__ping` wake probe | same test, section 2–3 |
| Persistence to content-addressed store | `Vat::evict` → `ContentStore::put`; wake reads + verifies | `cargo test -p sieveplate-store` |
| Restore after "protection domain" destruction | `destroy_cell` → `restore_cell(hash)`; state proven intact | vertical_slice test, section 5 |
| One declarative expression for the whole stack | `sieveplate-sysdef`: TOML → closure hash → plan | `sieve apply -f examples/system.toml` |

**End-to-end demo** (prints measured latencies at each step):

```bash
cargo run -p sieveplate-ctl --release -- demo
```

**Spec success criteria — met**: an actor that sleeps, wakes on message,
performs a transactional update, persists to the content store, and is
restored after domain destruction — defined declaratively, zero
recompilation (templates are content-addressed factories).

---

## Phase 2 — Cell Model (Nanvix-inspired split) ✅ (userspace form)

**Spec goal**: multiple isolated cells sharing a semantic tissue.

- Multiple cells across multiple vats on one host: `sieveplate-engine::Host`.
- Cross-cell calls via promise pipelining (reply_to / continuations):
  `sieveplate-fabric::Fabric::call_pipelined`.
- Create / destroy / snapshot / restore / scale-to-zero lifecycle:
  `Host::{create_cell, destroy_cell, snapshot_cell, restore_cell, scale_to_zero, wake}`.
- Density probe: `sieve bench --suite cells` (create + evict 200 cells,
  reports per-op latency).

**Note on the spec's Unikraft/Firecracker split**: the user-VM/system-VM
split is expressed here as *cell/vat vs host+store* (stateless hot cells,
stateful shared tissue), which is the same disaggregation in one address
space. VM-grade isolation is the seL4 port target, not this binary.

Verify:

```bash
cargo test -p sieveplate-ctl --test phases phase2_pipelined_cross_cell_chain
cargo run -p sieveplate-ctl --release -- bench --suite cells
```

---

## Phase 3 — Sense Signal Injection ✅

**Spec goal**: hardware/external events drive actor state changes with
zero polling.

- Sense sources (all event-driven, all push): `sieveplate-senses::sources`
  — `timer`, `tcp` (JSON lines), `file` (inotify tail — the eBPF
  consumption path), plus an mpsc synthetic source for tests.
- Declarative wiring: `[[route]] from = "sense:tick" to = "core/counter"`.
- Wake path: signal → envelope → fabric → vat → **restore sleeping cell
  from CAS** → deliver. Latency recorded in `wake_us` metrics and the
  `wake/3` Datalog facts.

Verify (a sense signal wakes a sleeping cell; wake latency asserted):

```bash
cargo test -p sieveplate-ctl --test phases phase3_sense_wakes_sleeping_cell
```

Kernel events: `ebpf/` carries reference BPF programs (TCP/kprobe) plus
`run.sh`, which streams kernel events as JSON lines into the file sense —
wiring real hardware signals into sleeping cells without kernel patches.

---

## Phase 4 — Declarative Scaling (multi-host) ✅

**Spec goal**: cells across hosts, managed declaratively.

- Framed-TCP transport with a `__hello` handshake so peers learn each
  other's names and replies route back across hosts:
  `sieveplate-fabric::net`.
- Bidirectional pipelined chains spanning hosts (continuation fires on the
  calling host when the remote reply arrives).
- Multi-host systems are declarative compositions: per-host specs +
  `[network] listen/peers` in the TOML; `sieve run` boots, wires peers,
  runs senses, and shuts down cleanly on Ctrl-C.

Verify (two hosts on localhost, cross-host pipelined call):

```bash
cargo test -p sieveplate-ctl --test phases phase4_multi_host_tcp_pipeline
```

Plan management across runs:

```bash
sieve apply  -f examples/system.toml --root ./runtime   # record plan (closure hash)
sieve plan   -f examples/system.toml --root ./runtime   # diff vs HEAD
sieve apply  -f examples/system-v2.toml --root ./runtime
sieve rollback --root ./runtime                          # apply previous plan
```

---

## Phase 5 — Production Hardening ♾️ (ongoing)

| Spec task | Delivered so far |
|---|---|
| Observability | `tracing` throughout; `Metrics` (counters + p50/p95/p99 latency series, JSON snapshot); hash-chained event log; `sieve store verify` |
| Security | capability enforcement + audit surface (`ctx.capabilities()`, cap tables in status); tamper-evident log; promise failure semantics (no hang); SECURITY.md with reporting policy |
| Performance | release benchmarks above (BENCHMARKS.md), all targets met with margin |
| Documentation | README, ARCHITECTURE, PHASES (this file), BENCHMARKS, ADRs, crate-level docs |
| Community | Apache-2.0, CONTRIBUTING.md, CI (fmt + clippy -D warnings + tests + demo smoke) |

---

## The full verification sweep

```bash
cargo test --workspace                          # 28 tests: units + integration
cargo run -p sieveplate-ctl --release -- demo   # Phase-1 vertical slice, live
cargo run -p sieveplate-ctl --release -- bench --suite all
sieve run -f examples/system.toml               # declarative system until Ctrl-C
```
