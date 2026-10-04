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

- **SIEVE1 secure links** (`sieveplate-fabric::net` + `::secure` +
  `::identity`): every TCP connection performs a hybrid post-quantum
  handshake (X25519 ‖ ML-KEM-768 key exchange, Ed25519 ∧ ML-DSA-65 dual
  signatures, ChaCha20-Poly1305 frames, sequence-bound AEAD). Peers are
  authenticated against a TOFU/pinned `known_peers.json`; there is no
  plaintext mode. **Multi-host is two real machines, not just
  localhost**: the handshake and trust store are host-independent; the
  phase-4 test runs two hosts over loopback because CI has loopback —
  point `[network] peers` at real addresses for real machines.
- **Crash-failure detection**: link teardown fails all in-flight calls to
  that peer immediately (`Fabric::peer_disconnected`) — a caller gets an
  error or an answer, never a silent hang. The adversarial suite kills a
  peer mid-turn and asserts fast failure (`--test adversarial`).
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

## Phase 5 — Production Hardening ✅ (this revision) / ♾️ (ongoing)

| Spec task | Delivered so far |
|---|---|
| Observability | `tracing` throughout; `Metrics` (counters + p50/p95/p99 latency series, JSON snapshot); hash-chained event log; `sieve store verify` |
| Security — kernel level | **process cells**: seccomp default-deny + Landlock + mediated pipe (`sieveplate-jail`), caps re-checked at the parent boundary; adversarial tests spawn real workers and assert socket()/open() denial (ADR-0005) |
| Security — links | **SIEVE1 hybrid post-quantum secure links** on every host connection, TOFU pinning + strict mode (ADR-0004); replay/tamper/impostor tests |
| Security — storage | CAS verify-on-read (corruption refused); hash-chained log (forgery rejected); hearth delta hash-verified apply |
| Failure containment | promise failure on rollback; peer-crash detection fails in-flight calls fast; process-cell respawn from CAS |
| Versioning | **Hearth layer**: content-addressed snapshots, branches + reflog, logical `diff` (branch level), byte-level `ddiff` (snapshot level) — `sieve hearth ...` |
| Performance | honest benchmarks: every row states what it measures and what it does NOT (BENCHMARKS.md); new jail + handshake suites measure real isolation/crypto costs |
| Documentation | README, ARCHITECTURE, PHASES (this file), BENCHMARKS, SECURITY, ADR-0001..0008 (platform matrix, capability bridge, PQ policy, mesh, rotation, wasm) |
| Multi-hop mesh | **Distance-vector routing** over sealed links (ADR-0006): envelopes relay through hosts with no direct socket; poison-response withdrawal on relay death; per-envelope TTL; `__fault` propagation fails in-flight calls fast at ANY mesh depth | `cargo test -p sieveplate-ctl --test mesh` |
| WASM cells | **Wasmtime/WASI template kind** (ADR-0008): any `wasm32-wasip1` binary is a cell (frozen SIEVE-WASI ABI v1, `docs/wasm-abi.md`); one turn = one instance; structural scale-to-zero | `cargo test -p sieveplate-ctl --test wasm` |
| Identity rotation | **Key format FROZEN v1 + ML-DSA rotation** (ADR-0007): 4-signature crossover statements, generation counters, in-handshake re-pinning, replay/downgrade rejection | `cargo test -p sieveplate-ctl --test identity_rotation` + `sieve identity rotate` |
| Live dashboard | **`sieve top`**: Catppuccin Mocha TUI (identity, cells by isolation, mesh routes, hearth branches, store integrity, latency percentiles); headless `--screenshot` renders a frame as JSON for CI visual review | `cargo run -p sieveplate-ctl -- top -f examples/system-wasm.toml --root ./rt --screenshot /tmp/top.json --seed-hearth` |
| Community | Apache-2.0, CONTRIBUTING.md, CI: fmt + clippy -D warnings + tests + jail/adversarial + **eBPF load as root** + **seL4 build & QEMU boot smoke** + **nix flake check** |

---

## The full verification sweep

```bash
cargo test --workspace                                     # all units + integration
cargo test -p sieveplate-ctl --test jail                   # real process cells: seccomp denial
cargo test -p sieveplate-ctl --test adversarial            # kill-node / corrupt-blob / forged-log
cargo run -p sieveplate-ctl --release -- demo              # Phase-1 vertical slice, live
cargo run -p sieveplate-ctl --release -- bench --suite all # honest benchmarks (jail + handshake included)
sieve run -f examples/system.toml                          # declarative system until Ctrl-C
sudo cargo test -p sieveplate-senses -- --ignored          # eBPF: real bpf(2) load + packet events (root)
# hearth: snapshot → branch → diff → ddiff → verified rebuild
R=./rt; sieve hearth write k --text v1 --root $R
T=$(sieve hearth snapshot main k=$(sieve hearth write k --text v2 --root $R | cut -f2) --root $R | head -1 | cut -f2)
sieve hearth diff main main --root $R
```

CI (GitHub Actions) runs all of it, including the eBPF root test, the
seL4 Microkit build + QEMU boot smoke, and `nix flake check`.
