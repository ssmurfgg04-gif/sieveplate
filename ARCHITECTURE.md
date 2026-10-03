# Sieveplate Architecture

This document maps the 7-layer specification onto the shipped code, states
what runs today, and what is a port target.

## Layer → crate map

| Layer | Spec name | Implementation | Status |
|---|---|---|---|
| L7 | Declarative System Definition ("the DNA") | `sieveplate-sysdef` | **runs** |
| L6 | Asynchronous Dataflow Orchestration ("the nervous system") | `sieveplate-fabric` | **runs** |
| L5 | Actor Cell Substrate ("the tissue") | `sieveplate-core` | **runs** |
| L4 | Cell Instantiation Engine ("the membrane") | `sieveplate-engine` | **runs** |
| L3 | Content-Addressable Semantic Store ("the memory") | `sieveplate-store` | **runs** |
| L2 | Verified Kernel Foundation ("the skeleton") | `sieveplate-core::cap` + `platforms/sel4` | userspace now; seL4 port target |
| L1 | eBPF Sensory Layer ("the nerves") | `sieveplate-senses` + `ebpf/` | timer/TCP/inotify run; eBPF bridge is bpftool-based |
| L0 | Memory-Centric Hardware Path | abstraction only | future |

## Design decisions that shape everything

### 1. The cell is the only unit of computation (L5)

A cell is private state + a mailbox. It never shares memory with another
cell. Handlers run one message at a time inside a vat — a single-threaded
async event loop. There are no locks inside cells and no data races between
them by construction.

The turn is transactional. Before a handler runs, the vat takes the cell's
serialized state (`Cell::snapshot`) as the rollback point. If the handler
returns `Err` **or panics** (caught via `catch_unwind`), the vat restores
the snapshot and the cell is as it was. Committed turns persist a fresh
content-addressed snapshot.

### 2. Sleeping actors are the storage model, not an optimization (L5+L3)

A cell idle past its `SleepPolicy` is **evicted**: snapshot → content
address → memory freed. What remains is a stub; live references stay valid
because a message to a stub triggers a restore-before-turn inside the vat.
Sleeping is therefore invisible to callers and *is* the persistence
mechanism: "sleep" and "save" are the same operation.

### 3. Capabilities are the only authority (L2, userspace edition)

Cells address other cells exclusively through capability tables — the
CNode analogue. `ctx.send/call` resolve targets against the table and fail
with `NoCap` otherwise. Authorities are created by `insert`, narrowed by
`attenuate` (subset-of-parent, enforced), and destroyed by `revoke`
(immediate; resolution fails from that instant).

On the seL4 port (`platforms/sel4/README.md`) this table is backed by real
kernel capabilities inside a Microkit protection domain. The userspace
semantics were deliberately chosen to match so the port is mechanical.

### 4. Promises are the composition primitive (L6)

A call carries a `reply_to: PromiseId`. Replies are ordinary envelopes
(`__reply`) that the fabric resolves into promise slots; a caller may
`await` a promise or *pipe* a continuation onto it. Continuations are
registered **before** the first hop resolves — the fabric completes the
chain without the caller ever blocking (the Spritely Goblins / Pathways
pattern, applied to an actor grid).

Promises also fail: a rolled-back turn resolves the caller's promise with
the error, so distributed calls have delivery semantics instead of
timeouts-as-error-handling.

### 5. Everything that happened is in a hash chain (L3)

The event log is append-only JSONL where each record commits to the SHA-256
of the previous one; the log is re-verified on open. The log projects into
Datalog facts (`turn_ok/4`, `wake/3`, `evict/2`, ...), and the bundled
Datalog engine answers semantic queries — "which cells woke slowly",
"who talked to whom", "what happened before the failure". The store is a
git-style fan-out CAS with verify-on-read: corruption is detected, never
silent.

### 6. The system is a pure function (L7)

`system_state = f(spec, template_descriptors)`. The closure hash is
sha256 over the canonical spec JSON plus every referenced template's
content descriptor. Applied plans are stored as content objects; `sieve
apply` records HEAD, `sieve plan` diffs without executing, `sieve
rollback` applies the previous plan. This is Nix-style reproducibility
for a *running* system rather than a package set.

### 7. Zero polling in the hot path (L1, L6)

Messages: mpsc mailboxes → vat loop → fabric → mailboxes. All async, all
event-driven. Sense sources: tokio timers, TCP reads, inotify — all push.
The only timer in the system is a 50 ms control-plane sweep that advances
idle eviction; it is never in the message path. The eBPF bridge consumes
kernel events as appended JSON lines (inotify-driven) — see `ebpf/`.

## Failure model

| Failure | Behavior | Recovery |
|---|---|---|
| Cell handler error/panic | turn rollback (state intact) | immediate; supervisor counts failures |
| Repeated failures (max_restarts) | supervisor one-for-one respawn from template + last snapshot | in-vat, sub-ms |
| Cell crash | same as eviction from the caller's view | wake-on-message |
| Vat exit | cells' last snapshots live in CAS | re-attach vat → stubs wake |
| Store corruption | detected on read (hash verify) | restore from replicas (operator) |
| Event log tamper | verify() fails on open | restore from backup; chain proves where |
| Network partition | peer send errors | retry at caller; promises fail fast with reason |
| Promise never resolves | timeout at the call site | cancel; late replies ignored (foreign guard) |

## What is NOT here (honest scope)

- **No hardware isolation in-process.** Vats isolate by discipline (single
  thread, message passing), not by MMU. The seL4 port target exists
  precisely because this is the boundary of the current design.
- **WASI components are not yet a cell template kind.** The `cas:`
  template prefix is reserved for content-addressed templates; a Wasmtime
  factory is future work.
- **CapTP-style wire security is out of scope.** The TCP fabric is framed
  and handshake-mapped but unencrypted; put it behind a tunnel for
  untrusted networks.
- **The Datalog engine is naive-fixpoint.** Fine for log-scale facts;
  swap for semi-naive/Soufflé when programs grow.
