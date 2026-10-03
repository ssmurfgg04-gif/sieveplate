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
| L3b | Hearth — versioning (snapshots/branches/diff/ddiff) | `sieveplate-hearth` | **runs** |
| L2 | Verified Kernel Foundation ("the skeleton") | `sieveplate-core::cap` + `platforms/sel4` | userspace now; seL4 build+boot smoke in CI; full port in progress |
| L1 | eBPF Sensory Layer ("the nerves") | `sieveplate-senses::ebpf` + `ebpf/` | timer/TCP/inotify run; **real bpf(2) loader** (root-gated, CI-verified as root) |
| L0 | Memory-Centric Hardware Path (+ quantum as a capability-guarded peripheral — a note, not a phase) | abstraction only | future |
| — | Process isolation ("the membrane's teeth") | `sieveplate-jail` | **runs** — seccomp+Landlock, adversarially tested |
| — | MicroVM cells | `sieveplate-microvm` | config-tested; launch gated on KVM + binary, honestly unavailable elsewhere |

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

**The capability bridge — three layers, not one system.** The original
plan said Goblins-style capabilities "map directly" onto seL4 kernel
capabilities. They do not: language caps are object references checked in
a turn context; seL4 caps are kernel objects. Sieveplate states them as
three enforcement layers (see [ADR-0005](docs/adr/0005-process-cells-capability-bridge.md)):

1. **language** — the CapTable in the turn context (routing authority);
2. **OS** — seccomp/Landlock/rlimits around `isolation = "process"`
   cells (bounding what buggy cell code can do to the machine, with the
   parent re-checking every emitted envelope against the same table);
3. **kernel (port target)** — seL4 caps via an explicit adapter
   (`attenuate` → `CNode_Copy` with rights mask; `revoke` →
   `CNode_Revoke`). The adapter is *not* formally verified; seL4's proofs
   cover the kernel, nothing else.

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
idle eviction; it is never in the message path. The eBPF sense is a real
loader: it builds raw `bpf_insn`, loads via the `bpf(2)` syscall
(`BPF_PROG_LOAD`, socket filter), attaches to an `AF_PACKET` socket
(`SO_ATTACH_BPF`) and feeds packet events into the pump. It requires
root/CAP_BPF on modern kernels and **reports that requirement as an
error** rather than faking events; CI runs the load test as root.

## Failure model

| Failure | Behavior | Recovery |
|---|---|---|
| Cell handler error/panic | turn rollback (state intact) | immediate; supervisor counts failures |
| Repeated failures (max_restarts) | supervisor one-for-one respawn from template + last snapshot | in-vat, sub-ms |
| Cell crash | same as eviction from the caller's view | wake-on-message |
| Vat exit | cells' last snapshots live in CAS | re-attach vat → stubs wake |
| Store corruption | detected on read (hash verify) | restore from replicas (operator) |
| Event log tamper | verify() fails on open | restore from backup; chain proves where |
| Network partition / **peer crash** | link teardown detected; **all in-flight calls to that peer fail immediately** (`peer_disconnected`) | retry at caller; promises fail fast with reason — never a silent hang |
| Jailed worker crash / seccomp kill | pipe EOF observed by the parent; in-flight calls fail | scale-to-zero respawn from CAS on next message |
| Promise never resolves | timeout at the call site | cancel; late replies ignored (foreign guard) |

## What is NOT here (honest scope)

- **Hardware isolation is opt-in per cell.** Thread cells isolate by
  discipline; `isolation = "process"` cells get kernel-enforced seccomp/
  Landlock sandboxing (ADR-0005); `isolation = "microvm"` cells get
  hardware virtualization **only where KVM and a hypervisor actually
  exist** — `sieveplate-microvm` refuses to launch otherwise and says
  exactly what is missing. The seL4 port target completes the ladder.
- **WASI components are not yet a cell template kind.** The `cas:`
  template prefix is reserved for content-addressed templates; a
  Wasmtime factory is the next template kind on the list (tracked, not
  built).
- **"No compile times" is only partly true, stated exactly.** Templates
  are content-addressed factories, so *deployed systems* change by
  substitution, not recompilation. But Nix substitution only helps for
  things someone has already built: a fresh `nix build` of this closure
  compiles at least once. We also deliberately did NOT adopt Soufflé for
  Datalog: it is a C++ code generator, which conflicts with live,
  interactive log queries — the in-process naive-fixpoint engine is the
  honest tradeoff (swap for semi-naive when programs grow).
- **Post-quantum signatures: hybrid KEM now, ML-DSA identity rotation
  designed but the identity file format is not frozen.** Link traffic is
  harvest-now-decrypt-later safe (ADR-0004); at-rest encryption is an
  operator layer.
- **The eBPF sense needs root** on modern kernels; the loader reports
  the privilege boundary as an error, and CI proves the path as root.
- **Multi-host routing is link-local.** No mesh routing/multi-hop relay
  across peers yet; envelopes travel one hop per configured link.

## Platform matrix

The isolation substrates do NOT stack ("seL4 under everything" was
incoherent with eBPF-as-a-Linux-feature and Firecracker-needs-KVM).
There are two platform modes; L3–L7 are shared unchanged:

| | **Linux host mode** (primary, CI-verified) | **seL4 mode** (port target) |
|---|---|---|
| cell isolation | thread + process (seccomp/Landlock) | Microkit protection domains |
| microVM cells | Firecracker / cloud-hypervisor under KVM | unikernel images replace them |
| senses | timer/TCP/inotify/**eBPF** | IRQ-driven driver PDs (no eBPF on seL4) |
| drivers | Linux | LionsOS/native PDs (system-VM fallback keeps its big-TCB cost on the ledger) |
