# ADR-0005: process cells — kernel-enforced sandboxing and the three-layer capability bridge

Date: 2026-10-04
Status: accepted

## Context

"Cells with isolation" previously meant software objects (actors) inside
one Rust process, and "capability security" meant permission tables
enforced by that same program. Honest review called this out: the
capability claim was only as strong as the process containing every cell.

Separately, the original plan treated TWO different capability systems as
one: Goblins-style language-level capabilities (object references checked
in a turn context) and seL4 kernel capabilities (unforgeable kernel
objects). "One maps directly to the other" is false — bridging them is
adapter work with its own trust assumptions, not a correspondence.

## Decision

### 1. Three isolation levels, one cell trait

`isolation = "thread" | "process" | "microvm"` on every cell. The cell
trait is identical at every level; only the enforcement substrate
changes:

| level | substrate | enforcement | status |
|---|---|---|---|
| `thread` | host process | language caps in the turn context | default |
| `process` | dedicated OS process | seccomp default-deny + Landlock + mediated pipe; caps re-checked at the parent boundary | implemented, tested (works unprivileged, any Linux ≥ 3.17; Landlock needs ≥ 5.13 and is reported as unsupported below that) |
| `microvm` | Firecracker / cloud-hypervisor VM | hardware virtualization | config generation golden-tested; launch refuses to run without a binary AND `/dev/kvm` |

A process cell's worker applies its sandbox **before any cell code
runs**: rlimit → Landlock (best-effort, honestly reported) →
`PR_SET_NO_NEW_PRIVS` → seccomp default-deny allowlist (read/write on
its stdio pipes, memory management, clock, futex, exit — *no* `open`,
no socket family, no process family). Denied syscalls return EPERM, so
probes fail observably and the worker survives to report. The worker's
only I/O is one mediated pipe; every envelope it emits is re-checked
against the parent's capability table.

Scale-to-zero for a process cell is literal: the child OS process is
killed; state lives in the CAS; the next message respawns the process
from the store.

### 2. The capability bridge is three layers, stated as such

| layer | system | checked where | guarantee |
|---|---|---|---|
| language | sieveplate CapTable (Goblins-style object refs) | vat turn context; re-checked at process-cell boundary | authority routing, attenuation, revocation — in-process |
| OS | seccomp/Landlock/rlimits | kernel, per process cell | what the *code executing the cell* can do to the machine, regardless of bugs in it |
| kernel (port target) | seL4 capabilities | seL4 kernel, per protection domain | what a cell can do to other cells' memory/IPC on the seL4 port |

They are NOT one system and do not "map directly". The language table
routes authority; the OS layer bounds blast radius if the language layer
(or the cell) is buggy; the seL4 layer will bound it architecturally on
the port target. Bridging language→seL4 caps is explicit adapter work on
the port (see `platforms/sel4/README.md`) and is **not** formally
verified — the seL4 proofs cover the kernel, not our bridge.

### 3. Platform matrix (resolves the layer contradiction in the original plan)

The original plan stacked seL4 under everything while also using eBPF
(a Linux feature) and Firecracker (needs Linux/KVM) — three isolation
substrates with no statement of how they compose. Resolution:

- **Linux host mode (today, fully supported)**: thread/process cells;
  eBPF senses (Linux feature, root-gated, honestly reported when
  unavailable); Firecracker/cloud-hypervisor microVM cells under KVM;
  drivers provided by Linux.
- **seL4 mode (port target)**: vats → Microkit protection domains;
  language caps → seL4 caps via the explicit bridge; **no eBPF**
  (replaced by LionsOS/native drivers); **no Firecracker** (unikernel
  images replace microVM cells). The two modes share L3–L7 unchanged
  because those layers are platform-agnostic.

Layer 1 (senses) is platform-specific by definition. Claiming eBPF
events feed cells "through" seL4 was incoherent; instead each platform
provides its own sense implementations and the pump/fabric above them
are unchanged.

## Consequences

- The capability claim is now *demonstrable*: adversarial tests spawn
  real workers and assert that `socket()` and `open()` fail with EPERM
  inside the jailed process.
- Honest costs: process spawn ~1.1 ms p50, pipe-mediated turn ~71 µs
  (BENCHMARKS.md). The 2026 spec's millisecond-class target still holds.
- Landlock on kernels < 5.13 is reported as `Unsupported` in the
  sandbox report surfaced by the engine — never silently assumed.
