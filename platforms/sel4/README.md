# platforms/sel4 — the seL4 / Microkit port target

Status: **port target — CI builds a real seL4 system and boots it under
QEMU as a smoke test.** The full runtime port is in progress; the honest
boundary statements live in
[ADR-0005](../../docs/adr/0005-process-cells-capability-bridge.md).

## What CI actually proves

The `sel4` job downloads the pinned Microkit SDK (2.0.1), compiles
`cell.c` (one protection domain hosting the reference cell skeleton)
against `libmicrokit`, links a `loader.img` with the seL4 kernel, boots
it under `qemu-system-aarch64` (virt, virtualization=on), and requires
the `sieveplate-seL4-cell boot OK` banner on the console. If seL4 stops
booting, or the system description breaks, the job goes red.

## Platform matrix (why there is no eBPF or Firecracker "under seL4")

The original plan stacked seL4 under everything while also using eBPF
(a Linux feature) and Firecracker (needs Linux/KVM). That was incoherent.
Per platform:

| capability | Linux host mode (primary) | seL4 mode (this port) |
|---|---|---|
| cell isolation | thread cells + seccomp/Landlock process cells | Microkit protection domains |
| capability enforcement | language CapTable + OS sandbox | language CapTable + **seL4 kernel caps** |
| senses (L1) | timer/TCP/inotify/eBPF (Linux) | IRQ-driven drivers posting to shared-memory rings |
| microVM cells | Firecracker / cloud-hypervisor under KVM | **not applicable** — unikernel images replace them |
| drivers | Linux | LionsOS/native driver PDs (a "system VM for drivers" fallback is documented but keeps its big-TCB cost on the ledger) |

L3–L7 (store, hearth, core semantics, fabric model, sysdef) are
platform-agnostic and shared unchanged.

## Mapping

| Sieveplate concept | seL4 / Microkit concept |
|---|---|
| Vat | Protection Domain (PD), one event loop, no shared memory |
| Cell | Private state inside a PD; cross-PD cells = cross-PD message |
| Envelope / `Route` | seL4 IPC (endpoint capabilities); `deliver()` → `seL4_Call` on the endpoint cap |
| `CapTable` (slot indices, insert/attenuate/revoke) | CNode slots (CPtrs); `mint`/`copy` with rights masking / `revoke` — semantics already identical |
| `Rights` bits | seL4 cap rights (Grant/Read/Write) + app-level policy bits |
| Fabric (L6) | Static route table fixed at build time (LionsOS composition discipline) |
| Content store (L3) | Region in a memory PD or virtio-blk-backed partition; CAS layout unchanged |
| `__ping` wake probe | kernel IPC ping; restore-from-CAS stays userspace logic |

## The capability bridge — stated as a bridge, not a mapping

Goblins-style capabilities (our `CapTable`: unforgeable authority tokens
= slot indices checked in the turn context) and seL4 kernel capabilities
(unforgeable kernel objects) are **different systems that do not "map
directly" onto each other**. The bridge is adapter code with its own
trust assumptions:

- a `Cap { target, rights }` is minted as a CNode slot with matching
  rights at cell creation;
- `attenuate` → `seL4_CNode_Copy` with a rights mask;
- `revoke` → `seL4_CNode_Revoke` + `Delete`;
- envelope delivery uses endpoint caps; a cell can only send along caps
  it holds, which the kernel enforces *in addition to* the language
  table.

The seL4 proofs cover the **kernel** on specific hardware configs (and
multicore support is the weak spot). They do NOT cover this bridge, the
runtime, or the cells. "Verified" is claimed only at that exact scope.

## What the full port must supply

1. **An async executor on seL4** (no std): timer-from-IRQ + a minimal
   `alloc`. The vat loop only needs mpsc/oneshot-shaped primitives —
   provide shims.
2. **Persistent storage for the CAS** (virtio-blk via a system PD, or a
   static partition; the store is append-only by design).
3. **Driver PDs** for the senses (no eBPF on seL4 — device IRQs post
   into the same `Signal` pump, so L5+ is unchanged).
4. **The cap bridge above**, with tests at the bridge boundary.

## Build + boot locally

```sh
# with a Microkit SDK (2.0.1) and QEMU installed
platforms/sel4/build.sh /path/to/microkit-sdk-2.0.1 qemu_virt_aarch64
platforms/sel4/boot-smoke.sh
```
