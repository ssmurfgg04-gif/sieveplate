# platforms/sel4 — the seL4 / Microkit port target

Status: **port target — not built in this repository.**

This directory documents how the userspace runtime maps onto a formally
verified seL4 foundation (LionsOS architecture, seL4 Microkit protection
domains). The userspace semantics were chosen to make this port
mechanical rather than architectural.

## Mapping

| Sieveplate concept | seL4 / Microkit concept |
|---|---|
| Vat | Protection Domain (PD), one event loop, no shared memory |
| Cell | Private state inside a PD; cross-PD cells = cross-PD message |
| Envelope / `Route` | seL4 IPC (endpoint capabilities); `deliver()` → `seL4_Call` on the endpoint cap |
| `CapTable` (slot indices, insert/attenuate/revoke) | CNode slots (CPtrs); `mint`/`copy` with rights masking/`revoke` — semantics already identical |
| `Rights` bits | seL4 cap rights (Grant/Read/Write) + app-level policy bits |
| Fabric (L6) | Static route table fixed at build time (LionsOS composition discipline) |
| Content store (L3) | Region in a memory PD or virtio-blk-backed partition; CAS layout unchanged |
| Sense sources (L1) | IRQ-driven eBPF-equivalent: device drivers post to shared-memory rings, wake vats (no polling) |
| `__ping` wake probe | kernel IPC ping; restore-from-CAS is userspace logic, unchanged |

## What the port must supply

1. **An async executor on seL4** (no std): timer-from-IRQ + a minimal
   `alloc`. The vat loop is runtime-agnostic by construction (it only
   needs `tokio`'s mpsc/oneshot — provide shims).
2. **Persistent storage for the CAS** (virtio-blk via the system PD, or a
   static partition; the store is append-only by design).
3. **A build-time composition step** (Microkit `metaprogram`) that fixes
   the vat/PD and route table — mirrors `sieveplate-sysdef`'s Plan,
   evaluated at build time instead of run time.

## Skeleton system description (Microkit 2.x style)

See `cell.system`. It sketches two PDs: `core_vat` (runs cells) and
`store` (owns the CAS region), connected by two endpoints (requests,
replies) — the minimum viable tissue.

## Why not build seL4 first

See `docs/adr/0002-linux-first-sel4-port-target.md`. The short version:
the spec's own risk register calls for the Linux fallback first, and every
interface here is shaped so the port is an implementation swap, not a
redesign.
