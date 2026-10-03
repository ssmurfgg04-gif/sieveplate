# ADR-0002: Linux-first userspace runtime, seL4 as port target

Status: accepted · Date: 2026-10-03

## Context

The spec's L2 calls for seL4 (formally verified, capability-secured) with
LionsOS-style static composition. Building directly on seL4 first would
mean: cross-compilation toolchains, no std, QEMU-only testing, and weeks
before any actor semantics exist at all. It would also make the "fallback"
the spec's own risk register recommends — "start with minimal integration;
fallback to Linux + BPF-LSM" — the de facto plan.

## Decision

Build the full stack as a **Linux-first Rust userspace runtime** whose
semantics deliberately mirror seL4's model, and treat seL4 as a **port
target**:

- Capability tables (`core::cap`) are CNode-shaped: slot indices, mint,
  attenuate (subset-only), revoke (immediate). A Microkit PD maps 1:1
  (`platforms/sel4/`).
- Vats are protection-domain-shaped: single-threaded event loops owning
  private state, communicating only by messages.
- The fabric's `Route` trait is the IPC boundary; on seL4 it is backed by
  kernel IPC, here by mpsc/TCP.

## Consequences

- The whole architecture is testable with `cargo test` on any laptop.
- We get honest isolation boundaries *within* the process (cells can only
  speak through caps) but **not** MMU isolation between cells — documented
  in SECURITY.md; true mutually-distrusting isolation waits for the port.
- The port remains real work (alloc, async executor, store on seL4), but
  it is mechanical in its interfaces rather than architectural.
