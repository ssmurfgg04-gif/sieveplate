# ADR-0008: Wasmtime/WASI as a cell template kind

Status: implemented
Date: 2026-10

## Context

Cells existed in two isolation modes: `thread` (in-vat actor) and
`process` (jailed OS process, seccomp + Landlock, ADR-0005). A third
kind was requested: **Wasmtime/WASI** — language-agnostic cells whose
isolation is the WebAssembly sandbox itself.

## Decision

### Isolation mode `wasm`

```toml
[[cell]]
name = "counter"
template = "wasm:examples/cells/counter.wasm"   # or cas:<hash>
isolation = "wasm"
```

- Modules run on **Wasmtime** with **WASI preview 1**.
- Guests are ordinary `wasm32-wasip1` binaries: any language that can
  read stdin, write stdout and touch one file is a cell authoring
  environment (the reference guest is Rust; C/Zig/TinyGo/AssemblyScript
  work the same way).
- **One turn = one fresh instance.** The host materializes the cell's
  persisted state into a preopened `/state` directory, feeds the turn as
  one JSON line on stdin, routes the guest's stdout JSON messages
  (capability-rechecked at the parent boundary, exactly like process
  cells), then persists `/state/state.bin` back to the CAS.
- Scale-to-zero is **structural**: between turns a cell is just a cached
  compiled module plus a content hash. No idle process, no sleeping
  instance, nothing to evict.

### The wire contract is FROZEN (SIEVE-WASI ABI v1)

`docs/wasm-abi.md` specifies the exact JSON (stdin turn request, stdout
reply/send/error messages, state-file semantics). Unknown fields and
unknown stdout ops are ignored — v1 guests run under any later runtime
that honors v1. A golden test would be redundant here; the ABI document
is the contract, and the committed `counter.wasm` fixture pins it
end-to-end in tests.

### Capability model

The guest has no sockets, no fork, no host memory access; its only
filesystem reach is the ONE preopened directory. Outgoing envelopes cross
the parent CapTable (`send`/`call` rights) before routing — the guest's
own view is advisory. Wasm cells therefore uphold the same
no-ambient-authority rule as every other isolation kind.

## Alternatives rejected

- **WASI Preview 2 / component model**: richer, but the p1 stdio+state
  contract is simpler to freeze and audit; p2 can layer on later as an
  additive ABI version (the doc reserves `{"abi":2}`).
- **Raw memory ABI** (`sieve_alloc`/`sieve_turn` exports): faster
  per-turn, but requires a guest-side allocator in every language and
  couples cells to host memory layout — worse for the "any language"
  goal.
- **Resident instances** (instantiate once, call a `turn` export
  repeatedly): faster still, but breaks structural scale-to-zero and
  gives guests persistent host memory — a weaker sandbox story.

## Measured cost (honest numbers)

A wasm turn includes instance creation: measured **~2.1 ms p50**
(`/tmp` demo, release build) — dominated by instantiation. Thread cells
remain the low-latency path (µs); wasm cells buy language freedom and
sandbox strength. Every number in `BENCHMARKS.md` states what it
measures.

## Consequences

- `sieveplate-engine::wasm_cell` (manager), `Isolation::Wasm`, spec
  validation for the `wasm:` template prefix.
- Tests: `crates/sieveplate-ctl/tests/wasm.rs` (turn/snapshot/
  scale-to-zero/wake, error isolation, coexistence with thread cells).
- `wasmtime` is a hard workspace dependency; debug builds disable debug
  info (`[profile.dev] debug = 0`) to keep linking tractable.
