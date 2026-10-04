# WASM cells (Wasmtime / WASI preview 1)

A Sieveplate cell does not have to be a Rust template or a jailed OS
process: it can be **any program compiled to `wasm32-wasip1`**. The
runtime executes one WASI turn per message — the guest reads a JSON line
from stdin, touches its single `/state` directory, and writes JSON
messages to stdout (the frozen **SIEVE-WASI ABI v1**, specified in
[`docs/wasm-abi.md`](../../docs/wasm-abi.md)).

`counter/` is the reference guest: a real Rust program (serde_json +
base64) handling `add`, `get` and `echo`. The compiled module is
committed at `examples/cells/counter.wasm` so tests and demos need no
wasm toolchain.

## Rebuild the committed module

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release \
  --manifest-path examples/wasm-cells/counter/Cargo.toml
cp examples/wasm-cells/counter/target/wasm32-wasip1/release/wasm-counter-cell.wasm \
  examples/cells/counter.wasm
```

## Use it declaratively

```toml
[[cell]]
name = "counter"
vat = "core"
template = "wasm:examples/cells/counter.wasm"   # or cas:<hash> of the module
isolation = "wasm"
[[cell.caps]]
to = "core/counter"
rights = ["send", "call"]
```

Then:

```bash
sieve run -f examples/system-wasm.toml
```

## Why wasm cells

- **Language-agnostic**: any toolchain targeting `wasm32-wasip1` (Rust,
  C, Zig, AssemblyScript, TinyGo...) produces cells.
- **Isolation**: the guest cannot open sockets, fork, or touch host
  memory; its only filesystem reach is the one preopened directory, and
  every outgoing message crosses the parent's capability check.
- **Structural scale-to-zero**: instances live for exactly one turn —
  between messages a cell is just a cached module plus a content hash.
