# SIEVE-WASI Guest ABI v1 (frozen)

This document defines the wire contract between the Sieveplate runtime
(host) and a WebAssembly cell (guest) executed by Wasmtime with WASI
preview 1. **Version 1 is frozen**: once released, any change is additive
(new optional JSON fields, new stdout ops) — never a reinterpretation of
existing fields. Guests written against v1 keep working forever.

Reference guest: `examples/wasm-cells/counter` (Rust → `wasm32-wasip1`),
committed module: `examples/cells/counter.wasm`.

## Isolation model

A guest receives, per turn:

- stdin  — one JSON line (the turn request, below)
- stdout — free-form JSON lines (the turn's messages, below)
- stderr — captured, logged by the host (not part of the protocol)
- one preopened directory, guest path `/state`, read-write — **the only
  filesystem capability**
- nothing else: no sockets, no network, no ambient authority, no access
  to other cells' state

Messages the guest emits are re-checked against the parent-side
capability table before routing (the same authority boundary process
cells cross).

## Turn lifecycle

A wasm cell has no resident instance. For every envelope the fabric
delivers, the host:

1. materializes `/state/state.bin` from the cell's persisted snapshot
   (content-addressed, verify-on-read) if one exists;
2. instantiates a fresh module instance with the WASI context above;
3. calls `_start`;
4. reads stdout messages, re-checks capabilities, routes them;
5. unless the guest reported `{"op":"error"}`, reads `/state/state.bin`
   and persists it to the content store (the cell's new snapshot).

Consequences: state lives ONLY in `/state/state.bin` (guests may use any
byte format they like; the host is content-agnostic). Between turns the
cell occupies nothing — scale-to-zero is structural, and waking is the
next turn.

## stdin — turn request (one JSON line per turn)

```json
{"op":"init","state_b64":"<base64>"|null}
{"op":"turn","kind":"<verb>","payload_b64":"<base64>","reply_to":<u64>|null,"from":"<host/vat/cell>"|null}
```

- `init` is sent instead of `turn` only when a caller supplies restored
  state at creation time; the guest seeds its state file from it.
- `kind` is the envelope verb the guest handler dispatches on.
- `reply_to` is present when the sender expects a reply resolving that
  promise id.
- `payload_b64` decodes to the raw envelope payload bytes.
- `from` is the sender's port path (informational; replies go back by
  promise id, not by addressing).

## stdout — guest messages (one JSON object per line)

```json
{"op":"reply","id":<u64>,"payload_b64":"<base64>"}
{"op":"send","to":"<vat/cell or host/vat/cell>","kind":"<verb>","payload_b64":"<base64>","reply_to":<u64>|null}
{"op":"error","message":"<why>"}
```

- `reply` resolves the promise `id` (normally the `reply_to` of the
  current turn) with the payload.
- `send` emits a new envelope — routed only if the parent capability
  table grants it (`send` right for fire-and-forget, `call` when
  `reply_to` is set).
- `error` fails the turn: no state is persisted, and if the turn had a
  `reply_to`, the caller observes the failure.

Unknown fields are ignored; unknown stdout `op`s are logged and ignored —
write a v1 guest and it runs under any later runtime that honors v1.

## Kernel-level operations

`__ping` (the wake probe) never reaches the guest: the manager answers
`pong` directly. `snapshot` is the content hash of the last persisted
state. A guest that turns on messages owns its durability entirely.

## Versioning

- The ABI version travels nowhere on the wire: the contract above IS v1.
- Future v2 (if ever) would add an `{"abi":2}` field on the turn request;
  v1 guests ignore it and keep working.
