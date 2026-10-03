# Contributing to sieveplate

Thanks for looking at the cell grid. The project is young; the fastest way
to help is to make the vertical slice do one more true thing.

## Ground rules

1. **`cargo test --workspace` must pass.** The integration tests encode the
   spec's phase success criteria — don't weaken them.
2. **`cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
   must be clean.** CI enforces both.
3. **No polling in the hot path.** If you added a `loop { sleep; check }`
   in message delivery, you found a bug in your design, not in tokio.
4. **No ambient authority.** New cell APIs must resolve targets through the
   capability table. If a cell can name a thing it has no cap for, the API
   is wrong.
5. **Every failure path must resolve promises.** A call that can hang is a
   distributed bug factory. Fail the promise with a reason.
6. **Rollback is sacred.** Any state change outside a committed turn is a
   bug. If your cell needs effects beyond its state (files, network), route
   them through cells that own those resources.

## Good first contributions

- A new bundled cell (follow `crates/sieveplate-cells/src/counter.rs`;
  register it in `builtin_registry`, give it a content descriptor).
- A new sense source (follow `sources.rs`; push, don't poll).
- Datalog fact projections for new event kinds (`store/src/eventlog.rs`).
- Benchmarks for paths not yet covered.

## Commit style

Short imperative subject (`vat: fail promises on respawn`), body explains
why. Tests for behavior changes; PHASES.md updated if you move a phase
criterion.
