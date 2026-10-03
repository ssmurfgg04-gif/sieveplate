//! **sieveplate-senses** — Layer 1: the Sensory Layer ("the Nerves").
//!
//! Hardware/external events become cell messages with zero polling in the
//! hot path: sources are event-driven (async timers, TCP reads, inotify),
//! and the eBPF bridge consumes kernel events from a JSON-lines stream
//! written by `ebpf/run.sh` (bpftool-based reference implementation).
//!
//! Every source yields [`Signal`]s; the [`pump::SensePump`] maps them to
//! envelopes through declarative routes and hands them to the fabric.
//! A message to a sleeping cell wakes it — the Phase-3 success criterion.

pub mod pump;
pub mod sources;

pub use pump::{SensePump, SignalRoute};
pub use sources::{spawn_file_tail, spawn_tcp, spawn_timer, Signal, SignalTx};
