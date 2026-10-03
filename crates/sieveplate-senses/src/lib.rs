//! **sieveplate-senses** — Layer 1: the Sensory Layer ("the Nerves").
//!
//! Hardware/external events become cell messages with zero polling in the
//! hot path: sources are event-driven (async timers, TCP reads, inotify).
//! The eBPF bridge (`ebpf` module) loads a real BPF program via `bpf(2)`
//! and feeds packet events straight into the pump — root-gated, reported
//! honestly when privileges are missing.
//!
//! Every source yields [`Signal`]s; the [`pump::SensePump`] maps them to
//! envelopes through declarative routes and hands them to the fabric.
//! A message to a sleeping cell wakes it — the Phase-3 success criterion.

pub mod pump;
pub mod sources;

#[cfg(target_os = "linux")]
pub mod ebpf;

pub use pump::{SensePump, SignalRoute};
pub use sources::{spawn_file_tail, spawn_tcp, spawn_timer, Signal, SignalTx};
