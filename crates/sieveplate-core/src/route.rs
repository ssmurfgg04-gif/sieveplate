//! Route trait — how envelopes leave a vat and cross the grid (L6).
//!
//! Implemented by `sieveplate-fabric::Fabric`, which routes locally to vat
//! mailboxes and remotely over framed TCP. The vat only sees this trait, so
//! the whole stack is transport-agnostic (in-proc, TCP, or — on the seL4
//! port — kernel IPC).

use crate::envelope::{Envelope, PromiseId};
use crate::error::CellError;
use crate::promise::Continuation;

/// Something that can deliver an envelope to its destination vat/host.
#[async_trait::async_trait]
pub trait Route: Send + Sync {
    /// Deliver an envelope. Must not block on the receiver's processing —
    /// enqueue and return (zero-poll, no synchronous round trips).
    async fn deliver(&self, env: Envelope) -> Result<(), CellError>;

    /// Queue a pipelined continuation on a promise. When the promise
    /// resolves, the router delivers the continuation with the resolved
    /// payload (and resolves `cont.next` with the continuation's own reply,
    /// if any). If the promise is already resolved, implementations must
    /// deliver immediately (spawn — this is sync).
    fn pipe_continuation(&self, pid: PromiseId, cont: Continuation) -> Result<(), CellError>;
}

/// Envelope id helper: a stable way to reference an envelope's id in logs.
pub fn env_id(env: &Envelope) -> u64 {
    env.id
}
