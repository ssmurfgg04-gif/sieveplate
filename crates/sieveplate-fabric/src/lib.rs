//! **sieveplate-fabric** — Layer 6: Asynchronous Dataflow Orchestration
//! ("the Nervous System").
//!
//! The fabric routes envelopes between cells with no central scheduler and
//! no polling:
//! - **local**: envelope → vat mailbox (mpsc)
//! - **remote**: envelope → length-prefixed bincode frame over TCP
//! - **promises**: replies resolve promises; piped continuations fire
//!   automatically, so a caller can compose multi-hop chains without ever
//!   blocking (the Pathways/Goblins pattern)

pub mod error;
mod net;
mod router;

pub use error::FabricError;
pub use net::{connect_peer, frame, serve, unframe, Network};
pub use router::Fabric;

use sieveplate_core::{CellError, Port, PromiseId, Promises};

/// Build the canonical id for a host alias + listener address.
pub fn peer_id(host: &str) -> String {
    host.to_string()
}

/// Convenience: a promise to await with timeout.
pub async fn promise_value(
    promises: &Promises,
    pid: PromiseId,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, CellError> {
    let rx = promises.waiter(pid);
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(reason))) => Err(CellError::Other(reason)),
        Ok(Err(_)) => Err(CellError::Other("promise dropped".into())),
        Err(_) => Err(CellError::Timeout(timeout.as_millis() as u64)),
    }
}

/// Destination port + verb for a pipelined continuation.
pub fn continuation(
    to: Port,
    kind: impl Into<String>,
    next: Option<PromiseId>,
) -> sieveplate_core::Continuation {
    sieveplate_core::Continuation {
        to,
        kind: kind.into(),
        next,
    }
}
