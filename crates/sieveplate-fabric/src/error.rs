//! Fabric error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FabricError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame codec error: {0}")]
    Codec(String),

    #[error("peer not connected: {0}")]
    PeerNotConnected(String),

    #[error("no local vat: {0}")]
    NoLocalVat(String),

    // ---- secure link (SIEVE1) ----
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error(
        "replayed or reordered frame (expected seq {expected}, got frame of {frame_len} bytes)"
    )]
    Replay { expected: u64, frame_len: usize },

    #[error("peer key changed for host '{host}': pinned {expected}, got {got}")]
    PeerKeyChanged {
        host: String,
        expected: String,
        got: String,
    },

    #[error("unknown peer host '{host}' (fingerprint {fingerprint}) and strict pinning is on")]
    UnknownPeer { host: String, fingerprint: String },
}

impl From<FabricError> for sieveplate_core::CellError {
    fn from(e: FabricError) -> Self {
        sieveplate_core::CellError::Other(format!("fabric: {e}"))
    }
}
