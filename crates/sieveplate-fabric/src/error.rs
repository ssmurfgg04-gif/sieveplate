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
}

impl From<FabricError> for sieveplate_core::CellError {
    fn from(e: FabricError) -> Self {
        sieveplate_core::CellError::Other(format!("fabric: {e}"))
    }
}
