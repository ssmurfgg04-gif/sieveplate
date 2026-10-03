//! Core error type.

use thiserror::Error;

/// Errors flowing through cells, vats and the engine.
#[derive(Debug, Error, Clone)]
pub enum CellError {
    #[error("capability denied: no {needed} right for target {target}")]
    NoCap { needed: String, target: String },

    #[error("cell not found: {0}")]
    NotFound(String),

    #[error("vat closed: {0}")]
    VatClosed(String),

    #[error("unknown template: {0}")]
    UnknownTemplate(String),

    #[error("cell panicked: {0}")]
    Panicked(String),

    #[error("poison message (deliberate failure for rollback testing)")]
    Poison,

    #[error("store error: {0}")]
    Store(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("{0}")]
    Other(String),
}

impl From<sieveplate_store::StoreError> for CellError {
    fn from(e: sieveplate_store::StoreError) -> Self {
        CellError::Store(e.to_string())
    }
}

impl From<std::io::Error> for CellError {
    fn from(e: std::io::Error) -> Self {
        CellError::Io(e.to_string())
    }
}
