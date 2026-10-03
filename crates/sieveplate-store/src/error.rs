//! Store-wide error type.

use thiserror::Error;

/// Errors surfaced by the content-addressable store, event log and Datalog engine.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("integrity violation: content hash mismatch for {expected} (read {found})")]
    Integrity { expected: String, found: String },

    #[error("malformed hash: {0}")]
    MalformedHash(String),

    #[error("json codec error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("datalog error: {0}")]
    Datalog(String),

    #[error("event log corrupt at seq {seq}: {why}")]
    Corrupt { seq: u64, why: String },
}
