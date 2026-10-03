//! Hearth errors.

use sieveplate_store::Hash;

#[derive(Debug, thiserror::Error)]
pub enum HearthError {
    #[error("store error: {0}")]
    Store(#[from] sieveplate_store::StoreError),

    #[error("commit {0} not found")]
    CommitNotFound(Hash),

    #[error("tree {0} not found")]
    TreeNotFound(Hash),

    #[error("branch '{0}' not found")]
    BranchNotFound(String),

    #[error("branch '{0}' already exists")]
    BranchExists(String),

    #[error("delta {0} does not apply to base {1}: {2}")]
    DeltaMismatch(Hash, Hash, String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
