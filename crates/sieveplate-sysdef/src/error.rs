//! Spec error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("toml parse: {0}")]
    Toml(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("io: {0}")]
    Io(String),

    #[error("store: {0}")]
    Store(String),
}

impl From<sieveplate_engine::host::CellSpec> for SpecError {
    fn from(_: sieveplate_engine::host::CellSpec) -> Self {
        SpecError::Validation("internal conversion error".into())
    }
}
