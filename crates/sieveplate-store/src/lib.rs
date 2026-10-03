//! **sieveplate-store** — Layer 3 of the Sieveplate stack: the
//! Content-Addressable Semantic Store ("the Memory").
//!
//! Three cooperating pieces:
//! 1. [`cas::ContentStore`] — immutable objects addressed by SHA-256.
//!    Actor snapshots, cell templates and declarative system plans all live here.
//! 2. [`eventlog::EventLog`] — append-only, hash-chained system history
//!    (tamper-evident; verified on open).
//! 3. [`datalog`] — embedded Datalog engine for semantic/temporal queries
//!    over the projected event log.

pub mod cas;
pub mod datalog;
pub mod error;
pub mod eventlog;

pub use cas::{content_hash, ContentStore, Hash, StoreStats};
pub use datalog::{parse_program, query as datalog_query, Fact, Rule, Term};
pub use error::StoreError;
pub use eventlog::{EventLog, EventRecord};
