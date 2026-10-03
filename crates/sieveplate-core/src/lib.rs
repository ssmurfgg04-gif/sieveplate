//! **sieveplate-core** — Layer 5: the Actor Cell Substrate ("the Tissue").
//!
//! The fundamental unit of computation is the *cell*: a self-contained,
//! transactional, persistent actor. Cells live in *vats* (single-threaded
//! event loops with transactional turns), sleep when idle (zero CPU), and
//! hold *capability tables* (no ambient authority — L2 semantics in
//! userspace).
//!
//! Layout:
//! - [`cell::Cell`] / [`cell::TurnCtx`] — the actor trait and turn context
//! - [`vat`] — the transactional vat event loop + sleeping actors
//! - [`cap`] — capability tables (mint / attenuate / revoke)
//! - [`promise`] — promise pipelining primitives (L6)
//! - [`route`] — the delivery abstraction implemented by the fabric
//! - [`metrics`] — counters + latency summaries (Phase 5 observability)

pub mod cap;
pub mod cell;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod metrics;
pub mod port;
pub mod promise;
pub mod route;
pub mod vat;

pub use cap::{Cap, CapTable, Rights};
pub use cell::{
    BoxedCell, Cell, CellFactory, RestartPolicy, SleepPolicy, TemplateRegistry, TurnCtx, TurnRunner,
};
pub use envelope::{Envelope, PromiseId};
pub use error::CellError;
pub use metrics::Metrics;
pub use port::{parse_port, Port};
pub use promise::{Continuation, Promises};
pub use route::Route;
pub use vat::{spawn as spawn_vat, CellStub, VatCtrl, VatDeps, VatHandle, VatInput, VatStatus};
