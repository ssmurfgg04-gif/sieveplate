//! **sieveplate-sysdef** — Layer 7: Declarative System Definition ("the DNA").
//!
//! The entire system is a pure function over content-addressed inputs:
//! `system_state = f(spec, template_descriptors)`. The spec is TOML; the
//! closure hash identifies the exact system; plans are content-addressed
//! objects in the store, which makes *rollback* = apply(previous plan).

mod error;
mod plan;
mod spec;

pub use error::SpecError;
pub use plan::{Plan, PlanDiff, PlanStore};
pub use spec::{CapCfg, CellCfg, NetworkCfg, RouteCfg, SenseCfg, SystemSpec};
