//! Bundled reference cells.
//!
//! These small cells exercise every runtime capability and double as demo
//! and benchmark subjects:
//! - [`counter::CounterCell`] — transactional counter with deliberate
//!   poison/panic verbs for rollback tests
//! - [`greeter::GreeterCell`] — the Phase-1 "greeter" from the spec
//! - [`echo::EchoCell`] — round-trip payload, used for pipelining
//! - [`kv::KvCell`] — a small key/value store with a larger state
//!
//! Each ships a [`CellFactory`](sieveplate_core::CellFactory) registered
//! under `builtin:<name>`; template descriptors feed the L7 closure hash.

pub mod counter;
pub mod echo;
pub mod greeter;
pub mod kv;

use std::sync::Arc;

use sieveplate_core::TemplateRegistry;

/// Register all bundled cells into a registry.
pub fn register_all(registry: &TemplateRegistry) {
    registry.register("builtin:counter", Arc::new(counter::CounterFactory));
    registry.register("builtin:greeter", Arc::new(greeter::GreeterFactory));
    registry.register("builtin:echo", Arc::new(echo::EchoFactory));
    registry.register("builtin:kv", Arc::new(kv::KvFactory));
}

/// A registry with all bundled cells pre-registered.
pub fn builtin_registry() -> TemplateRegistry {
    let r = TemplateRegistry::new();
    register_all(&r);
    r
}
