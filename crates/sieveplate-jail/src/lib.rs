//! **sieveplate-jail** — real process-isolated cells.
//!
//! A *process cell* is a cell that runs in its own OS process under a
//! kernel-enforced sandbox:
//!
//! | mechanism | what it bounds | status |
//! |---|---|---|
//! | seccomp (default-deny allowlist) | syscalls: no `open`, no `socket`, no `clone`/`fork`/`execve` | any Linux ≥ 3.17, unprivileged |
//! | Landlock (best-effort) | filesystem view (read-only, granted paths only) | kernel ≥ 5.13, else reported unsupported |
//! | rlimit AS | address space | any Linux |
//! | mediated stdio pipe | the only channel out: every envelope is re-checked by the parent's CapTable | always |
//!
//! The protocol and supervision live in [`proto`] / [`parent`]; the worker
//! side in [`worker`]; the sandbox in [`sandbox`]. The honest enforcement
//! report ([`sandbox::SandboxReport`]) is surfaced by the engine, so the
//! capability story is precise: language-level caps in the vat, kernel-
//! level confinement around process cells, and no claim that one replaces
//! the other (ADR-0005).

pub mod parent;
pub mod proto;
pub mod sandbox;
pub mod worker;

pub use parent::JailProc;
pub use sandbox::{LandlockStatus, SandboxError, SandboxPolicy, SandboxReport};
pub use worker::run_worker;
