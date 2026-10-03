//! The `Cell` trait — the fundamental unit of computation (L5 "Tissue").
//!
//! A cell is a self-contained actor with private state and a mailbox.
//! Handlers run inside *transactional turns*: the vat snapshots the cell's
//! state before the turn and rolls it back if the handler errors or panics.
//! Cells never block on other cells — they `ctx.send()` (async) or
//! `ctx.call()` (promise-pipelined) and finish their turn.

use sieveplate_store::Hash;

use crate::envelope::Envelope;
use crate::error::CellError;
use crate::port::Port;
use crate::promise::{Continuation, Promises};
use crate::route::Route;
use std::sync::Arc;

/// A type-erased cell living in a vat.
pub type BoxedCell = Box<dyn Cell + Send>;

/// Turn context: everything a handler may touch. Sends are capability-
/// checked here (the L2 discipline, userspace edition).
pub struct TurnCtx<'a> {
    pub(crate) outbox: &'a mut Vec<Envelope>,
    pub(crate) reply: &'a mut Option<Vec<u8>>,
    pub(crate) caps: &'a crate::cap::CapTable,
    pub(crate) fabric: Arc<dyn Route>,
    pub(crate) promises: Arc<Promises>,
    pub(crate) self_port: Port,
}

impl<'a> TurnCtx<'a> {
    /// Capability-checked async send (fire-and-forget).
    pub fn send(&mut self, to: &str, kind: &str, payload: Vec<u8>) -> Result<(), CellError> {
        let target = crate::port::parse_port(to, &self.self_port.host, &self.self_port.vat)?;
        // Implicit self-authority; otherwise a SEND capability is required.
        if target != self.self_port && !self.caps.grants(&target, crate::cap::Rights::SEND) {
            return Err(CellError::NoCap {
                needed: "send".into(),
                target: target.to_path(),
            });
        }
        self.outbox
            .push(Envelope::new(target, kind, payload).with_from(self.self_port.clone()));
        Ok(())
    }

    /// Capability-checked pipelined call: returns a promise id immediately.
    /// The reply (a `__reply` envelope from the target's vat) resolves the
    /// promise. Await it via [`Self::promise_receiver`] — or don't: pipe
    /// another call onto it with [`Self::pipe`].
    pub fn call(
        &mut self,
        to: &str,
        kind: &str,
        payload: Vec<u8>,
    ) -> Result<crate::envelope::PromiseId, CellError> {
        let target = crate::port::parse_port(to, &self.self_port.host, &self.self_port.vat)?;
        if target != self.self_port && !self.caps.grants(&target, crate::cap::Rights::CALL) {
            return Err(CellError::NoCap {
                needed: "call".into(),
                target: target.to_path(),
            });
        }
        let pid = self.promises.mint();
        self.outbox.push(
            Envelope::new(target, kind, payload)
                .with_from(self.self_port.clone())
                .with_reply_to(pid),
        );
        Ok(pid)
    }

    /// Pipe a follow-up message onto a promise: when the promise resolves,
    /// the fabric sends `kind` with the resolved payload to `to`. True
    /// pipelining: no local waiting, the chain completes in the fabric.
    pub fn pipe(
        &self,
        pid: crate::envelope::PromiseId,
        to: &str,
        kind: &str,
    ) -> Result<crate::envelope::PromiseId, CellError> {
        let target = crate::port::parse_port(to, &self.self_port.host, &self.self_port.vat)?;
        let next = self.promises.mint();
        let cont = Continuation {
            to: target.clone(),
            kind: kind.to_string(),
            next: Some(next),
        };
        // The fabric owns delivery of fired continuations; queue it.
        let _ = self.fabric.pipe_continuation(pid, cont);
        Ok(next)
    }

    /// Register a local waiter for a promise minted by this cell.
    /// The receiver yields `Ok(payload)` on success or `Err(reason)` when
    /// the call's turn rolled back (or the target was unreachable).
    pub fn promise_receiver(
        &self,
        pid: crate::envelope::PromiseId,
    ) -> tokio::sync::oneshot::Receiver<crate::promise::PromiseResult> {
        self.promises.waiter(pid)
    }

    /// Set the automatic reply payload. If the incoming envelope carried a
    /// `reply_to` promise, the vat sends a `__reply` with this payload when
    /// the turn commits — no explicit send needed.
    pub fn set_reply(&mut self, payload: Vec<u8>) {
        *self.reply = Some(payload);
    }

    /// The port of the cell currently running this turn.
    pub fn self_port(&self) -> &Port {
        &self.self_port
    }

    /// Live capabilities (for audit/debug inside handlers).
    pub fn capabilities(&self) -> Vec<(u32, crate::cap::Cap)> {
        self.caps.list()
    }
}

/// A sleeping-actor persistence policy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SleepPolicy {
    /// Evict the cell (scale to zero) after this idle duration. `None` = never.
    pub after_idle_ms: Option<u64>,
    /// Persist a fresh snapshot to the store after every committed turn.
    pub persist_on_turn: bool,
}

impl Default for SleepPolicy {
    fn default() -> Self {
        SleepPolicy {
            after_idle_ms: None,
            persist_on_turn: true,
        }
    }
}

/// Supervisor policy (one_for_one with exponential backoff).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestartPolicy {
    pub max_restarts: u32,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy {
            max_restarts: 3,
            backoff_base_ms: 10,
            backoff_max_ms: 2_000,
        }
    }
}

/// The cell trait. `S` implementations are type-erased into [`BoxedCell`].
#[async_trait::async_trait]
pub trait Cell: Send {
    /// Handle one message inside a transactional turn.
    /// Return `Err` (or panic) to roll the cell's state back.
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError>;

    /// Serialize the cell's private state (the rollback/persist payload).
    fn snapshot(&self) -> Result<Vec<u8>, CellError>;

    /// Restore private state from bytes.
    fn restore(&mut self, data: &[u8]) -> Result<(), CellError>;
}

/// Factory rebuilding cells from a template id (used for wake-from-store
/// and supervisor restarts).
pub trait CellFactory: Send + Sync {
    fn build(&self) -> Result<BoxedCell, CellError>;
    /// Content descriptor of the template; contributes to the system
    /// closure hash (L7: system_state = f(input_hashes)).
    fn descriptor(&self) -> String;
}

/// Registry of templates by id (e.g. `builtin:counter`).
#[derive(Default)]
pub struct TemplateRegistry {
    templates: std::sync::RwLock<std::collections::BTreeMap<String, Arc<dyn CellFactory>>>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, id: impl Into<String>, factory: Arc<dyn CellFactory>) {
        self.templates
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.into(), factory);
    }

    pub fn build(&self, id: &str) -> Result<BoxedCell, CellError> {
        self.templates
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .ok_or_else(|| CellError::UnknownTemplate(id.to_string()))?
            .build()
    }

    pub fn descriptor(&self, id: &str) -> Option<String> {
        self.templates
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .map(|f| f.descriptor())
    }

    /// All registered template ids.
    pub fn ids(&self) -> Vec<String> {
        self.templates
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Content hash over all template descriptors (sorted) — an input to
    /// the declarative closure hash.
    pub fn descriptors_hash(&self) -> Hash {
        let mut buf = String::new();
        for (id, f) in self
            .templates
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            buf.push_str(id);
            buf.push('@');
            buf.push_str(&f.descriptor());
            buf.push('\n');
        }
        sieveplate_store::content_hash(buf.as_bytes())
    }
}
