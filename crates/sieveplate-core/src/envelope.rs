//! Envelopes — the wire format of the cell grid (L6 message passing).

use serde::{Deserialize, Serialize};

use crate::port::Port;

/// Reference to a pending reply. Promise ids are minted by the
/// [`crate::promise::Promises`] registry; carrying one in an envelope means
/// "send the reply to this promise, not back to me" — the essence of
/// promise pipelining: the caller does not block, the fabric completes the
/// chain on the caller's behalf.
pub type PromiseId = u64;

/// A message between cells. `kind` is a small string verb
/// (`add`, `get`, `greet`, ...); `payload` is opaque bytes (cells agree on
/// their own codec — the bundled cells use bincode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Unique id. For `__reply` envelopes this is the promise id being resolved.
    pub id: u64,
    pub from: Option<Port>,
    pub to: Port,
    /// Reply target when this message is part of a pipelined call.
    pub reply_to: Option<PromiseId>,
    /// Informational: promise this message logically depends on.
    pub depends_on: Option<PromiseId>,
    pub kind: String,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(to: Port, kind: impl Into<String>, payload: Vec<u8>) -> Self {
        Envelope {
            id: crate::ids::next_id(),
            from: None,
            to,
            reply_to: None,
            depends_on: None,
            kind: kind.into(),
            payload,
        }
    }

    pub fn with_from(mut self, from: Port) -> Self {
        self.from = Some(from);
        self
    }

    pub fn with_reply_to(mut self, pid: PromiseId) -> Self {
        self.reply_to = Some(pid);
        self
    }

    /// Reserved control kinds used by the runtime itself.
    pub const KIND_REPLY: &'static str = "__reply";
    pub const KIND_FAULT: &'static str = "__fault";
    /// Kernel-level wake probe: the vat wakes (restores) the target cell
    /// and replies without invoking the cell's handler.
    pub const KIND_PING: &'static str = "__ping";
    pub fn is_control(&self) -> bool {
        self.kind == Self::KIND_REPLY
            || self.kind == Self::KIND_FAULT
            || self.kind == Self::KIND_PING
    }
}
