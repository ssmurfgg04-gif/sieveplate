//! Promise registry — L6 promise pipelining.
//!
//! The "Sleep Until Shift" / zero-blocking requirement at the orchestration
//! layer: callers never wait on a round trip to keep sending. A call returns
//! a [`PromiseId`]; further messages can be *piped* onto that promise so
//! the fabric forwards them automatically when the reply lands
//! (network-transparent composition in the spirit of Spritely Goblins'
//! promise pipelining and Google Pathways' async dataflow).
//!
//! Promises can also *fail*: the vat resolves a call's promise with an
//! error when the turn rolls back, so callers never hang.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::envelope::PromiseId;
use crate::ids::next_id;

/// Outcome of a promise.
pub type PromiseResult = Result<Vec<u8>, String>;

/// A message template waiting on a promise: when the promise resolves with
/// payload `P`, the fabric sends an envelope to `to` with kind `kind` and
/// payload `P`; its reply resolves `next` (chaining).
#[derive(Debug, Clone)]
pub struct Continuation {
    pub to: crate::Port,
    pub kind: String,
    pub next: Option<PromiseId>,
}

#[derive(Default)]
struct Slot {
    waiter: Option<oneshot::Sender<PromiseResult>>,
    piped: Vec<Continuation>,
    done: Option<PromiseResult>,
}

impl Slot {
    fn settle(&mut self, outcome: PromiseResult) -> Vec<Continuation> {
        // First settlement wins (success or failure).
        if self.done.is_none() {
            self.done = Some(outcome.clone());
        }
        if let (Some(tx), Some(done)) = (self.waiter.take(), &self.done) {
            let _ = tx.send(done.clone());
        }
        // Continuations fire only on success.
        match &self.done {
            Some(Ok(_)) => std::mem::take(&mut self.piped),
            _ => Vec::new(),
        }
    }
}

struct Inner {
    map: Mutex<HashMap<PromiseId, Slot>>,
}

/// Registry of in-flight promises. Share via `Arc`/clone.
#[derive(Clone)]
pub struct Promises {
    inner: Arc<Inner>,
}

impl Default for Promises {
    fn default() -> Self {
        Self::new()
    }
}

impl Promises {
    pub fn new() -> Self {
        Promises {
            inner: Arc::new(Inner {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Mint a fresh promise id. The slot is created eagerly so the promise
    /// is "known" from birth — this also closes the race where a reply
    /// resolves before the caller registers its waiter.
    pub fn mint(&self) -> PromiseId {
        let pid = next_id();
        self.inner
            .map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(pid)
            .or_default();
        pid
    }

    /// Register a waiter. If the promise is already settled, the returned
    /// receiver is immediately ready.
    pub fn waiter(&self, pid: PromiseId) -> oneshot::Receiver<PromiseResult> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.inner.map.lock().unwrap_or_else(|p| p.into_inner());
        let slot = map.entry(pid).or_default();
        match &slot.done {
            Some(done) => {
                let _ = tx.send(done.clone());
            }
            None => slot.waiter = Some(tx),
        }
        rx
    }

    /// Pipe a continuation onto a promise. If already resolved, the
    /// continuation is returned to the caller for immediate delivery.
    pub fn pipe(&self, pid: PromiseId, cont: Continuation) -> Option<Continuation> {
        let mut map = self.inner.map.lock().unwrap_or_else(|p| p.into_inner());
        let slot = map.entry(pid).or_default();
        match &slot.done {
            Some(Ok(_)) => Some(cont), // fire now
            Some(Err(_)) => None,      // failed promise: continuation dropped
            None => {
                slot.piped.push(cont);
                None
            }
        }
    }

    /// Resolve a promise with a payload, waking the waiter and returning
    /// piped continuations for delivery. First settlement wins. Unknown
    /// ids (promises minted by a *foreign* registry — e.g. a reply hopping
    /// through this host) are ignored without allocating state.
    pub fn resolve_notify(&self, pid: PromiseId, payload: Vec<u8>) -> Vec<Continuation> {
        let mut map = self.inner.map.lock().unwrap_or_else(|p| p.into_inner());
        if !map.contains_key(&pid) {
            return Vec::new();
        }
        let slot = map.get_mut(&pid).unwrap();
        slot.settle(Ok(payload))
    }

    /// Fail a promise (rolled-back turn, unknown cell, ...). The waiter
    /// receives the error; piped continuations are dropped. Unknown ids are
    /// ignored (foreign registry).
    pub fn resolve_fail(&self, pid: PromiseId, reason: String) {
        let mut map = self.inner.map.lock().unwrap_or_else(|p| p.into_inner());
        if !map.contains_key(&pid) {
            return;
        }
        let slot = map.get_mut(&pid).unwrap();
        slot.settle(Err(reason));
    }

    /// Peek at a resolved promise's payload without registering a waiter.
    /// `None` for failed or pending promises.
    pub fn peek(&self, pid: PromiseId) -> Option<Vec<u8>> {
        self.inner
            .map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&pid)
            .and_then(|s| s.done.clone())
            .and_then(|r| r.ok())
    }

    /// Drop a promise (e.g. after timeout) so late continuations fail fast.
    pub fn cancel(&self, pid: PromiseId) {
        self.inner
            .map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port::Port;

    fn cont() -> Continuation {
        Continuation {
            to: Port::new("h", "v", "c"),
            kind: "add".into(),
            next: None,
        }
    }

    #[tokio::test]
    async fn wait_resolves() {
        let p = Promises::new();
        let pid = p.mint();
        let rx = p.waiter(pid);
        p.resolve_notify(pid, b"hello".to_vec());
        assert_eq!(rx.await.unwrap().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn failure_propagates() {
        let p = Promises::new();
        let pid = p.mint();
        let rx = p.waiter(pid);
        p.resolve_fail(pid, "rolled back".into());
        assert_eq!(rx.await.unwrap().unwrap_err(), "rolled back");
    }

    #[tokio::test]
    async fn late_piping_fires_immediately() {
        let p = Promises::new();
        let pid = p.mint();
        p.resolve_notify(pid, b"x".to_vec());
        assert!(p.pipe(pid, cont()).is_some());
    }

    #[tokio::test]
    async fn early_piping_queues_until_resolve() {
        let p = Promises::new();
        let pid = p.mint();
        assert!(p.pipe(pid, cont()).is_none());
        let conts = p.resolve_notify(pid, b"x".to_vec());
        assert_eq!(conts.len(), 1);
    }

    #[tokio::test]
    async fn failed_promises_drop_continuations() {
        let p = Promises::new();
        let pid = p.mint();
        assert!(p.pipe(pid, cont()).is_none());
        p.resolve_fail(pid, "no".into());
        assert!(p.peek(pid).is_none());
        // late piping on a failed promise returns None (dropped, not fired)
        assert!(p.pipe(pid, cont()).is_none());
    }

    #[tokio::test]
    async fn wait_and_pipe_coexist() {
        let p = Promises::new();
        let pid = p.mint();
        let rx = p.waiter(pid);
        assert!(p.pipe(pid, cont()).is_none());
        let conts = p.resolve_notify(pid, b"z".to_vec());
        assert_eq!(conts.len(), 1);
        assert_eq!(rx.await.unwrap().unwrap(), b"z");
    }
}
