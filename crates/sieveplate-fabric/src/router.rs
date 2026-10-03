//! The Fabric router — local vat mailboxes + remote peers + promises.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use tokio::sync::mpsc;

use sieveplate_core::{
    CellError, Continuation, Envelope, Port, PromiseId, Promises, Route, VatInput,
};

/// Raw frame sender to a remote peer (net.rs fills this).
pub type PeerTx = mpsc::Sender<Vec<u8>>;

struct Inner {
    host: String,
    /// Promises awaiting a REMOTE reply: pid → peer host. On peer
    /// disconnect every entry for that peer fails fast (crash detection).
    inflight: RwLock<HashMap<PromiseId, String>>,
    /// Live link tasks (accept loops + connection pumps). `crash_links`
    /// aborts them all, closing every socket — a host-level crash.
    links: RwLock<Vec<tokio::task::JoinHandle<()>>>,
    /// Listener handle (Network::shutdown aborts this).
    listener: RwLock<Option<tokio::task::JoinHandle<()>>>,
    locals: RwLock<HashMap<String, mpsc::Sender<VatInput>>>,
    /// Per-cell proxies (process cells): raw envelope senders keyed
    /// "vat/cell". Take precedence over whole-vat mailboxes.
    proxies: RwLock<HashMap<String, mpsc::Sender<Envelope>>>,
    peers: RwLock<HashMap<String, PeerTx>>,
    promises: Promises,
}

/// The fabric: one instance per host. Clone freely.
#[derive(Clone)]
pub struct Fabric {
    inner: Arc<Inner>,
}

impl Fabric {
    /// A fabric for `host`. Promise registry is shared with all clones.
    pub fn new(host: impl Into<String>, promises: Promises) -> Self {
        Fabric {
            inner: Arc::new(Inner {
                host: host.into(),
                inflight: RwLock::new(HashMap::new()),
                links: RwLock::new(Vec::new()),
                listener: RwLock::new(None),
                locals: RwLock::new(HashMap::new()),
                proxies: RwLock::new(HashMap::new()),
                peers: RwLock::new(HashMap::new()),
                promises,
            }),
        }
    }

    pub fn host(&self) -> &str {
        &self.inner.host
    }

    pub fn promises(&self) -> &Promises {
        &self.inner.promises
    }

    /// Register a local vat's mailbox.
    pub fn attach_local_vat(&self, vat: &str, tx: mpsc::Sender<VatInput>) {
        self.inner
            .locals
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(vat.to_string(), tx);
    }

    /// Register a per-cell proxy target (process cells): envelopes whose
    /// `to` resolves to this vat/cell pair go to the proxy verbatim.
    pub fn attach_proxy(&self, vat: &str, cell: &str, tx: mpsc::Sender<Envelope>) {
        self.inner
            .proxies
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(format!("{vat}/{cell}"), tx);
    }

    pub fn drop_proxy(&self, vat: &str, cell: &str) {
        self.inner
            .proxies
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&format!("{vat}/{cell}"));
    }

    /// Register (or replace) a remote peer's frame sender.
    pub fn attach_peer(&self, host: &str, tx: PeerTx) {
        self.inner
            .peers
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host.to_string(), tx);
    }

    pub fn drop_peer(&self, host: &str) {
        self.inner
            .peers
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(host);
    }

    /// Crash detection: the link to `host` broke. Every in-flight call to
    /// that peer fails immediately — a caller waits for an ANSWER or a
    /// FAILURE, never for a timeout that hides the difference.
    pub fn peer_disconnected(&self, host: &str) {
        self.drop_peer(host);
        let mut inflight = self
            .inner
            .inflight
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let dead: Vec<PromiseId> = inflight
            .iter()
            .filter(|(_, peer)| peer.as_str() == host)
            .map(|(pid, _)| *pid)
            .collect();
        for pid in dead {
            inflight.remove(&pid);
            self.inner
                .promises
                .resolve_fail(pid, format!("peer '{host}' disconnected"));
        }
    }

    /// Register a link task for crash teardown.
    pub fn track_link(&self, task: tokio::task::JoinHandle<()>) {
        self.inner
            .links
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    /// Set the listener task (so crash_links can stop accepting too).
    pub fn track_listener(&self, task: tokio::task::JoinHandle<()>) {
        *self
            .inner
            .listener
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(task);
    }

    /// CRASH: abort every link task and the listener. Sockets close; the
    /// far end sees EOF and runs its own crash detection.
    pub fn crash_links(&self) {
        if let Some(l) = self
            .inner
            .listener
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            l.abort();
        }
        let mut guard = self.inner.links.write().unwrap_or_else(|p| p.into_inner());
        let links = std::mem::take(&mut *guard);
        for t in links {
            t.abort();
        }
    }

    /// List connected peer hosts.
    pub fn peers(&self) -> Vec<String> {
        self.inner
            .peers
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// One-shot request/reply over a promise. Blocking at THIS call site —
    /// external drivers/tests use this; cells use `ctx.call` to stay
    /// non-blocking inside their turn. Rolled-back turns return `Err`.
    pub async fn call(
        &self,
        to: sieveplate_core::Port,
        kind: &str,
        payload: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, CellError> {
        let pid = self.inner.promises.mint();
        // Stamp the caller's host (empty cell = "the driver, not a cell")
        // so replies route back across hosts and resolve here.
        let env = Envelope::new(to, kind, payload)
            .with_from(Port::new(&self.inner.host, "", ""))
            .with_reply_to(pid);
        self.deliver(env).await?;
        let rx = self.inner.promises.waiter(pid);
        let res = tokio::time::timeout(timeout, rx).await;
        match res {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(reason))) => Err(CellError::Other(reason)),
            Ok(Err(_)) => Err(CellError::Other("promise waiter dropped".into())),
            Err(_) => {
                self.inner.promises.cancel(pid);
                Err(CellError::Timeout(timeout.as_millis() as u64))
            }
        }
    }

    /// Fire a pipelined chain: send `first`; when its reply resolves, the
    /// fabric delivers `next` with that payload and resolves the returned
    /// promise with the *next hop's* reply. Registered before the first
    /// message is even sent — true pipelining.
    pub async fn call_pipelined(
        &self,
        first_to: sieveplate_core::Port,
        first_kind: &str,
        first_payload: Vec<u8>,
        next_to: sieveplate_core::Port,
        next_kind: &str,
    ) -> Result<PromiseId, CellError> {
        let pid = self.inner.promises.mint();
        let next_pid = self.inner.promises.mint();
        self.inner.promises.pipe(
            pid,
            Continuation {
                to: next_to,
                kind: next_kind.to_string(),
                next: Some(next_pid),
            },
        );
        let env = Envelope::new(first_to, first_kind, first_payload)
            .with_from(Port::new(&self.inner.host, "", ""))
            .with_reply_to(pid);
        self.deliver(env).await?;
        Ok(next_pid)
    }

    async fn deliver_local(&self, env: Envelope) -> Result<(), CellError> {
        let vat_name = env.to.vat.clone();
        // Per-cell proxies (process cells) take precedence over the
        // whole-vat mailbox: envelopes for a jailed cell never enter the
        // vat — the parent mediates them.
        let cell_key = format!("{}/{}", env.to.vat, env.to.cell);
        let proxy = self
            .inner
            .proxies
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&cell_key)
            .cloned();
        if let Some(tx) = proxy {
            return tx
                .send(env)
                .await
                .map_err(|_| CellError::VatClosed(cell_key));
        }
        let tx = self
            .inner
            .locals
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&env.to.vat)
            .cloned();
        match tx {
            Some(tx) => tx
                .send(VatInput::Env(env))
                .await
                .map_err(|_| CellError::VatClosed(vat_name)),
            None => Err(CellError::Other(format!(
                "no local vat '{}' on host '{}'",
                vat_name, self.inner.host
            ))),
        }
    }

    async fn deliver_remote(&self, env: Envelope) -> Result<(), CellError> {
        let host_name = env.to.host.clone();
        // Track the call so a peer crash can fail it fast.
        if let Some(pid) = env.reply_to {
            self.inner
                .inflight
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .insert(pid, host_name.clone());
        }
        let bytes = crate::net::frame(&env)?;
        let tx = self
            .inner
            .peers
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&env.to.host)
            .cloned();
        match tx {
            Some(tx) => tx
                .send(bytes)
                .await
                .map_err(|_| CellError::Other(format!("peer '{}' closed", host_name))),
            None => Err(CellError::Other(format!(
                "peer '{}' not connected",
                host_name
            ))),
        }
    }

    /// Deliver a fired continuation: envelope to `cont.to` with the payload;
    /// its reply resolves `cont.next`.
    async fn fire(&self, cont: Continuation, payload: Vec<u8>) {
        let mut env = Envelope::new(cont.to.clone(), cont.kind.clone(), payload);
        if let Some(n) = cont.next {
            env.reply_to = Some(n);
        }
        if let Err(e) = self.deliver(env).await {
            tracing::warn!(error = %e, to = %cont.to, "continuation delivery failed");
        }
    }
}

#[async_trait]
impl Route for Fabric {
    async fn deliver(&self, env: Envelope) -> Result<(), CellError> {
        // Replies resolve their promise here (whoever receives them) and
        // fire any piped continuations chained onto it.
        if env.kind == Envelope::KIND_REPLY {
            self.inner
                .inflight
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&env.id);
            let conts = self
                .inner
                .promises
                .resolve_notify(env.id, env.payload.clone());
            for c in conts {
                let payload = self.inner.promises.peek(env.id).unwrap_or_default();
                self.fire(c, payload).await;
            }
            // A reply addressed to *our* host with no cell destination has
            // finished its journey here. Replies in transit (foreign host
            // destination) must continue routing below.
            if env.to.cell.is_empty() && env.to.host == self.inner.host {
                return Ok(());
            }
        }
        if env.to.host == self.inner.host {
            self.deliver_local(env).await
        } else {
            self.deliver_remote(env).await
        }
    }

    fn pipe_continuation(&self, pid: PromiseId, cont: Continuation) -> Result<(), CellError> {
        if let Some(cont) = self.inner.promises.pipe(pid, cont) {
            // Promise already resolved: fire immediately (spawn — this is
            // a sync entry point).
            let payload = self.inner.promises.peek(pid).unwrap_or_default();
            let this = self.clone();
            tokio::spawn(async move {
                this.fire(cont, payload).await;
            });
        }
        Ok(())
    }
}
