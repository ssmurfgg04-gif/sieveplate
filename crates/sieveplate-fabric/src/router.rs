//! The Fabric router — local vat mailboxes + remote peers + promises.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::mesh::{RouteAnnounce, RouteAnnounceEntry, RouteTable, POISON};
use sieveplate_core::{
    CellError, Continuation, Envelope, Port, PromiseId, Promises, Route, VatInput,
};

/// Raw frame sender to a remote peer (net.rs fills this).
pub type PeerTx = mpsc::Sender<Vec<u8>>;

/// Routing-table announcement control kind (sealed channel, ADR-0006).
pub const KIND_ROUTES: &str = "__routes";

/// Routing facts for one in-flight remote call.
struct InflightCall {
    /// The peer key whose link carries this call (final dest when direct,
    /// the mesh next hop when forwarded). Link death = this call fails.
    next_hop: String,
    /// Original caller port (None-safe). `originator()` compares its host
    /// against ours.
    from: Option<Port>,
}

impl InflightCall {
    fn clone_for_fault(&self) -> InflightCall {
        InflightCall {
            next_hop: self.next_hop.clone(),
            from: self.from.clone(),
        }
    }

    fn is_originator(&self, self_host: &str) -> bool {
        match &self.from {
            Some(p) => p.host == self_host,
            None => true, // cannot route a fault back — resolve locally
        }
    }
}

struct Inner {
    host: String,
    /// In-flight REMOTE calls: pid → routing info. On a link death every
    /// call whose NEXT HOP was that link fails fast — locally when we
    /// originated the call, or via a `__fault` envelope routed back to the
    /// original caller when we only forwarded it (multi-hop crash
    /// detection, ADR-0006).
    inflight: RwLock<HashMap<PromiseId, InflightCall>>,
    /// Live link tasks (accept loops + connection pumps). `crash_links`
    /// aborts them all, closing every socket — a host-level crash.
    links: RwLock<Vec<tokio::task::JoinHandle<()>>>,
    /// Listener handle (Network::shutdown aborts this).
    listener: RwLock<Option<tokio::task::JoinHandle<()>>>,
    locals: RwLock<HashMap<String, mpsc::Sender<VatInput>>>,
    /// Per-cell proxies (process cells): raw envelope senders keyed
    /// "vat/cell". Take precedence over whole-vat mailboxes.
    proxies: RwLock<HashMap<String, mpsc::Sender<Envelope>>>,
    /// Direct peer links: name → (frame sender, connection id). The id
    /// makes disconnect handling generation-aware: a LATE EOF from a dead
    /// socket must never erase the state of a NEWER link to the same peer
    /// (same name — hosts relink under one name), so pumps exit through
    /// `peer_disconnected_conn` and only the CURRENT connection's death
    /// counts.
    peers: RwLock<HashMap<String, (PeerTx, u64)>>,
    /// Monotonic connection-id source.
    conn_seq: std::sync::atomic::AtomicU64,
    promises: Promises,
    /// Multi-hop routing table (ADR-0006): dest host → next hop + cost.
    mesh: RouteTable,
}

/// The fabric: one instance per host. Clone freely.
#[derive(Clone)]
pub struct Fabric {
    inner: Arc<Inner>,
}

impl Fabric {
    /// A fabric for `host`. Promise registry is shared with all clones.
    pub fn new(host: impl Into<String>, promises: Promises) -> Self {
        let host = host.into();
        Fabric {
            inner: Arc::new(Inner {
                host: host.clone(),
                inflight: RwLock::new(HashMap::new()),
                links: RwLock::new(Vec::new()),
                listener: RwLock::new(None),
                locals: RwLock::new(HashMap::new()),
                proxies: RwLock::new(HashMap::new()),
                peers: RwLock::new(HashMap::new()),
                conn_seq: std::sync::atomic::AtomicU64::new(1),
                promises,
                mesh: RouteTable::new(host.clone()),
            }),
        }
    }

    /// The multi-hop routing table (mesh, ADR-0006).
    pub fn mesh(&self) -> &RouteTable {
        &self.inner.mesh
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

    /// Register (or replace) a remote peer's frame sender. The peer joins
    /// the mesh at cost 1 and the full table is re-announced so both sides
    /// (and everyone else) converge.
    pub fn attach_peer(&self, host: &str, tx: PeerTx) -> u64 {
        let conn = self
            .inner
            .conn_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .peers
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host.to_string(), (tx, conn));
        self.inner.mesh.add_direct(host);
        self.spawn_announce(None);
        conn
    }

    /// Send a control frame DIRECTLY to a peer (bypasses the route table —
    /// announcements must not be routed or they could not bootstrap).
    fn send_control(&self, peer: &str, kind: &str, payload: Vec<u8>) {
        let env = Envelope::new(Port::new("", "", ""), kind, payload);
        let bytes = match crate::net::frame(&env) {
            Ok(b) => b,
            Err(_) => return,
        };
        let tx = self
            .inner
            .peers
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(peer)
            .map(|(tx, _)| tx.clone());
        if let Some(tx) = tx {
            tokio::spawn(async move {
                let _ = tx.send(bytes).await;
            });
        }
    }

    /// Broadcast the full routing table to every direct peer. `poison`
    /// entries (destination, POISON) are appended as withdrawals — peers
    /// forget routes to them if they learned those routes from us.
    pub fn spawn_announce(&self, poison: Option<Vec<String>>) {
        let this = self.clone();
        tokio::spawn(async move {
            let ann = this.inner.mesh.announce();
            let mut ann = ann;
            if let Some(withdrawn) = poison {
                for host in withdrawn {
                    ann.entries.push(RouteAnnounceEntry { host, hops: POISON });
                }
            }
            let payload = serde_json::to_vec(&ann).unwrap_or_default();
            for peer in this.peers() {
                this.send_control(&peer, KIND_ROUTES, payload.clone());
            }
        });
    }

    /// A `__routes` announcement arrived on a sealed link. Learn from it;
    /// when our table changed, re-announce to everyone (triggered DV
    /// update). This is the mesh convergence step.
    pub fn mesh_receive(&self, ann: &RouteAnnounce) {
        if ann.from == self.inner.host {
            return; // our own table echoed back — nothing to learn
        }
        if self.inner.mesh.learn(ann) {
            self.spawn_announce(None);
        }
    }

    pub fn drop_peer(&self, host: &str) {
        self.inner
            .peers
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(host);
    }

    /// Drop the peer entry ONLY if it is still the connection that died
    /// (`conn` matches). Returns true when the entry was removed — i.e.
    /// this death is the CURRENT link's and the mesh must react.
    pub fn drop_peer_if_current(&self, host: &str, conn: u64) -> bool {
        let mut peers = self.inner.peers.write().unwrap_or_else(|p| p.into_inner());
        match peers.get(host) {
            Some((_, cur)) if *cur == conn => {
                peers.remove(host);
                true
            }
            _ => false,
        }
    }

    /// Crash detection: the link to `host` broke. Every in-flight call
    /// routed over that link fails immediately — a caller waits for an
    /// ANSWER or a FAILURE, never for a timeout that hides the difference.
    /// Calls we merely FORWARDED get a `__fault` envelope routed back to
    /// the original caller (multi-hop failure propagation, ADR-0006).
    /// Every mesh route that used this peer is withdrawn and poisoned
    /// outward so the rest of the grid stops forwarding through the dead
    /// link.
    pub fn peer_disconnected(&self, host: &str) {
        self.drop_peer(host);
        self.handle_disconnect(host);
    }

    /// The pump for connection `conn` to `host` died. If a newer
    /// connection to the same host has already replaced this entry, the
    /// death is STALE — the mesh keeps its routes and in-flight calls
    /// (they ride the new link). Otherwise this is the current link's
    /// death: fail calls, withdraw routes, poison outward.
    pub fn peer_disconnected_conn(&self, host: &str, conn: u64) {
        if !self.drop_peer_if_current(host, conn) {
            tracing::debug!(
                peer = %host,
                conn,
                "stale link death ignored — newer connection already in place"
            );
            return;
        }
        self.handle_disconnect(host);
    }

    fn handle_disconnect(&self, host: &str) {
        let self_host = self.inner.host.clone();
        let mut inflight = self
            .inner
            .inflight
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let dead: Vec<(PromiseId, InflightCall)> = inflight
            .iter()
            .filter(|(_, c)| c.next_hop == host)
            .map(|(pid, c)| (*pid, c.clone_for_fault()))
            .collect();
        for (pid, call) in dead {
            inflight.remove(&pid);
            if call.is_originator(&self_host) {
                self.inner
                    .promises
                    .resolve_fail(pid, format!("peer '{host}' disconnected"));
            } else if let Some(from) = call.from {
                // Propagate: the caller may be one or more hops away.
                let mut fault = Envelope::new(
                    from,
                    Envelope::KIND_FAULT,
                    format!("peer '{host}' disconnected in transit").into_bytes(),
                );
                fault.id = pid;
                let this = self.clone();
                tokio::spawn(async move {
                    let _ = this.deliver(fault).await;
                });
            }
        }
        drop(inflight);
        // Mesh withdrawal: forget everything that routed via `host`, then
        // poison those destinations to the surviving peers.
        let withdrawn = self.inner.mesh.remove_peer(host);
        if !withdrawn.is_empty() {
            self.spawn_announce(Some(withdrawn));
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
        // Mesh loop guard: every forwarding host consumes one unit of TTL
        // (ADR-0006). An envelope that cycles dies here instead of forever.
        let env = {
            let mut e = env;
            if e.ttl == 0 {
                return Err(CellError::Other(format!(
                    "envelope to '{host_name}' exhausted its mesh TTL"
                )));
            }
            e.ttl -= 1;
            e
        };
        let bytes = crate::net::frame(&env)?;
        // Direct socket first; otherwise forward via the mesh next hop
        // (ADR-0006). A forwarder is any host on the path — including us.
        let direct = self
            .inner
            .peers
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&host_name)
            .map(|(tx, _)| tx.clone());
        let (tx, used_hop) = match direct {
            Some(tx) => (Some(tx), host_name.clone()),
            None => match self.inner.mesh.next_hop(&host_name) {
                Some(hop) => {
                    let tx = self
                        .inner
                        .peers
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&hop)
                        .map(|(tx, _)| tx.clone());
                    (tx, hop)
                }
                None => (None, host_name.clone()),
            },
        };
        // Track the call against the LINK it actually uses, so a link
        // death fails exactly the calls that depended on it.
        if let Some(pid) = env.reply_to {
            self.inner
                .inflight
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .insert(
                    pid,
                    InflightCall {
                        next_hop: used_hop,
                        from: env.from.clone(),
                    },
                );
        }
        match tx {
            Some(tx) => tx
                .send(bytes)
                .await
                .map_err(|_| CellError::Other(format!("peer toward '{host_name}' closed"))),
            None => Err(CellError::Other(format!("no route to host '{host_name}'"))),
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
        // Faults from the mesh resolve their promise as a FAILURE (the
        // caller gets an error, never a fabricated value) and keep
        // routing home when this host is only a transit stop.
        if env.kind == Envelope::KIND_FAULT {
            self.inner
                .inflight
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&env.id);
            let reason =
                String::from_utf8(env.payload.clone()).unwrap_or_else(|_| "mesh fault".to_string());
            self.inner.promises.resolve_fail(env.id, reason);
            if env.to.host == self.inner.host {
                return Ok(());
            }
        }
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
