//! The Vat — L5 event loop with transactional turns.
//!
//! A vat is a single-threaded async event loop owning a set of cells.
//! Delivering an envelope to a cell runs one *turn*:
//!
//! 1. If the cell is asleep (evicted), restore it from the content store
//!    first — this is the "sleeping actor" wake path.
//! 2. Snapshot the cell's state (rollback point).
//! 3. Run the handler. Sends collect in an outbox; a reply payload may be
//!    set for automatic `__reply` delivery.
//! 4. Commit: flush the outbox through the fabric, persist a fresh
//!    snapshot (content-addressed), reset the supervisor counter.
//!    Rollback: restore the pre-turn snapshot, notify the supervisor,
//!    emit a `__fault` envelope.
//! 5. If the cell has been idle past its sleep policy, evict it
//!    (scale-to-zero: snapshot → store → drop from memory).
//!
//! Zero-poll discipline: the hot path is purely async (mpsc + fabric);
//! the only timer is a control-plane sweep for idle eviction.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::sync::{mpsc, oneshot};

use sieveplate_store::{ContentStore, EventLog, Hash};

use crate::cap::CapTable;
use crate::cell::{BoxedCell, RestartPolicy, SleepPolicy, TemplateRegistry, TurnCtx};
use crate::envelope::Envelope;
use crate::error::CellError;
use crate::metrics::Metrics;
use crate::port::Port;
use crate::promise::Promises;
use crate::route::Route;

/// A cell stub left behind when a cell is evicted (scaled to zero).
/// Live references stay valid: a message to the stub wakes the cell.
#[derive(Debug, Clone)]
pub struct CellStub {
    pub name: String,
    pub template: String,
    pub caps: CapTable,
    pub policy: SleepPolicy,
    pub snapshot: Hash,
    pub last_activity: Instant,
}

struct CellEntry {
    cell: BoxedCell,
    caps: CapTable,
    policy: SleepPolicy,
    restart: RestartPolicy,
    template: String,
    last_snapshot: Option<Hash>,
    last_activity: Instant,
    fail_count: u32,
}

/// Control commands into a vat.
pub enum VatCtrl {
    Inject {
        name: String,
        template: String,
        cell: BoxedCell,
        caps: CapTable,
        policy: SleepPolicy,
        restart: RestartPolicy,
        reply: oneshot::Sender<Result<(), CellError>>,
    },
    Evict {
        name: String,
        reply: oneshot::Sender<Result<Hash, CellError>>,
    },
    Destroy {
        name: String,
        reply: oneshot::Sender<Result<(), CellError>>,
    },
    Snapshot {
        name: String,
        reply: oneshot::Sender<Result<Hash, CellError>>,
    },
    Status {
        reply: oneshot::Sender<VatStatus>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

pub enum VatInput {
    Env(Envelope),
    Ctrl(VatCtrl),
}

/// Point-in-time vat status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VatStatus {
    pub name: String,
    pub active: Vec<String>,
    pub sleeping: Vec<String>,
}

/// Handle to a running vat.
#[derive(Clone)]
pub struct VatHandle {
    pub name: String,
    tx: mpsc::Sender<VatInput>,
    task: std::sync::Arc<tokio::task::JoinHandle<()>>,
}

impl VatHandle {
    /// HARD-STOP: abort the vat task. In-flight turns are dropped
    /// mid-flight (no drain, no replies). Used by crash semantics.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Send an envelope into the vat's mailbox.
    pub async fn send_env(&self, env: Envelope) -> Result<(), CellError> {
        self.tx
            .send(VatInput::Env(env))
            .await
            .map_err(|_| CellError::VatClosed(self.name.clone()))
    }

    /// Clone the mailbox sender (the fabric stores this to route locally).
    pub fn sender(&self) -> mpsc::Sender<VatInput> {
        self.tx.clone()
    }

    pub async fn ctrl(&self, c: VatCtrl) -> Result<(), CellError> {
        self.tx
            .send(VatInput::Ctrl(c))
            .await
            .map_err(|_| CellError::VatClosed(self.name.clone()))
    }
}

/// Everything a vat needs from its environment.
pub struct VatDeps {
    pub host: String,
    pub name: String,
    pub store: Arc<ContentStore>,
    pub log: Arc<EventLog>,
    pub metrics: Arc<Metrics>,
    pub fabric: Arc<dyn Route>,
    pub registry: Arc<TemplateRegistry>,
    pub promises: Arc<Promises>,
    pub mailbox_capacity: usize,
}

struct Vat {
    host: String,
    name: String,
    cells: HashMap<String, CellEntry>,
    sleeping: HashMap<String, CellStub>,
    store: Arc<ContentStore>,
    log: Arc<EventLog>,
    metrics: Arc<Metrics>,
    fabric: Arc<dyn Route>,
    registry: Arc<TemplateRegistry>,
    promises: Arc<Promises>,
}

/// Spawn a vat as a tokio task; returns its handle.
pub fn spawn(deps: VatDeps) -> VatHandle {
    let (tx, rx) = mpsc::channel(deps.mailbox_capacity);
    let vat = Vat {
        host: deps.host,
        name: deps.name.clone(),
        cells: HashMap::new(),
        sleeping: HashMap::new(),
        store: deps.store,
        log: deps.log,
        metrics: deps.metrics,
        fabric: deps.fabric,
        registry: deps.registry,
        promises: deps.promises,
    };
    let task = std::sync::Arc::new(tokio::spawn(vat.run(rx)));
    VatHandle {
        name: deps.name,
        tx,
        task,
    }
}

impl Vat {
    async fn run(mut self, mut rx: mpsc::Receiver<VatInput>) {
        loop {
            // Control-plane sweep for idle eviction. The message hot path
            // never polls; this only advances scale-to-zero for idle cells.
            let sweep = tokio::time::sleep(Duration::from_millis(50));
            tokio::select! {
                biased;
                input = rx.recv() => match input {
                    None => break,
                    Some(VatInput::Ctrl(c)) => {
                        if self.handle_ctrl(c).await { break; }
                    }
                    Some(VatInput::Env(env)) => self.turn(env).await,
                },
                _ = sweep => self.sweep().await,
            }
        }
        tracing::debug!(vat = %self.name, "vat loop exited");
    }

    // -----------------------------------------------------------------
    // The transactional turn
    // -----------------------------------------------------------------
    async fn turn(&mut self, env: Envelope) {
        // Fabric-level control envelopes never reach cells — they are
        // resolved by the router on receipt. Dropping them here breaks any
        // fault-feedback loop by construction.
        if env.kind == Envelope::KIND_REPLY || env.kind == Envelope::KIND_FAULT {
            tracing::debug!(kind = %env.kind, cell = %env.to.cell, "control envelope consumed at vat boundary");
            return;
        }
        // Kernel-level wake probe: wake the cell (restore if sleeping) and
        // reply without invoking the handler.
        if env.kind == Envelope::KIND_PING {
            self.handle_ping(env).await;
            return;
        }
        let started = Instant::now();
        let cname = env.to.cell.clone();

        // Wake-from-store path (sleeping actor).
        if !self.cells.contains_key(&cname) {
            match self.sleeping.remove(&cname) {
                Some(stub) => match self.rebuild_from_stub(&stub) {
                    Ok(entry) => {
                        self.metrics
                            .record_us("wake_us", started.elapsed().as_micros() as u64);
                        let _ = self.log.append(
                            "cell.wake",
                            vec![
                                ("cell".into(), cname.clone()),
                                ("us".into(), started.elapsed().as_micros().to_string()),
                            ],
                        );
                        self.cells.insert(cname.clone(), entry);
                    }
                    Err(e) => {
                        tracing::warn!(cell = %cname, error = %e, "wake failed");
                        self.signal_failure(&env, format!("wake failed: {e}"));
                        return;
                    }
                },
                None => {
                    self.signal_failure(&env, format!("unknown cell '{cname}'"));
                    return;
                }
            }
        }

        // Snapshot = rollback point.
        let rollback_point = {
            let entry = self.cells.get(&cname).unwrap();
            entry.cell.snapshot()
        };

        let mut outbox: Vec<Envelope> = Vec::new();
        let mut reply: Option<Vec<u8>> = None;

        let self_port = Port::new(&self.host, &self.name, &cname);
        let outcome = {
            let entry = self.cells.get_mut(&cname).unwrap();
            let CellEntry { cell, caps, .. } = &mut *entry;
            let mut ctx = TurnCtx {
                outbox: &mut outbox,
                reply: &mut reply,
                caps,
                fabric: Arc::clone(&self.fabric),
                promises: Arc::clone(&self.promises),
                self_port: self_port.clone(),
            };
            // Run the handler; panics are caught and become rollbacks.
            let fut = cell.handle(&env, &mut ctx);
            AssertUnwindSafe(fut).catch_unwind().await
        };

        let entry = self.cells.get_mut(&cname).unwrap();
        let elapsed_us = started.elapsed().as_micros() as u64;

        let committed = match outcome {
            Ok(Ok(())) => {
                // Auto-reply for promise-pipelined calls. External callers
                // (from = None) resolve at the fabric via an empty-cell
                // destination; real cells receive the reply as a message.
                if let Some(pid) = env.reply_to {
                    let rep = Envelope {
                        id: pid,
                        from: Some(self_port.clone()),
                        to: env
                            .from
                            .clone()
                            .unwrap_or_else(|| Port::new(&self.host, &self.name, "")),
                        reply_to: None,
                        depends_on: None,
                        kind: Envelope::KIND_REPLY.into(),
                        payload: reply.clone().unwrap_or_default(),
                        ttl: crate::MAX_HOPS,
                    };
                    let _ = self.fabric.deliver(rep).await;
                }
                // Flush outbox through the fabric (L6).
                for mut o in outbox {
                    if o.from.is_none() {
                        o.from = Some(self_port.clone());
                    }
                    if let Err(e) = self.fabric.deliver(o).await {
                        tracing::warn!(error = %e, "outbox delivery failed");
                    }
                }
                entry.last_activity = Instant::now();
                entry.fail_count = 0;
                // Persist (content-addressed snapshot → L3 store).
                if entry.policy.persist_on_turn {
                    if let Ok(bytes) = entry.cell.snapshot() {
                        match self.store.put(&bytes) {
                            Ok(h) => entry.last_snapshot = Some(h),
                            Err(e) => tracing::warn!(error = %e, "snapshot persist failed"),
                        }
                    }
                }
                self.metrics.count("turns_ok");
                self.metrics.record_us("turn_us", elapsed_us);
                let _ = self.log.append(
                    "turn.ok",
                    vec![
                        ("cell".into(), cname.clone()),
                        ("msg".into(), env.kind.clone()),
                        ("us".into(), elapsed_us.to_string()),
                    ],
                );
                true
            }
            Ok(Err(e)) => {
                self.rollback(&cname, &env, &rollback_point, e.to_string(), elapsed_us)
                    .await;
                false
            }
            Err(panic) => {
                let msg = panic_message(panic);
                self.rollback(&cname, &env, &rollback_point, msg, elapsed_us)
                    .await;
                false
            }
        };

        // Supervisor: exponential backoff restart on repeated failures.
        if !committed {
            let restart = entry_restart(&mut self.cells, &cname);
            if restart.exceeded {
                self.metrics.count("supervisor_restarts");
                let _ = self.respawn(&cname).await;
            }
        }

        // Scale-to-zero if idle past policy.
        self.maybe_evict(&cname).await;
    }

    async fn rollback(
        &mut self,
        cname: &str,
        env: &Envelope,
        rollback_point: &Result<Vec<u8>, CellError>,
        reason: String,
        elapsed_us: u64,
    ) {
        if let Ok(bytes) = rollback_point {
            if let Some(entry) = self.cells.get_mut(cname) {
                if let Err(e) = entry.cell.restore(bytes) {
                    tracing::error!(cell = %cname, error = %e, "rollback restore failed");
                }
            }
        }
        if let Some(entry) = self.cells.get_mut(cname) {
            entry.fail_count += 1;
        }
        self.metrics.count("turns_failed");
        self.metrics.count("turns_rolled_back");
        let _ = self.log.append(
            "turn.fail",
            vec![
                ("cell".into(), cname.to_string()),
                ("msg".into(), env.kind.clone()),
                ("reason".into(), reason.clone()),
                ("us".into(), elapsed_us.to_string()),
            ],
        );
        tracing::info!(cell = %cname, msg = %env.kind, %reason, "turn rolled back");
        // Fail the caller's promise (pipelined calls never hang).
        if let Some(pid) = env.reply_to {
            self.promises.resolve_fail(pid, reason.clone());
        }
        // Fault envelopes only flow to real originating cells — never to
        // empty/external destinations, which would cascade.
        if let Some(from) = &env.from {
            if !from.cell.is_empty() {
                let _ = self.fabric.deliver(self.fault_env(env, reason)).await;
            }
        }
    }

    /// Signal a pre-turn failure (unknown cell / failed wake): fail the
    /// promise, or fault the originating cell — but never cascade.
    /// Sync + fire-and-forget: delivery is spawned (no borrow across await).
    fn signal_failure(&self, env: &Envelope, reason: String) {
        if let Some(pid) = env.reply_to {
            self.promises.resolve_fail(pid, reason.clone());
        }
        if let Some(from) = &env.from {
            if !from.cell.is_empty() {
                let env = self.fault_env(env, reason.clone());
                let fabric = Arc::clone(&self.fabric);
                tokio::spawn(async move {
                    let _ = fabric.deliver(env).await;
                });
            }
        }
        tracing::debug!(reason = %reason, "failure signalled without cascade");
    }

    // -----------------------------------------------------------------
    // Sleeping actors: evict / wake
    // -----------------------------------------------------------------
    async fn maybe_evict(&mut self, cname: &str) {
        let idle = match self.cells.get(cname) {
            Some(e) => e.last_activity.elapsed(),
            None => return,
        };
        let after = self
            .cells
            .get(cname)
            .and_then(|e| e.policy.after_idle_ms)
            .map(Duration::from_millis);
        if let Some(after) = after {
            if idle >= after {
                self.evict(cname).await;
            }
        }
    }

    async fn sweep(&mut self) {
        let names: Vec<String> = self.cells.keys().cloned().collect();
        for n in names {
            self.maybe_evict(&n).await;
        }
    }

    /// Evict (scale to zero): snapshot → store → drop, leaving a stub.
    async fn evict(&mut self, cname: &str) -> Option<Hash> {
        let mut entry = self.cells.remove(cname)?;
        let bytes = entry.cell.snapshot().ok()?;
        let h = self.store.put(&bytes).ok()?;
        entry.last_snapshot = Some(h.clone());
        self.sleeping.insert(
            cname.to_string(),
            CellStub {
                name: cname.to_string(),
                template: entry.template,
                caps: entry.caps,
                policy: entry.policy,
                snapshot: h.clone(),
                last_activity: entry.last_activity,
            },
        );
        self.metrics.count("evictions");
        let _ = self
            .log
            .append("cell.evict", vec![("cell".into(), cname.to_string())]);
        tracing::debug!(cell = %cname, hash = %h, "cell evicted to store");
        Some(h)
    }

    fn rebuild_from_stub(&self, stub: &CellStub) -> Result<CellEntry, CellError> {
        let bytes = self
            .store
            .get(&stub.snapshot)?
            .ok_or_else(|| CellError::Store("snapshot object missing".into()))?;
        let mut cell = self.registry.build(&stub.template)?;
        cell.restore(&bytes)?;
        Ok(CellEntry {
            cell,
            caps: stub.caps.clone(),
            policy: stub.policy.clone(),
            restart: RestartPolicy::default(),
            template: stub.template.clone(),
            last_snapshot: Some(stub.snapshot.clone()),
            last_activity: Instant::now(),
            fail_count: 0,
        })
    }

    /// Supervisor respawn: rebuild from template + last persisted snapshot.
    async fn respawn(&mut self, cname: &str) -> Result<(), CellError> {
        let (template, last_snapshot) = {
            let e = self
                .cells
                .get(cname)
                .ok_or(CellError::NotFound(cname.into()))?;
            (e.template.clone(), e.last_snapshot.clone())
        };
        let mut cell = self.registry.build(&template)?;
        let mut last_snapshot_new = None;
        if let Some(h) = &last_snapshot {
            if let Some(bytes) = self.store.get(h)? {
                cell.restore(&bytes)?;
                last_snapshot_new = Some(h.clone());
            }
        }
        if let Some(entry) = self.cells.get_mut(cname) {
            entry.cell = cell;
            entry.fail_count = 0;
            entry.last_snapshot = last_snapshot_new;
            entry.last_activity = Instant::now();
        }
        let _ = self.log.append(
            "cell.restore",
            vec![
                ("cell".into(), cname.to_string()),
                ("hash".into(), last_snapshot.unwrap_or_default()),
            ],
        );
        tracing::info!(cell = %cname, "supervisor respawned cell from template");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Control plane
    // -----------------------------------------------------------------
    /// Returns true when the vat should exit.
    async fn handle_ctrl(&mut self, c: VatCtrl) -> bool {
        match c {
            VatCtrl::Inject {
                name,
                template,
                cell,
                caps,
                policy,
                restart,
                reply,
            } => {
                let existed =
                    self.sleeping.remove(&name).is_some() || self.cells.remove(&name).is_some();
                self.cells.insert(
                    name.clone(),
                    CellEntry {
                        cell,
                        caps,
                        policy,
                        restart,
                        template,
                        last_snapshot: None,
                        last_activity: Instant::now(),
                        fail_count: 0,
                    },
                );
                if !existed {
                    let _ = self
                        .log
                        .append("cell.create", vec![("cell".into(), name.clone())]);
                }
                let _ = reply.send(Ok(()));
                false
            }
            VatCtrl::Evict { name, reply } => {
                if let Some(stub) = self.sleeping.get(&name) {
                    // Already asleep: report its snapshot hash.
                    let h = stub.snapshot.clone();
                    let _ = reply.send(Ok(h));
                } else {
                    let _ = reply.send(
                        self.evict(&name)
                            .await
                            .ok_or(CellError::NotFound(name.clone())),
                    );
                }
                false
            }
            VatCtrl::Destroy { name, reply } => {
                let gone =
                    self.cells.remove(&name).is_some() || self.sleeping.remove(&name).is_some();
                let _ = reply.send(if gone {
                    Ok(())
                } else {
                    Err(CellError::NotFound(name))
                });
                false
            }
            VatCtrl::Snapshot { name, reply } => {
                let res = match self.cells.get(&name) {
                    Some(entry) => entry
                        .cell
                        .snapshot()
                        .and_then(|b| self.store.put(&b).map_err(CellError::from)),
                    None => Err(CellError::NotFound(name.clone())),
                };
                let _ = reply.send(res);
                false
            }
            VatCtrl::Status { reply } => {
                let _ = reply.send(VatStatus {
                    name: self.name.clone(),
                    active: self.cells.keys().cloned().collect(),
                    sleeping: self.sleeping.keys().cloned().collect(),
                });
                false
            }
            VatCtrl::Shutdown { reply } => {
                let _ = reply.send(());
                true
            }
        }
    }

    fn fault_env(&self, cause: &Envelope, reason: String) -> Envelope {
        let mut env = Envelope::new(
            cause
                .from
                .clone()
                .unwrap_or_else(|| Port::new(&self.host, &self.name, "")),
            Envelope::KIND_FAULT,
            reason.into_bytes(),
        );
        env.from = Some(Port::new(&self.host, &self.name, cause.to.cell.clone()));
        env
    }

    /// `__ping`: ensure the target cell is in memory (waking it from the
    /// store if sleeping) and reply `pong` — a handler-free wake probe.
    async fn handle_ping(&mut self, env: Envelope) {
        let started = Instant::now();
        let cname = env.to.cell.clone();
        if !self.cells.contains_key(&cname) {
            match self.sleeping.remove(&cname) {
                Some(stub) => match self.rebuild_from_stub(&stub) {
                    Ok(entry) => {
                        self.metrics
                            .record_us("wake_us", started.elapsed().as_micros() as u64);
                        let _ = self.log.append(
                            "cell.wake",
                            vec![
                                ("cell".into(), cname.clone()),
                                ("us".into(), started.elapsed().as_micros().to_string()),
                            ],
                        );
                        self.cells.insert(cname.clone(), entry);
                    }
                    Err(e) => {
                        let _ = self
                            .fabric
                            .deliver(self.fault_env(&env, format!("wake failed: {e}")))
                            .await;
                        return;
                    }
                },
                None => {
                    let _ = self
                        .fabric
                        .deliver(self.fault_env(&env, format!("unknown cell '{cname}'")))
                        .await;
                    return;
                }
            }
        }
        let reply = Envelope {
            id: env.reply_to.unwrap_or_else(crate::ids::next_id),
            from: Some(Port::new(&self.host, &self.name, cname)),
            to: env
                .from
                .clone()
                .unwrap_or_else(|| Port::new(&self.host, &self.name, "")),
            reply_to: None,
            depends_on: None,
            kind: Envelope::KIND_REPLY.into(),
            payload: b"pong".to_vec(),
            ttl: crate::MAX_HOPS,
        };
        let _ = self.fabric.deliver(reply).await;
    }
}

// Helpers -------------------------------------------------------------------

struct RestartCheck {
    exceeded: bool,
}

fn entry_restart(cells: &mut HashMap<String, CellEntry>, cname: &str) -> RestartCheck {
    let e = match cells.get(cname) {
        Some(e) => e,
        None => return RestartCheck { exceeded: false },
    };
    RestartCheck {
        exceeded: e.fail_count > e.restart.max_restarts,
    }
}

fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// AssertUnwindSafe re-export (keeps the vat import list tidy).
use std::panic::AssertUnwindSafe;
