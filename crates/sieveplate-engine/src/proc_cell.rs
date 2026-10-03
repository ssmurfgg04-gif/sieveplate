//! Process-cell backing: cells that live in jailed child processes.
//!
//! Flow of an envelope to a process cell `core/worker`:
//!
//! ```text
//! caller → fabric.deliver(env)            (env.to = host/core/worker)
//!        → proxies["core/worker"]         (per-cell mailbox)
//!        → pump task: respawn if dead     (true scale-to-zero: the OS
//!          → JailProc.stdin_tx            process is GONE when evicted)
//!            → worker __worker process    (seccomp + Landlock sandbox)
//! ```
//!
//! Emitted envelopes flow back through the pump, are **re-checked against
//! the parent's CapTable** (the worker's copy is advisory), then handed to
//! the fabric. State persists in the CAS: every committed turn ships a
//! fresh snapshot (`Persist`), so eviction loses nothing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sieveplate_core::{Cap, CapTable, CellError, Envelope, Port, Rights, Route};
use sieveplate_jail::proto::ParentToWorker;
use sieveplate_jail::{parent::spawn_worker, proto::WorkerToParent, JailProc, SandboxPolicy};
use sieveplate_store::{ContentStore, Hash};
use tokio::sync::{mpsc, oneshot};

/// Waiters for outstanding SnapshotReq calls.
type SnapshotWaiters = HashMap<u64, oneshot::Sender<Result<Vec<u8>, String>>>;

/// Everything known about one process-backed cell.
pub struct ProcCell {
    pub name: String,
    pub vat: String,
    pub template: String,
    pub caps: CapTable,
    pub sandbox: SandboxPolicy,
    pub store: Arc<ContentStore>,
    pub state_hash: Mutex<Option<Hash>>,
    proc: Mutex<Option<JailProc>>,
    snapshot_waiters: Mutex<SnapshotWaiters>,
    req_counter: AtomicU64,
}

impl ProcCell {
    fn full_name(&self) -> String {
        format!("{}/{}", self.vat, self.name)
    }

    fn stdin_sender(&self) -> Result<mpsc::Sender<ParentToWorker>, CellError> {
        let guard = self.proc.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(p) if !p.is_dead() => Ok(p.stdin_tx.clone()),
            _ => Err(CellError::Other("worker not running".into())),
        }
    }

    /// Current persisted state (for respawn), read through the CAS with
    /// verify-on-read.
    fn current_state(&self) -> Option<Vec<u8>> {
        let h = self
            .state_hash
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()?;
        self.store.get(&h).ok().flatten()
    }

    fn is_running(&self) -> bool {
        self.proc
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|p| !p.is_dead())
            .unwrap_or(false)
    }
}

/// Manager for all process cells of a host.
pub struct ProcCellManager {
    pub store: Arc<ContentStore>,
    pub exe: PathBuf,
    cells: Mutex<HashMap<String, Arc<ProcCell>>>,
}

impl ProcCellManager {
    pub fn new(store: Arc<ContentStore>, exe: PathBuf) -> Self {
        ProcCellManager {
            store,
            exe,
            cells: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, vat: &str, name: &str) -> Option<Arc<ProcCell>> {
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&format!("{vat}/{name}"))
            .cloned()
    }

    pub fn is_proc_cell(&self, vat: &str, name: &str) -> bool {
        self.get(vat, name).is_some()
    }

    /// (vat, cell, running) for every process cell.
    pub fn list(&self) -> Vec<(String, String, bool)> {
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|c| (c.vat.clone(), c.name.clone(), c.is_running()))
            .collect()
    }

    /// Instantiate a process cell: spawn the worker, wire the fabric proxy,
    /// start the pumps.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        self: &Arc<Self>,
        fabric: &sieveplate_fabric::Fabric,
        name: String,
        vat: String,
        template: String,
        caps: Vec<Cap>,
        sandbox: SandboxPolicy,
        restore_state: Option<(Vec<u8>, Option<Hash>)>,
    ) -> Result<Arc<ProcCell>, CellError> {
        let cell = Arc::new(ProcCell {
            name: name.clone(),
            vat: vat.clone(),
            template: template.clone(),
            caps: CapTable::from_caps(caps.clone()),
            sandbox,
            store: Arc::clone(&self.store),
            state_hash: Mutex::new(restore_state.as_ref().and_then(|(_, h)| h.clone())),
            proc: Mutex::new(None),
            snapshot_waiters: Mutex::new(HashMap::new()),
            req_counter: AtomicU64::new(1),
        });

        // Spawn the jailed worker (Init handshake happens inside).
        let (jproc, out_rx) = spawn_worker(
            &self.exe,
            &template,
            restore_state.map(|(s, _)| s),
            caps,
            &cell.sandbox,
        )
        .await?;
        *cell.proc.lock().unwrap_or_else(|p| p.into_inner()) = Some(jproc);

        // Inbound pump: fabric proxy mailbox → worker stdin (with respawn).
        let (in_tx, mut in_rx) = mpsc::channel::<Envelope>(256);
        fabric.attach_proxy(&vat, &name, in_tx);
        let cell2 = Arc::clone(&cell);
        let fabric2 = fabric.clone();
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(env) = in_rx.recv().await {
                // Scale-to-zero wake path: if the worker is dead (evicted
                // or crashed), respawn it with the persisted state first.
                let needs_spawn = !cell2.is_running();
                if needs_spawn {
                    let restore = cell2.current_state();
                    match spawn_worker(
                        &manager.exe,
                        &cell2.template,
                        restore,
                        cell2.caps.list().into_iter().map(|(_, c)| c).collect(),
                        &cell2.sandbox,
                    )
                    .await
                    {
                        Ok((jp, out_rx2)) => {
                            *cell2.proc.lock().unwrap_or_else(|p| p.into_inner()) = Some(jp);
                            manager.start_out_pump(Arc::clone(&cell2), out_rx2, &fabric2);
                        }
                        Err(e) => {
                            tracing::warn!(
                                cell = %cell2.full_name(),
                                error = %e,
                                "respawn failed; failing in-flight call"
                            );
                            if let Some(pid) = env.reply_to {
                                let rep = fault_reply(&env, pid, &e.to_string());
                                let _ = fabric2.deliver(rep).await;
                            }
                            continue;
                        }
                    }
                }
                let is_ping = env.kind == Envelope::KIND_PING;
                let fwd = if is_ping {
                    ParentToWorker::Ping
                } else {
                    ParentToWorker::Envelope(env)
                };
                match cell2.stdin_sender() {
                    Ok(tx) => {
                        if tx.send(fwd).await.is_err() {
                            tracing::warn!(cell = %cell2.full_name(), "worker stdin closed");
                        }
                    }
                    Err(e) => {
                        if let Some(pid) = fwd_pid(&fwd) {
                            let rep = failure_reply(pid, &e.to_string());
                            let _ = fabric2.deliver(rep).await;
                        }
                    }
                }
            }
        });

        // Outbound pump: worker stdout → capability check → fabric.
        self.start_out_pump(Arc::clone(&cell), out_rx, fabric);

        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(cell.full_name(), Arc::clone(&cell));
        Ok(cell)
    }

    /// Start the stdout pump for a freshly spawned worker.
    fn start_out_pump(
        self: &Arc<Self>,
        cell: Arc<ProcCell>,
        mut out_rx: mpsc::Receiver<WorkerToParent>,
        fabric: &sieveplate_fabric::Fabric,
    ) {
        let fabric = fabric.clone();
        let store = Arc::clone(&self.store);
        let self_port = Port::new(
            fabric.host().to_string(),
            cell.vat.clone(),
            cell.name.clone(),
        );
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                match msg {
                    WorkerToParent::Envelope(env) => {
                        // Re-check the parent-side capability table: the
                        // worker's own check is advisory; this is the real
                        // authority boundary. Replies always flow back.
                        if let Some(from) = &env.from {
                            if from != &self_port && env.kind != Envelope::KIND_REPLY {
                                let bit = if env.reply_to.is_some() {
                                    Rights::CALL
                                } else {
                                    Rights::SEND
                                };
                                if !cell.caps.grants(&env.to, bit) {
                                    tracing::warn!(
                                        cell = %cell.full_name(),
                                        to = %env.to.to_path(),
                                        "worker envelope denied by capability table"
                                    );
                                    if let Some(pid) = env.reply_to {
                                        let rep = fault_reply(
                                            &env,
                                            pid,
                                            "denied by capability table (parent check)",
                                        );
                                        let _ = fabric.deliver(rep).await;
                                    }
                                    continue;
                                }
                            }
                        }
                        let _ = fabric.deliver(env).await;
                    }
                    WorkerToParent::Pipe { pid, cont } => {
                        let _ = fabric.pipe_continuation(pid, cont);
                    }
                    WorkerToParent::Persist { state } => {
                        if let Ok(h) = store.put(&state) {
                            *cell.state_hash.lock().unwrap_or_else(|p| p.into_inner()) = Some(h);
                        }
                    }
                    WorkerToParent::Snapshot { req_id, state } => {
                        let h = store.put(&state).ok();
                        *cell.state_hash.lock().unwrap_or_else(|p| p.into_inner()) = h;
                        if let Some(tx) = cell
                            .snapshot_waiters
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&req_id)
                        {
                            let _ = tx.send(Ok(state));
                        }
                    }
                    WorkerToParent::Fault { reason } => {
                        tracing::warn!(cell = %cell.full_name(), %reason, "worker fault");
                    }
                    WorkerToParent::Pong | WorkerToParent::Ready => {}
                }
            }
        });
    }

    /// Snapshot a process cell: ask the worker for state, store it.
    pub async fn snapshot(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let cell = self
            .get(vat, name)
            .ok_or_else(|| CellError::NotFound(format!("{vat}/{name}")))?;
        let tx = cell.stdin_sender()?;
        let req_id = cell.req_counter.fetch_add(1, Ordering::SeqCst);
        let (wait_tx, rx) = oneshot::channel();
        cell.snapshot_waiters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(req_id, wait_tx);
        tx.send(ParentToWorker::SnapshotReq { req_id })
            .await
            .map_err(|_| CellError::Other("worker stdin closed".into()))?;
        let _state = tokio::time::timeout(std::time::Duration::from_secs(10), rx)
            .await
            .map_err(|_| CellError::Timeout(10_000))?
            .map_err(|_| CellError::Other("snapshot waiter dropped".into()))?
            .map_err(CellError::Other)?;
        let h = cell
            .state_hash
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| CellError::Store("snapshot hash missing".into()))?;
        Ok(h)
    }

    /// Scale to zero: persist state, then KILL the process. The OS process
    /// is gone; the next message respawns it from the CAS.
    pub async fn scale_to_zero(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let h = self.snapshot(vat, name).await?;
        if let Some(cell) = self.get(vat, name) {
            if let Some(p) = cell.proc.lock().unwrap_or_else(|p| p.into_inner()).take() {
                p.kill();
            }
        }
        Ok(h)
    }

    /// Destroy: kill + forget.
    pub async fn destroy(&self, vat: &str, name: &str) -> Result<(), CellError> {
        if let Some(cell) = self.get(vat, name) {
            if let Some(p) = cell.proc.lock().unwrap_or_else(|p| p.into_inner()).take() {
                p.kill();
            }
        }
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&format!("{vat}/{name}"));
        Ok(())
    }

    /// Force-wake via the kernel-level ping (respawns if needed); returns
    /// elapsed microseconds.
    pub async fn wake(
        &self,
        fabric: &sieveplate_fabric::Fabric,
        vat: &str,
        name: &str,
    ) -> Result<u64, CellError> {
        let _cell = self
            .get(vat, name)
            .ok_or_else(|| CellError::NotFound(format!("{vat}/{name}")))?;
        let start = std::time::Instant::now();
        let port = Port::new(fabric.host().to_string(), vat.to_string(), name.to_string());
        let rep = fabric
            .call(
                port,
                Envelope::KIND_PING,
                Vec::new(),
                std::time::Duration::from_secs(15),
            )
            .await?;
        if rep != b"pong" {
            return Err(CellError::Other("unexpected ping reply".into()));
        }
        Ok(start.elapsed().as_micros() as u64)
    }
}

/// Build a failure `__reply` for an in-flight call.
fn fault_reply(env: &Envelope, pid: u64, reason: &str) -> Envelope {
    let mut rep = Envelope::new(
        env.from.clone().unwrap_or_else(|| Port::new("", "", "")),
        Envelope::KIND_REPLY,
        reason.as_bytes().to_vec(),
    );
    rep.id = pid;
    rep
}

/// The promise id a not-yet-sent message was resolving, if any.
fn fwd_pid(fwd: &ParentToWorker) -> Option<u64> {
    match fwd {
        ParentToWorker::Envelope(env) => env.reply_to,
        _ => None,
    }
}

/// Failure reply with no destination port (resolved by promise id only).
fn failure_reply(pid: u64, reason: &str) -> Envelope {
    let mut rep = Envelope::new(
        Port::new("", "", ""),
        Envelope::KIND_REPLY,
        reason.as_bytes().to_vec(),
    );
    rep.id = pid;
    rep
}
