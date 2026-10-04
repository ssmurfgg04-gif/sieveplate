//! WASM-cell backing: cells that are WebAssembly components executed by
//! Wasmtime with WASI preview1 (ADR-0008).
//!
//! Flow of an envelope to a wasm cell `core/wasm-ctr`:
//!
//! ```text
//! caller → fabric.deliver(env)             (env.to = host/core/wasm-ctr)
//!        → proxies["core/wasm-ctr"]         (per-cell mailbox)
//!        → pump task
//!            → run one WASI turn:
//!                fresh Store + instance (state re-materialized first)
//!                stdin  = one JSON line (the turn)
//!                guest reads /state/state.bin, mutates, rewrites it
//!                stdout = JSON lines (reply / send / error)
//!            → capability re-check → fabric
//! ```
//!
//! Isolation model: the guest has no sockets, no fork, no host memory
//! access — its ONLY capabilities are the WASI functions it imports and
//! the single preopened `/state` directory. Envelopes it emits are
//! re-checked against the parent's CapTable exactly like process cells'
//! (the guest's view is advisory; the parent is the authority).
//!
//! Scale-to-zero is structural: instances live for exactly one turn, so
//! between messages the cell occupies nothing but its compiled module
//! (cached) and its content-addressed state. Waking = next turn.
//!
//! The wire protocol (SIEVE-WASI ABI v1) is frozen and documented in
//! `docs/wasm-abi.md`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sieveplate_core::{Cap, CapTable, CellError, Envelope, Metrics, Port, Rights, Route};
use sieveplate_store::{ContentStore, Hash};
use tokio::sync::mpsc;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::WasiCtxBuilder;

/// Everything known about one wasm-backed cell.
pub struct WasmCell {
    pub name: String,
    pub vat: String,
    pub caps: CapTable,
    pub store: Arc<ContentStore>,
    pub state_hash: Mutex<Option<Hash>>,
    /// Host-side directory preopened at `/state` in the guest.
    state_dir: PathBuf,
    /// Cached compilation (engine + module + linker) — the expensive part.
    runtime: Mutex<Option<Arc<WasmRuntime>>>,
}

/// A compiled module ready to instantiate (one per cell).
pub struct WasmRuntime {
    pub engine: Engine,
    pub module: Module,
    pub linker: Linker<WasiP1Ctx>,
}

impl WasmCell {
    fn full_name(&self) -> String {
        format!("{}/{}", self.vat, self.name)
    }

    fn state_file(&self) -> PathBuf {
        self.state_dir.join("state.bin")
    }

    fn current_state(&self) -> Option<Vec<u8>> {
        let h = self
            .state_hash
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()?;
        self.store.get(&h).ok().flatten()
    }
}

/// Manager for all wasm cells of a host.
pub struct WasmCellManager {
    pub store: Arc<ContentStore>,
    /// Runtime root: per-cell state dirs live under `wasm-state/`.
    root: PathBuf,
    /// Shared metrics (turn latencies/counters land in the same series as
    /// thread cells so the dashboard treats every isolation uniformly).
    metrics: Arc<Metrics>,
    cells: Mutex<HashMap<String, Arc<WasmCell>>>,
}

impl WasmCellManager {
    pub fn new(store: Arc<ContentStore>, root: impl Into<PathBuf>, metrics: Arc<Metrics>) -> Self {
        WasmCellManager {
            store,
            root: root.into(),
            metrics,
            cells: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, vat: &str, name: &str) -> Option<Arc<WasmCell>> {
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&format!("{vat}/{name}"))
            .cloned()
    }

    pub fn is_wasm_cell(&self, vat: &str, name: &str) -> bool {
        self.get(vat, name).is_some()
    }

    /// (vat, cell, running) for every wasm cell. A wasm cell is always
    /// "running" in the sense that its next message will execute — there
    /// is no resident process to die.
    pub fn list(&self) -> Vec<(String, String, bool)> {
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|c| (c.vat.clone(), c.name.clone(), true))
            .collect()
    }

    /// Resolve a `wasm:`/`cas:` template reference to module bytes.
    /// - `wasm:<path>` — file path (absolute, or relative to the runtime
    ///   root); `.wat` text modules are assembled automatically.
    /// - `cas:<hash>` — module bytes already in the content store.
    fn module_bytes(&self, template: &str) -> Result<Vec<u8>, CellError> {
        if let Some(h) = template.strip_prefix("cas:") {
            return self
                .store
                .get(h)
                .map_err(|e| CellError::Store(e.to_string()))?
                .ok_or_else(|| CellError::NotFound(format!("module {h}")));
        }
        if let Some(p) = template.strip_prefix("wasm:") {
            let path = PathBuf::from(p);
            // Resolution order: absolute → relative to CWD → relative to
            // the runtime root (so `wasm:cells/counter.wasm` works both
            // from the repo and from a service's working directory).
            let path = if path.is_absolute() || path.exists() {
                path
            } else {
                self.root.join(path)
            };
            let bytes = std::fs::read(&path)
                .map_err(|e| CellError::Other(format!("module '{p}' unreadable: {e}")))?;
            // WAT text → binary (dev convenience; committed modules are wasm).
            if String::from_utf8_lossy(&bytes[..bytes.len().min(4)]).starts_with("(mod")
                || path.extension().is_some_and(|e| e == "wat")
            {
                return wat::parse_bytes(&bytes)
                    .map(|cow: std::borrow::Cow<'_, [u8]>| cow.into_owned())
                    .map_err(|e| CellError::Other(format!("wat parse: {e}")));
            }
            return Ok(bytes);
        }
        Err(CellError::Other(format!(
            "template '{template}' is not a wasm: or cas: module reference"
        )))
    }

    /// Instantiate a wasm cell: compile the module, wire the fabric proxy,
    /// start the pump.
    pub async fn create(
        self: &Arc<Self>,
        fabric: &sieveplate_fabric::Fabric,
        name: String,
        vat: String,
        template: String,
        caps: Vec<Cap>,
        restore_state: Option<Vec<u8>>,
    ) -> Result<Arc<WasmCell>, CellError> {
        let bytes = self.module_bytes(&template)?;
        let state_dir = self.root.join("wasm-state").join(&vat).join(&name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| CellError::Other(format!("state dir: {e}")))?;

        // Restore path: seed the state file from the persisted blob.
        let cell = Arc::new(WasmCell {
            name: name.clone(),
            vat: vat.clone(),
            caps: CapTable::from_caps(caps),
            store: Arc::clone(&self.store),
            state_hash: Mutex::new(None),
            state_dir,
            runtime: Mutex::new(None),
        });
        if let Some(state) = restore_state {
            std::fs::write(cell.state_file(), &state)
                .map_err(|e| CellError::Other(format!("state seed: {e}")))?;
        }

        // Compile once (sync — module bytes are already in memory).
        let runtime = Arc::new(compile(&bytes)?);
        *cell.runtime.lock().unwrap_or_else(|p| p.into_inner()) = Some(runtime);

        // Inbound pump: fabric proxy mailbox → WASI turns.
        let (in_tx, mut in_rx) = mpsc::channel::<Envelope>(256);
        fabric.attach_proxy(&vat, &name, in_tx);
        let cell2 = Arc::clone(&cell);
        let fabric2 = fabric.clone();
        let manager = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            while let Some(env) = in_rx.blocking_recv() {
                if env.kind == Envelope::KIND_PING {
                    // Kernel-level wake probe: no handler runs; the cell
                    // is "woken" by materializing its state.
                    if let Some(pid) = env.reply_to {
                        let rep = reply_env(pid, b"pong".to_vec());
                        let fl = fabric2.clone();
                        tokio::spawn(async move {
                            let _ = fl.deliver(rep).await;
                        });
                    }
                    continue;
                }
                match manager.run_turn(&fabric2, &cell2, env) {
                    Ok(messages) => apply_messages(&fabric2, &cell2, messages),
                    Err(reason) => {
                        tracing::warn!(cell = %cell2.full_name(), %reason, "wasm turn failed");
                    }
                }
            }
        });

        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(cell.full_name(), Arc::clone(&cell));
        Ok(cell)
    }

    /// Execute one turn synchronously (runs on the blocking pool).
    fn run_turn(
        &self,
        fabric: &sieveplate_fabric::Fabric,
        cell: &Arc<WasmCell>,
        env: Envelope,
    ) -> Result<Vec<GuestMessage>, String> {
        let turn_started = std::time::Instant::now();
        self.metrics.count("messages_in");
        let runtime = cell
            .runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| "cell not compiled".to_string())?;

        // Materialize persisted state for the guest to read.
        if let Some(state) = cell.current_state() {
            std::fs::write(cell.state_file(), &state)
                .map_err(|e| format!("state materialize: {e}"))?;
        }

        let stdin_line = turn_json(&env)?;
        let stdin = MemoryInputPipe::new(stdin_line);
        let stdout = MemoryOutputPipe::new(1 << 20);

        let mut builder = WasiCtxBuilder::new();
        builder.stdin(stdin);
        builder.stdout(stdout.clone());
        builder.stderr(wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(1 << 16));
        builder
            .preopened_dir(&cell.state_dir, "/state", wasmtime_wasi::FsPerms::ReadWrite)
            .map_err(|e| e.to_string())?;
        let wasi = builder.build_p1();

        let mut store = Store::new(&runtime.engine, wasi);
        let instance = runtime
            .linker
            .instantiate(&mut store, &runtime.module)
            .map_err(|e| format!("instantiate: {e}"))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| format!("no _start: {e}"))?;
        start
            .call(&mut store, ())
            .map_err(|e| format!("trap: {e}"))?;

        // Parse the guest's stdout: one JSON object per line.
        let out = stdout.contents().to_vec();
        let mut messages = Vec::new();
        for line in String::from_utf8_lossy(&out).lines() {
            if line.trim().is_empty() {
                continue;
            }
            match parse_guest_line(line) {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    tracing::warn!(cell = %cell.full_name(), line, error = %e, "bad guest line")
                }
            }
        }

        self.metrics
            .record_us("turn_us", turn_started.elapsed().as_micros() as u64);
        // Harvest state (unless the guest reported an error this turn).
        let errored = messages.iter().any(|m| matches!(m, GuestMessage::Error(_)));
        if !errored {
            if let Ok(state) = std::fs::read(cell.state_file()) {
                if let Ok(h) = cell.store.put(&state) {
                    *cell.state_hash.lock().unwrap_or_else(|p| p.into_inner()) = Some(h);
                }
            }
        }

        // Every envelope the guest emitted flows back through the pump's
        // caller with the parent cap check (apply_messages). Replies that
        // reference the incoming envelope's promise are addressed by id.
        let _ = fabric; // (used by apply_messages; kept for symmetry)
        Ok(messages)
    }

    /// Snapshot: the cell's persisted state hash (turns persist on
    /// commit).
    pub fn snapshot(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let cell = self
            .get(vat, name)
            .ok_or_else(|| CellError::NotFound(format!("{vat}/{name}")))?;
        let hash = cell
            .state_hash
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        hash.ok_or_else(|| CellError::Store("wasm cell has no persisted state yet".into()))
    }

    /// Scale to zero: wasm cells are structurally at zero between turns —
    /// this just returns the persisted hash (and clears any live state
    /// file so the next turn re-materializes from the CAS).
    pub fn scale_to_zero(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let cell = self
            .get(vat, name)
            .ok_or_else(|| CellError::NotFound(format!("{vat}/{name}")))?;
        let h = self.snapshot(vat, name)?;
        let _ = std::fs::remove_file(cell.state_file());
        Ok(h)
    }

    /// Destroy: forget the cell and CLOSE its mailbox (dropping the proxy
    /// sender ends the pump's blocking loop — required for clean runtime
    /// shutdown, which waits for blocking tasks).
    pub fn destroy(
        &self,
        fabric: &sieveplate_fabric::Fabric,
        vat: &str,
        name: &str,
    ) -> Result<(), CellError> {
        fabric.drop_proxy(vat, name);
        self.cells
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&format!("{vat}/{name}"));
        Ok(())
    }

    /// Force-wake via the kernel-level ping; returns elapsed microseconds.
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
        let us = start.elapsed().as_micros() as u64;
        self.metrics.record_us("wake_us", us);
        Ok(us)
    }
}

/// One compiled module (cached per cell).
fn compile(bytes: &[u8]) -> Result<WasmRuntime, CellError> {
    let engine = Engine::default();
    let module = Module::from_binary(&engine, bytes)
        .map_err(|e| CellError::Other(format!("bad wasm module: {e}")))?;
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |t| t)
        .map_err(|e| CellError::Other(format!("linker: {e}")))?;
    Ok(WasmRuntime {
        engine,
        module,
        linker,
    })
}

/// The turn request serialized for the guest's stdin (ABI v1).
fn turn_json(env: &Envelope) -> Result<Vec<u8>, String> {
    use serde_json::json;
    let from = env.from.as_ref().map(|p| p.to_path());
    let line = json!({
        "op": "turn",
        "kind": env.kind,
        "payload_b64": b64(&env.payload),
        "reply_to": env.reply_to,
        "from": from,
    });
    let mut out = serde_json::to_vec(&line).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok(out)
}

/// Messages a guest may produce in one turn (ABI v1).
enum GuestMessage {
    /// Resolve the referenced promise with a payload.
    Reply { id: u64, payload: Vec<u8> },
    /// Emit an envelope (subject to the parent capability check).
    Send {
        to: Port,
        kind: String,
        payload: Vec<u8>,
        reply_to: Option<u64>,
    },
    /// The turn failed; state changes are ignored.
    Error(String),
}

fn parse_guest_line(line: &str) -> Result<GuestMessage, String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("json: {e}"))?;
    match v["op"].as_str() {
        Some("reply") => {
            let id = v["id"].as_u64().ok_or("reply missing id")?;
            let payload = v["payload_b64"].as_str().map(unb64).unwrap_or_default();
            Ok(GuestMessage::Reply { id, payload })
        }
        Some("send") => {
            let to = v["to"].as_str().ok_or("send missing to")?.to_string();
            let kind = v["kind"].as_str().ok_or("send missing kind")?.to_string();
            let payload = v["payload_b64"].as_str().map(unb64).unwrap_or_default();
            let reply_to = v["reply_to"].as_u64();
            Ok(GuestMessage::Send {
                to: parse_loose_port(&to)?,
                kind,
                payload,
                reply_to,
            })
        }
        Some("error") => Ok(GuestMessage::Error(
            v["message"].as_str().unwrap_or("guest error").to_string(),
        )),
        // Unknown ops are ignored: forward compatibility.
        _ => Err(format!("unknown op in '{line}'")),
    }
}

/// `host/vat/cell` or `vat/cell` (host defaults to the local host).
fn parse_loose_port(s: &str) -> Result<Port, String> {
    let segs: Vec<&str> = s.split('/').filter(|x| !x.is_empty()).collect();
    match segs.len() {
        3 => Ok(Port::new(segs[0], segs[1], segs[2])),
        2 => Ok(Port::new("", segs[0], segs[1])),
        _ => Err(format!("'{s}' is not a port path")),
    }
}

fn apply_messages(
    fabric: &sieveplate_fabric::Fabric,
    cell: &Arc<WasmCell>,
    messages: Vec<GuestMessage>,
) {
    let self_port = Port::new(
        fabric.host().to_string(),
        cell.vat.clone(),
        cell.name.clone(),
    );
    for msg in messages {
        match msg {
            GuestMessage::Error(reason) => {
                tracing::warn!(cell = %cell.full_name(), %reason, "guest error");
            }
            GuestMessage::Reply { id, payload } => {
                let rep = reply_env(id, payload);
                let rt = fabric.clone();
                tokio::spawn(async move {
                    let _ = rt.deliver(rep).await;
                });
            }
            GuestMessage::Send {
                to,
                kind,
                payload,
                reply_to,
            } => {
                let mut env = Envelope::new(to, kind, payload);
                // Stamp the cell as sender, then re-check the parent-side
                // capability table: the guest's view is advisory.
                env.from = Some(self_port.clone());
                env.reply_to = reply_to;
                let bit = if reply_to.is_some() {
                    Rights::CALL
                } else {
                    Rights::SEND
                };
                if !cell.caps.grants(&env.to, bit) {
                    tracing::warn!(
                        cell = %cell.full_name(),
                        to = %env.to.to_path(),
                        "wasm envelope denied by capability table"
                    );
                    continue;
                }
                let rt = fabric.clone();
                tokio::spawn(async move {
                    let _ = rt.deliver(env).await;
                });
            }
        }
    }
}

/// A `__reply` envelope resolving `id` (delivered to the promise registry).
fn reply_env(id: u64, payload: Vec<u8>) -> Envelope {
    let mut rep = Envelope::new(Port::new("", "", ""), Envelope::KIND_REPLY, payload);
    rep.id = id;
    rep
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}
