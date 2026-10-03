//! Parent side of the jail: spawn, supervise, and mediate worker processes.
//!
//! [`spawn_worker`] launches a `sieve __worker` child with empty
//! environment and pipes as its only I/O. The pump threads bridge those
//! blocking pipes into async channels:
//! - child → parent envelopes are capability-checked at the *engine*
//!   boundary (the parent owns the CapTable; the OS sandbox bounds the
//!   process itself);
//! - parent → child envelopes ride the same pipe;
//! - child death (crash / seccomp kill / OOM) is observed as pipe EOF and
//!   surfaced through [`JailProc::is_dead`], so in-flight calls FAIL
//!   instead of hanging.

use std::io::Write as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::proto::{recv_frame, send_frame, ParentToWorker, WorkerToParent};
use crate::sandbox::SandboxPolicy;
use sieveplate_core::CellError;

/// A running jailed worker.
pub struct JailProc {
    pub stdin_tx: mpsc::Sender<ParentToWorker>,
    child: Arc<Mutex<Option<Child>>>,
    /// Set when the pipe to the worker breaks (worker died).
    dead: Arc<AtomicBool>,
}

impl JailProc {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Kill the child (best effort) — used by scale-to-zero and destroy.
    pub fn kill(&self) {
        if let Some(child) = self
            .child
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `exe __worker` with the given template + optional restored state.
/// Returns the handle plus a receiver of everything the worker emits.
pub async fn spawn_worker(
    exe: &std::path::Path,
    template: &str,
    restore_state: Option<Vec<u8>>,
    caps: Vec<sieveplate_core::Cap>,
    policy: &SandboxPolicy,
) -> Result<(JailProc, mpsc::Receiver<WorkerToParent>), CellError> {
    let mut cmd = Command::new(exe);
    cmd.args([
        "__worker",
        "--sandbox",
        serde_json::to_string(policy)
            .map_err(|e| CellError::Other(e.to_string()))?
            .as_str(),
    ])
    .env_clear()
    // The worker gets NO ambient environment: no HOME, no TMPDIR, no PATH.
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| CellError::Other(format!("worker spawn failed: {e}")))?;

    let mut stdin: std::process::ChildStdin = child
        .stdin
        .take()
        .ok_or_else(|| CellError::Other("no worker stdin".into()))?;
    let mut stdout: std::process::ChildStdout = child
        .stdout
        .take()
        .ok_or_else(|| CellError::Other("no worker stdout".into()))?;

    let dead = Arc::new(AtomicBool::new(false));

    // Writer thread: tokio channel → blocking pipe writes.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<ParentToWorker>(256);
    {
        let dead_w = Arc::clone(&dead);
        std::thread::spawn(move || {
            while let Some(msg) = stdin_rx.blocking_recv() {
                let mut buf = Vec::new();
                if send_frame(&mut buf, &msg).is_err() {
                    break;
                }
                if stdin.write_all(&buf).is_err() {
                    break;
                }
            }
            dead_w.store(true, Ordering::SeqCst);
        });
    }

    // Reader thread: blocking pipe reads → tokio channel.
    let (out_tx, mut out_rx) = mpsc::channel::<WorkerToParent>(1024);
    {
        let dead_r = Arc::clone(&dead);
        std::thread::spawn(move || {
            loop {
                match recv_frame(&mut stdout) {
                    Ok(Some(msg)) => {
                        if out_tx.blocking_send(msg).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // EOF: worker gone
                    Err(_) => break,
                }
            }
            dead_r.store(true, Ordering::SeqCst);
        });
    }

    let handle = JailProc {
        stdin_tx,
        child: Arc::new(Mutex::new(Some(child))),
        dead,
    };

    // Init handshake: two Ready frames (sandbox applied, cell built).
    handle
        .stdin_tx
        .send(ParentToWorker::Init {
            template: template.to_string(),
            restore_state,
            caps,
        })
        .await
        .map_err(|_| CellError::Other("worker died during init".into()))?;
    for expected in 0..2 {
        match tokio::time::timeout(std::time::Duration::from_secs(30), out_rx.recv()).await {
            Ok(Some(WorkerToParent::Ready)) => {}
            Ok(Some(WorkerToParent::Fault { reason })) => {
                return Err(CellError::Other(format!("worker fault at init: {reason}")));
            }
            Ok(Some(_)) => {}
            Ok(None) => return Err(CellError::Other("worker EOF at init".into())),
            Err(_) => {
                return Err(CellError::Other(format!(
                    "worker init timeout (waiting ready #{expected})"
                )))
            }
        }
    }
    Ok((handle, out_rx))
}
