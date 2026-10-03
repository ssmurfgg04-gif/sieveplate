//! The jailed worker: one cell, one process, zero ambient authority.
//!
//! Startup sequence (all before any cell code runs):
//! 1. apply the sandbox (rlimit → Landlock → `NO_NEW_PRIVS` → seccomp);
//! 2. report the enforcement result to the parent;
//! 3. wait for `Init` (template + caps + optional restored state).
//!
//! Turns are driven synchronously (`futures::executor::block_on`) —
//! the reference cells never await inside a handler, so this is exact and
//! keeps the worker single-threaded (no `clone`, which seccomp denies).
//! Every envelope the cell emits flows to the parent over stdout, where
//! capabilities are re-checked before routing.

use std::sync::Arc;

use futures::FutureExt;
use sieveplate_core::{
    BoxedCell, CapTable, CellError, Envelope, Port, Promises, Route, TemplateRegistry, TurnRunner,
};

use crate::proto::{recv_frame, send_frame, ParentToWorker, WorkerToParent};
use crate::sandbox::{self, SandboxPolicy};

/// Frame writes to stdout, whole-frame at a time (the parent's reader
/// thread parses complete frames — interleaved partial writes would be
/// garbage). `std::io::Stdout` has its own internal lock; taking the
/// `StdoutLock` for the duration of one `send_frame` makes a frame atomic.
fn send_out(msg: &WorkerToParent) -> std::io::Result<()> {
    let mut lock = std::io::stdout().lock();
    send_frame(&mut lock, msg)
}

/// The worker's only "network": the stdout pipe to the parent. Every
/// send/call/pipe becomes a protocol message the parent mediates.
#[derive(Clone, Default)]
struct ParentRoute;

impl ParentRoute {
    fn send(&self, msg: WorkerToParent) {
        let _ = send_out(&msg);
    }
}

#[async_trait::async_trait]
impl Route for ParentRoute {
    async fn deliver(&self, env: Envelope) -> Result<(), CellError> {
        self.send(WorkerToParent::Envelope(env));
        Ok(())
    }

    fn pipe_continuation(
        &self,
        pid: sieveplate_core::PromiseId,
        cont: sieveplate_core::Continuation,
    ) -> Result<(), CellError> {
        self.send(WorkerToParent::Pipe { pid, cont });
        Ok(())
    }
}

/// Run the worker until EOF or `Shutdown`. `registry` supplies the cell
/// templates (the CLI binary passes the built-in registry).
pub fn run_worker(
    registry: &TemplateRegistry,
    policy: &SandboxPolicy,
    rd: &mut dyn std::io::Read,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Sandbox FIRST — no cell code, no registry use before this.
    let report = match sandbox::apply_self(policy) {
        Ok(r) => r,
        Err(e) => {
            // Sandbox failure is fatal: report and exit non-zero.
            let _ = send_out(&WorkerToParent::Fault {
                reason: format!("sandbox init failed: {e}"),
            });
            return Err(e.into());
        }
    };
    send_out(&WorkerToParent::Ready)?;
    tracing::info!(?report, "worker sandboxed");

    let route = Arc::new(ParentRoute);

    let mut cell: Option<BoxedCell> = None;
    let mut runner: Option<TurnRunner> = None;
    let promises = Promises::new();

    while let Some(msg) = recv_frame(rd)? {
        let msg: ParentToWorker = msg;
        match msg {
            ParentToWorker::Shutdown => break,
            ParentToWorker::Ping => send_out(&WorkerToParent::Pong)?,
            ParentToWorker::Init {
                template,
                restore_state,
                caps,
            } => {
                match registry.build(&template) {
                    Ok(mut c) => {
                        if let Some(state) = restore_state {
                            if let Err(e) = c.restore(&state) {
                                send_out(&WorkerToParent::Fault {
                                    reason: format!("restore failed: {e}"),
                                })?;
                                continue;
                            }
                        }
                        // The real self-port is stamped per-envelope by
                        // run_turn (set_self_port); caps come from the
                        // parent, which re-checks them at the boundary too.
                        let r = TurnRunner::new(
                            Port::new("worker", "", "pending"),
                            CapTable::from_caps(caps),
                            route.clone(),
                            Arc::new(promises.clone()),
                        );
                        runner = Some(r);
                        cell = Some(c);
                        send_out(&WorkerToParent::Ready)?;
                    }
                    Err(e) => {
                        send_out(&WorkerToParent::Fault {
                            reason: format!("build failed: {e}"),
                        })?;
                    }
                }
            }
            ParentToWorker::Envelope(env) => match env.kind.as_str() {
                sieveplate_core::Envelope::KIND_REPLY => {
                    // Resolve a local promise (from a pipelined ctx.call).
                    let _ = promises.resolve_notify(env.id, env.payload);
                }
                sieveplate_core::Envelope::KIND_PING => {
                    // Kernel-level wake probe: no handler invocation.
                    let mut rep =
                        Envelope::new(reply_target(&env), Envelope::KIND_REPLY, b"pong".to_vec());
                    rep.id = env.reply_to.unwrap_or(rep.id);
                    send_out(&WorkerToParent::Envelope(rep))?;
                }
                _ => {
                    if let (Some(c), Some(r)) = (cell.as_mut(), runner.as_mut()) {
                        run_turn(c, r, env)?;
                    } else {
                        send_out(&WorkerToParent::Fault {
                            reason: "cell not initialized".into(),
                        })?;
                    }
                }
            },
            ParentToWorker::Pipe { pid, cont } => {
                // Registered on the worker-side promise registry so local
                // waiters chain; the parent ALSO registers it on the fabric
                // registry for cross-host continuation.
                promises.pipe(pid, cont);
            }
            ParentToWorker::SnapshotReq { req_id } => {
                if let Some(c) = cell.as_ref() {
                    match c.snapshot() {
                        Ok(state) => {
                            send_out(&WorkerToParent::Snapshot { req_id, state })?;
                        }
                        Err(e) => {
                            send_out(&WorkerToParent::Fault {
                                reason: format!("snapshot failed: {e}"),
                            })?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Drive one transactional turn inside the worker.
fn run_turn(
    cell: &mut BoxedCell,
    runner: &mut TurnRunner,
    env: Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    // Point the runner's self-port at the addressed cell (per-envelope
    // stamping keeps the worker generic over one template/many cells).
    runner.set_self_port(env.to.clone());
    let pre_state = cell.snapshot().unwrap_or_default();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ctx = runner.ctx();
        cell.handle(&env, &mut ctx).now_or_never()
    }));

    match outcome {
        Ok(Some(Ok(()))) => {
            // Commit: flush outbox + auto reply.
            for out in runner.take_outbox() {
                send_out(&WorkerToParent::Envelope(out))?;
            }
            if let Some(reply) = runner.take_reply() {
                let mut rep = Envelope::new(reply_target(&env), Envelope::KIND_REPLY, reply);
                rep.id = env.reply_to.unwrap_or(rep.id);
                send_out(&WorkerToParent::Envelope(rep))?;
            }
            // Persist-on-turn: ship fresh state to the parent.
            if let Ok(state) = cell.snapshot() {
                if state != pre_state {
                    send_out(&WorkerToParent::Persist { state })?;
                }
            }
        }
        Ok(Some(Err(reason))) => {
            let _ = cell.restore(&pre_state);
            send_out(&WorkerToParent::Fault {
                reason: reason.to_string(),
            })?;
        }
        Ok(None) => {
            // Handler never completed or polled a pending future: treat as
            // a fault (worker cells must be synchronous).
            let _ = cell.restore(&pre_state);
            send_out(&WorkerToParent::Fault {
                reason: "turn did not complete synchronously".into(),
            })?;
        }
        Err(panic) => {
            let _ = cell.restore(&pre_state);
            let reason = panic_message(panic);
            send_out(&WorkerToParent::Fault { reason })?;
        }
    }
    Ok(())
}

/// The reply target of an envelope: its `from` port (driver calls have no
/// from — replies then carry an empty port and resolve by promise id at
/// the parent).
fn reply_target(env: &Envelope) -> Port {
    match &env.from {
        Some(p) => p.clone(),
        None => Port::new("", "", ""),
    }
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        format!("panic: {s}")
    } else if let Some(s) = panic.downcast_ref::<String>() {
        format!("panic: {s}")
    } else {
        "panic: unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_messages_are_strings() {
        assert!(panic_message(Box::new("boom")).contains("boom"));
        assert!(panic_message(Box::new("x".to_string())).contains("x"));
    }
}
