//! Sandbox probe cell — deliberately attempts forbidden operations.
//!
//! Used by the jail tests to prove the kernel sandbox actually denies:
//! - verb `socket` → attempts a TCP connect (seccomp denies `socket`)
//! - verb `file`   → attempts to open a file (seccomp denies `open`)
//! - verb `ok`     → harmless, replies "ok"
//!
//! The reply payload says `blocked: <os error>` when the OS refused, or
//! `ALLOWED: <detail>` if the operation somehow succeeded (a sandbox
//! regression the tests turn red for).

use sieveplate_core::{
    BoxedCell, Cell, CellError, CellFactory, Envelope, Port, TemplateRegistry, TurnCtx,
};

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SandboxProbeCell {
    attempts: u64,
}

#[allow(clippy::suspicious_open_options)]
#[async_trait::async_trait]
impl Cell for SandboxProbeCell {
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError> {
        self.attempts += 1;
        let reply = match env.kind.as_str() {
            "ok" => "ok".to_string(),
            "socket" => match std::net::TcpStream::connect("127.0.0.1:9") {
                Ok(_) => "ALLOWED: socket connect succeeded".to_string(),
                Err(e) => format!("blocked: {e}"),
            },
            "file" => match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open("/tmp/sieveplate-probe-should-fail")
            {
                Ok(_) => "ALLOWED: file open succeeded".to_string(),
                Err(e) => format!("blocked: {e}"),
            },
            other => format!("unknown verb: {other}"),
        };
        ctx.set_reply(reply.into_bytes());
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<u8>, CellError> {
        bincode::serialize(&self.attempts).map_err(|e| CellError::Other(e.to_string()))
    }

    fn restore(&mut self, data: &[u8]) -> Result<(), CellError> {
        self.attempts = bincode::deserialize(data).map_err(|e| CellError::Other(e.to_string()))?;
        Ok(())
    }
}

pub struct SandboxProbeFactory;

impl CellFactory for SandboxProbeFactory {
    fn build(&self) -> Result<BoxedCell, CellError> {
        Ok(Box::new(SandboxProbeCell::default()))
    }
    fn descriptor(&self) -> String {
        "sandbox-probe-v1".to_string()
    }
}

/// Register under `builtin:sandbox-probe`.
pub fn register(registry: &TemplateRegistry) {
    registry.register("builtin:sandbox-probe", Arc::new(SandboxProbeFactory));
}

use std::sync::Arc;

/// A port helper kept for symmetry with the other cells.
#[allow(dead_code)]
fn local_port(vat: &str, name: &str) -> Port {
    Port::new("", vat, name)
}
