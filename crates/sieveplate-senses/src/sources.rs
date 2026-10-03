//! Event sources: timer, TCP listener, file tail (inotify), synthetic.
//!
//! All sources push events through an mpsc channel into the pump —
//! nothing in the system polls for events.

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// One sensory event.
#[derive(Debug, Clone)]
pub struct Signal {
    /// Source name (matches the declarative `[[sense]]` name).
    pub source: String,
    /// Signal name (becomes the envelope `kind` unless a route overrides).
    pub name: String,
    pub payload: Vec<u8>,
}

/// Channel sink all sources share.
pub type SignalTx = mpsc::Sender<Signal>;

/// Periodic timer source (the demo heartbeat).
pub fn spawn_timer(name: &str, period_ms: u64, tx: SignalTx) -> tokio::task::JoinHandle<()> {
    let name = name.to_string();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(period_ms.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // immediate first tick consumed
        loop {
            ticker.tick().await;
            let sig = Signal {
                source: name.clone(),
                name: name.clone(),
                payload: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis().to_le_bytes().to_vec())
                    .unwrap_or_default(),
            };
            if tx.send(sig).await.is_err() {
                break; // pump gone: shut down
            }
        }
    })
}

/// JSON-lines TCP source. Each line: {"name": "...", "payload": "..."}.
pub fn spawn_tcp(name: &str, addr: &str, tx: SignalTx) -> tokio::task::JoinHandle<()> {
    let name = name.to_string();
    let addr = addr.to_string();
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%addr, error = %e, "tcp sense bind failed");
                return;
            }
        };
        tracing::info!(%addr, sense = %name, "tcp sense listening");
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "tcp accept failed");
                    continue;
                }
            };
            let tx = tx.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line[..line.len() - 1]);
                        if line.trim().is_empty() {
                            continue;
                        }
                        let (sname, payload) = parse_json_line(&line);
                        let sig = Signal {
                            source: name.clone(),
                            name: sname.unwrap_or_else(|| name.clone()),
                            payload: payload.into_bytes(),
                        };
                        if tx.send(sig).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

/// File-tail source (inotify-driven on Linux): each appended JSON line is a
/// signal. This is the consumption end of the eBPF bridge: `ebpf/run.sh`
/// appends kernel events as JSON lines and cells wake the instant they
/// appear — no polling.
pub fn spawn_file_tail(
    name: &str,
    path: std::path::PathBuf,
    tx: SignalTx,
) -> tokio::task::JoinHandle<()> {
    let name = name.to_string();
    #[cfg(target_os = "linux")]
    {
        tokio::spawn(async move {
            if let Err(e) = inotify_tail(&name, path, tx).await {
                tracing::error!(error = %e, "file-tail sense exited");
            }
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        tokio::spawn(async move {
            tracing::warn!(sense = %name, "file-tail sense unsupported on this platform");
            let _ = tx;
        })
    }
}

#[cfg(target_os = "linux")]
async fn inotify_tail(
    name: &str,
    path: std::path::PathBuf,
    tx: SignalTx,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use inotify::{Inotify, WatchMask};
    use std::io::Read;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        std::fs::write(&path, b"")?;
    }

    let mut inotify = Inotify::init()?;
    inotify
        .watches()
        .add(&path, WatchMask::MODIFY | WatchMask::CREATE)?;
    tracing::info!(path = %path.display(), sense = %name, "file-tail sense watching");

    let mut file = std::fs::File::open(&path)?;
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        // Block until inotify fires (event-driven, no polling).
        let mut events = inotify.read_events_blocking(&mut buf)?;
        if events.next().is_none() {
            continue;
        }
        // Read everything newly appended (file position persists between
        // events, so read_to_end yields only fresh bytes).
        let mut new_bytes = Vec::new();
        file.read_to_end(&mut new_bytes)?;
        pending.extend_from_slice(&new_bytes);
        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]);
            if line.trim().is_empty() {
                continue;
            }
            let (sname, payload) = parse_json_line(&line);
            let sig = Signal {
                source: name.to_string(),
                name: sname.unwrap_or_else(|| name.to_string()),
                payload: payload.into_bytes(),
            };
            if tx.send(sig).await.is_err() {
                return Ok(());
            }
        }
    }
}

/// Parse {"name": "...", "payload": "..."} JSON lines.
fn parse_json_line(line: &str) -> (Option<String>, String) {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => {
            let name = v.get("name").and_then(|x| x.as_str()).map(String::from);
            let payload = match v.get("payload") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            (name, payload)
        }
        // Plain text line: use the sense's own name.
        Err(_) => (None, line.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_lines() {
        let (n, p) = parse_json_line(r#"{"name":"packet","payload":"abc"}"#);
        assert_eq!(n.as_deref(), Some("packet"));
        assert_eq!(p, "abc");
        let (n, p) = parse_json_line("plain text");
        assert_eq!(n, None);
        assert_eq!(p, "plain text");
    }
}
