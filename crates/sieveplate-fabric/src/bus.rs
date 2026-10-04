//! GitHub issue-comment bus — a transport for hosts that cannot accept
//! inbound TCP connections (GitHub Actions runners are behind NAT, and so
//! is half the real world).
//!
//! Every host participating in a demo shares one GitHub issue ("the bus").
//! A node's outbound sealed frames are batched into a comment addressed to
//! one peer: `SIEVE-BUS {"v":1,"from":"alpha","to":"beta","frames":"<b64>"}`.
//! Each node polls the bus, claims comments addressed to it, and feeds the
//! raw `len|sealed` frames into a per-peer in-memory duplex — the same
//! byte-stream contract TCP gives us. Because [`crate::net`] link
//! establishment is generic over `AsyncRead + AsyncWrite`, the *entire*
//! SIEVE1 secure-link stack (hybrid PQ handshake, peer pinning, replay
//! protection, route announcements, multi-hop forwarding) runs over the
//! bus unchanged.
//!
//! Honesty notes (do not oversell this):
//! - The bus is a store-and-forward datalog, not a network. Latency is
//!   bounded by the poll interval, not by physics.
//! - Confidentiality/authentication come from SIEVE1 end-to-end, NOT from
//!   GitHub: the repo owner can read every comment and still see nothing
//!   but ciphertext.
//! - The default Actions `GITHUB_TOKEN` is rate-limited to ~1,000 REST
//!   calls/hour/repository; the three-host demo budgets well under that.
//! - The bus issue must be FRESH per run (the workflow creates and deletes
//!   one); nodes start reading from comment id 0.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::FabricError;

const MARKER: &str = "SIEVE-BUS";
/// Stay far below GitHub's 65536-char comment limit.
const MAX_BODY: usize = 48_000;

/// Where the bus lives and who may speak on it.
#[derive(Clone, Debug)]
pub struct BusConfig {
    /// `owner/name`
    pub repo: String,
    pub issue: u64,
    /// Token with `issues:write` on the repo. Falls back to
    /// `$GITHUB_TOKEN` when empty.
    pub token: String,
    pub poll_ms: u64,
}

impl BusConfig {
    fn token(&self) -> String {
        if self.token.is_empty() {
            std::env::var("GITHUB_TOKEN").unwrap_or_default()
        } else {
            self.token.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub REST plumbing (blocking; driven from tokio via spawn_blocking)
// ---------------------------------------------------------------------------

fn api_get(
    repo: &str,
    issue: u64,
    token: &str,
    page: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let url = format!(
        "https://api.github.com/repos/{repo}/issues/{issue}/comments?per_page=100&page={page}"
    );
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build();
    let resp = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("User-Agent", "sieveplate-bus")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GET comments: {e}"))?;
    resp.into_json::<Vec<serde_json::Value>>()
        .map_err(|e| format!("decode comments: {e}"))
}

fn api_post(repo: &str, issue: u64, token: &str, body: &str) -> Result<u64, String> {
    let url = format!("https://api.github.com/repos/{repo}/issues/{issue}/comments");
    let payload = serde_json::json!({ "body": body }).to_string();
    for attempt in 0..3 {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        let res = agent
            .post(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("User-Agent", "sieveplate-bus")
            .set("Accept", "application/vnd.github+json")
            .send_string(&payload);
        match res {
            Ok(resp) => {
                let v: serde_json::Value = resp
                    .into_json()
                    .map_err(|e| format!("decode comment id: {e}"))?;
                return v["id"]
                    .as_u64()
                    .ok_or_else(|| "no comment id in response".into());
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                if (500..600).contains(&code) && attempt < 2 {
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                return Err(format!(
                    "POST comment: HTTP {code}: {}",
                    truncate(&text, 300)
                ));
            }
            Err(e) => {
                if attempt < 2 {
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                return Err(format!("POST comment: {e}"));
            }
        }
    }
    unreachable!("retry loop always returns")
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

// ---------------------------------------------------------------------------
// Wire plumbing
// ---------------------------------------------------------------------------

/// One raw wire frame INCLUDING its `u32-be` length prefix, ready to be
/// concatenated into a batch or written into a duplex.
type RawFrame = Vec<u8>;

fn split_frames(mut buf: &[u8]) -> Result<Vec<RawFrame>, FabricError> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + len {
            return Err(FabricError::Codec("truncated frame in bus batch".into()));
        }
        out.push(buf[..4 + len].to_vec());
        buf = &buf[4 + len..];
    }
    if !buf.is_empty() {
        return Err(FabricError::Codec("dangling bytes in bus batch".into()));
    }
    Ok(out)
}

/// A participant on the bus. One per process.
pub struct BusNode {
    pub name: String,
    cfg: BusConfig,
    /// Per-destination outbound batches of raw frames, flushed each tick.
    outboxes: Mutex<HashMap<String, Vec<RawFrame>>>,
    /// Per-peer inbound feeder: raw frames written into that peer's wire
    /// duplex, so the link pump sees an ordinary byte stream.
    inbound: Mutex<HashMap<String, mpsc::Sender<RawFrame>>>,
    /// A previously unseen sender just spoke to us: surface a fresh duplex
    /// here and the accept loop will run the SIEVE1 responder on it.
    accepts: mpsc::Sender<(String, tokio::io::DuplexStream)>,
    last_comment: AtomicI64,
    stop: AtomicBool,
}

impl BusNode {
    pub fn new(
        name: impl Into<String>,
        cfg: BusConfig,
        accepts: mpsc::Sender<(String, tokio::io::DuplexStream)>,
    ) -> Arc<Self> {
        Arc::new(BusNode {
            name: name.into(),
            cfg,
            outboxes: Mutex::new(HashMap::new()),
            inbound: Mutex::new(HashMap::new()),
            accepts,
            last_comment: AtomicI64::new(0),
            stop: AtomicBool::new(false),
        })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn queue(&self, dest: &str, frame: RawFrame) {
        self.outboxes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(dest.to_string())
            .or_default()
            .push(frame);
    }

    /// Open a virtual wire to `peer`. Returns the user end: an ordinary
    /// duplex stream on which SIEVE1 + the envelope pump run unchanged.
    ///
    /// Every wire is TAGGED (`peer#<nanos>`): a redial gets a fresh,
    /// isolated wire on both ends, so stale handshake frames from an
    /// abandoned attempt can never poison a later one. After the handshake
    /// the pump re-keys the peer entry to the announced fabric name.
    pub async fn dial(self: &Arc<Self>, peer: &str) -> tokio::io::DuplexStream {
        // Unique WIRE id (not a host name): both directions of this virtual
        // socket address frames to the same id, so a redial gets a fresh,
        // isolated wire and stale handshake frames can never poison a
        // later attempt.
        let tag = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let wire_key = format!("{}>{}#{}", self.name, peer, tag);
        let (user, wire) = tokio::io::duplex(1 << 20);
        let (in_tx, in_rx) = mpsc::channel::<RawFrame>(256);
        // Register the feeder BEFORE returning, so an inbound ServerHello
        // that outraces this call is not dropped.
        self.inbound
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(wire_key.clone(), in_tx);

        // Far end of the wire: split into our two directions.
        let (wire_rd, mut wire_wr) = tokio::io::split(wire);

        // Inbound pump: bus frames → wire (the user end reads them).
        tokio::spawn(async move {
            let mut in_rx = in_rx;
            while let Some(raw) = in_rx.recv().await {
                if wire_wr.write_all(&raw).await.is_err() {
                    break;
                }
            }
        });

        // Outbound pump: user's sealed frames → bus outbox. We never close
        // the user end ourselves in a demo lifetime, so read until error.
        let node = Arc::downgrade(self);
        let peer_owned = wire_key;
        tokio::spawn(async move {
            let mut rd = wire_rd;
            loop {
                let mut lenbuf = [0u8; 4];
                if rd.read_exact(&mut lenbuf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(lenbuf) as usize;
                let mut body = vec![0u8; len];
                if rd.read_exact(&mut body).await.is_err() {
                    break;
                }
                let mut raw = lenbuf.to_vec();
                raw.extend_from_slice(&body);
                if let Some(n) = node.upgrade() {
                    n.queue(&peer_owned, raw);
                } else {
                    break;
                }
            }
        });

        user
    }

    /// Post one comment now (used for receipts / out-of-band notices).
    pub async fn post(&self, body: String) -> Result<(), FabricError> {
        let repo = self.cfg.repo.clone();
        let issue = self.cfg.issue;
        let token = self.cfg.token();
        tokio::task::spawn_blocking(move || api_post(&repo, issue, &token, &body))
            .await
            .map_err(|e| FabricError::Codec(format!("bus post join: {e}")))?
            .map_err(FabricError::Codec)
            .map(|_| ())
    }

    /// One flush+fetch cycle. Returns when done; call in a loop.
    pub async fn tick(self: &Arc<Self>) {
        self.flush().await;
        self.fetch().await;
    }

    /// Fetch every comment body currently on the bus (any marker). Used by
    /// the receipt verifier — receipts are SIGNED plaintext, deliberately
    /// readable by the aggregator without a sealed link.
    pub async fn fetch_comment_bodies(&self) -> Vec<String> {
        let repo = self.cfg.repo.clone();
        let issue = self.cfg.issue;
        let token = self.cfg.token();
        let pages = tokio::task::spawn_blocking(move || {
            let mut all = Vec::new();
            for page in 1..=5u64 {
                match api_get(&repo, issue, &token, page) {
                    Ok(mut c) => {
                        let done = c.len() < 100;
                        all.append(&mut c);
                        if done {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            all
        })
        .await
        .unwrap_or_default();
        pages
            .iter()
            .filter_map(|c| c["body"].as_str().map(String::from))
            .collect()
    }

    async fn flush(&self) {
        let batches: Vec<(String, Vec<RawFrame>)> = {
            let mut ob = self.outboxes.lock().unwrap_or_else(|p| p.into_inner());
            ob.drain().collect()
        };
        for (dest, frames) in batches {
            if frames.is_empty() {
                continue;
            }
            // Chunk the batch so each comment stays under the body cap.
            let mut chunk: Vec<RawFrame> = Vec::new();
            let mut size = 0usize;
            let flush_chunk = |chunk: &mut Vec<RawFrame>| {
                let bytes: Vec<u8> = chunk.concat();
                let body = format!(
                    "{MARKER} {}",
                    serde_json::json!({
                        "v": 1, "from": self.name, "to": dest,
                        "frames": B64.encode(&bytes)
                    })
                );
                // `dest` here is a WIRE key; the receiving side matches its
                // feeder table by that key (see fetch / deliver_inbound).
                let repo = self.cfg.repo.clone();
                let issue = self.cfg.issue;
                let token = self.cfg.token();
                let body = body.clone();
                tokio::task::spawn_blocking(move || api_post(&repo, issue, &token, &body))
            };
            for f in frames {
                let flen = f.len();
                if size + flen > MAX_BODY && !chunk.is_empty() {
                    let _ = flush_chunk(&mut chunk).await;
                    size = 0;
                }
                size += flen;
                chunk.push(f);
            }
            if !chunk.is_empty() {
                let _ = flush_chunk(&mut chunk).await;
            }
        }
    }

    async fn fetch(self: &Arc<Self>) {
        let repo = self.cfg.repo.clone();
        let issue = self.cfg.issue;
        let token = self.cfg.token();
        let since = self.last_comment.load(Ordering::SeqCst);
        let pages = tokio::task::spawn_blocking(move || {
            let mut all = Vec::new();
            for page in 1..=5u64 {
                match api_get(&repo, issue, &token, page) {
                    Ok(mut c) => {
                        let done = c.len() < 100;
                        all.append(&mut c);
                        if done {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            all
        })
        .await
        .unwrap_or_default();

        let mut max_seen = since;
        for c in pages {
            let id = c["id"].as_i64().unwrap_or(0);
            if id <= since {
                continue;
            }
            max_seen = max_seen.max(id);
            let body = c["body"].as_str().unwrap_or("");
            let Some(json_part) = body.strip_prefix(MARKER) else {
                continue; // not ours (humans/CI may comment on the issue)
            };
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(json_part.trim()) else {
                continue;
            };
            let from = msg["from"].as_str().unwrap_or("").to_string();
            let to = msg["to"].as_str().unwrap_or("").to_string();
            // `to` is a WIRE key we registered when we opened (or accepted)
            // that virtual socket. Unknown keys are not ours. And our own
            // flushes come back to us here too — never feed those into a
            // wire or the initiator would read back its own ClientHello.
            if from.is_empty() || to.is_empty() || from == self.name {
                continue;
            }
            let Ok(bytes) = B64.decode(msg["frames"].as_str().unwrap_or("")) else {
                tracing::warn!(from = %from, "bus: undecodable frame batch");
                continue;
            };
            let Ok(frames) = split_frames(&bytes) else {
                tracing::warn!(from = %from, "bus: malformed frame batch");
                continue;
            };
            for raw in frames {
                self.deliver_inbound(&to, &from, raw).await;
            }
        }
        self.last_comment.store(max_seen, Ordering::SeqCst);
    }

    async fn deliver_inbound(self: &Arc<Self>, wire_key: &str, from: &str, raw: RawFrame) {
        let existing = {
            self.inbound
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(wire_key)
                .cloned()
        };
        if let Some(tx) = existing {
            let _ = tx.send(raw).await;
            return;
        }
        // Not a wire we opened. Accept it ONLY if it is a wire the remote
        // dialed TO us — dial wires are named "{dialer}>{receiver}#tag".
        // Anything else (a third party's wire we merely overheard on the
        // shared bus) must be ignored, or every node would answer every
        // handshake it sees.
        let mine = format!("{}>{}#", from, self.name);
        if !wire_key.starts_with(&mine) {
            return;
        }
        // The REMOTE dialed us: build the accept-side wire.
        // Build the accept-side wire: feeder → duplex (their frames), and
        // duplex → outbox under the SAME wire key (our replies). This
        // outbound direction is the responder's half of the socket.
        let (user, wire) = tokio::io::duplex(1 << 20);
        let (in_tx, in_rx) = mpsc::channel::<RawFrame>(256);
        self.inbound
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(wire_key.to_string(), in_tx.clone());
        let (mut wire_rd, mut wire_wr) = tokio::io::split(wire);
        // inbound pump: bus frames → duplex
        tokio::spawn(async move {
            let mut in_rx = in_rx;
            while let Some(raw) = in_rx.recv().await {
                if wire_wr.write_all(&raw).await.is_err() {
                    break;
                }
            }
        });
        // outbound pump: responder's sealed frames → bus (queued under the
        // same wire key so the initiator's feeder receives them)
        let node = Arc::downgrade(self);
        let key = wire_key.to_string();
        tokio::spawn(async move {
            loop {
                let mut lenbuf = [0u8; 4];
                if wire_rd.read_exact(&mut lenbuf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(lenbuf) as usize;
                let mut body = vec![0u8; len];
                if wire_rd.read_exact(&mut body).await.is_err() {
                    break;
                }
                let mut framed = lenbuf.to_vec();
                framed.extend_from_slice(&body);
                if let Some(n) = node.upgrade() {
                    n.queue(&key, framed);
                } else {
                    break;
                }
            }
        });
        let _ = in_tx.send(raw).await;
        let _ = self.accepts.send((from.to_string(), user)).await;
    }

    /// The polling agent loop. Stop with [`BusNode::stop`].
    pub async fn run(self: Arc<Self>) {
        let poll = Duration::from_millis(self.cfg.poll_ms.max(500));
        while !self.stop.load(Ordering::SeqCst) {
            self.tick().await;
            tokio::time::sleep(poll).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Link establishment over the bus
// ---------------------------------------------------------------------------

/// Dial `peer` over the bus and run the SIEVE1 initiator + hello + pump.
pub async fn connect_over_bus(
    node: &Arc<BusNode>,
    fabric: &crate::router::Fabric,
    peer: &str,
    link: &crate::net::LinkConfig,
) -> Result<(), FabricError> {
    let user = node.dial(peer).await;
    let (rd, wr) = tokio::io::split(user);
    crate::net::establish_outbound(fabric, rd, wr, peer, link).await
}

/// Consume inbound wires until the accept channel closes: run the SIEVE1
/// responder + hello + pump on each.
pub fn serve_over_bus(
    node: Arc<BusNode>,
    fabric: crate::router::Fabric,
    link: crate::net::LinkConfig,
    mut accepts: mpsc::Receiver<(String, tokio::io::DuplexStream)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((from, user)) = accepts.recv().await {
            let task_fabric = fabric.clone();
            let task_link = link.clone();
            let h = tokio::spawn(async move {
                let (rd, wr) = tokio::io::split(user);
                let _ = crate::net::establish_inbound(task_fabric, rd, wr, task_link, from).await;
            });
            fabric.track_link(h);
        }
        let _ = node; // keep the node alive as long as we serve
    })
}
