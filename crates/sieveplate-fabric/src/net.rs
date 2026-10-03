//! Secure framed TCP transport — Phase 4 multi-host + hardening.
//!
//! Every TCP link runs the SIEVE1 handshake first (see [`crate::secure`]):
//! both hosts prove identity with hybrid Ed25519+ML-DSA signatures, and all
//! subsequent frames are sealed with ChaCha20-Poly1305 under per-direction
//! sequence numbers (replay/reorder rejected). The wire format per frame:
//! `u32 big-endian length | sealed ciphertext (payload + 16-byte tag)`.
//!
//! Inside the encrypted channel, frames carry length-prefixed bincode
//! [`Envelope`]s (the same `frame()`/`unframe()` codec as before). The
//! first inner envelope on an inbound link is the `__hello` handshake
//! naming the sender's host, so both sides learn how to route replies.
//!
//! The old plaintext transport is gone: encryption is on by default, not a
//! feature flag (ADR-0004). Host identities live in
//! `<runtime>/fabric/identity.json`, pinned peers in `known_peers.json`.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::error::FabricError;
use crate::identity::{HostIdentity, KnownPeers};
use crate::router::Fabric;
use crate::secure;
use sieveplate_core::{Envelope, Port, Route};

const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Link security configuration: who we are and who we trust.
#[derive(Clone)]
pub struct LinkConfig {
    pub identity: HostIdentity,
    pub peers: Arc<KnownPeers>,
}

impl LinkConfig {
    pub fn new(identity: HostIdentity, peers: Arc<KnownPeers>) -> Self {
        LinkConfig { identity, peers }
    }
}

/// Serialize an envelope into a length-prefixed frame (the *plaintext*
/// payload carried inside a sealed channel frame).
pub fn frame(env: &Envelope) -> Result<Vec<u8>, FabricError> {
    let body = bincode::serialize(env).map_err(|e| FabricError::Codec(e.to_string()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse one plaintext frame from the buffer; returns (envelope, bytes consumed).
pub fn unframe(buf: &[u8]) -> Result<Option<(Envelope, usize)>, FabricError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME as usize {
        return Err(FabricError::Codec(format!("frame too large: {len}")));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let env: Envelope =
        bincode::deserialize(&buf[4..4 + len]).map_err(|e| FabricError::Codec(e.to_string()))?;
    Ok(Some((env, 4 + len)))
}

/// Run the accept loop for this host. Every inbound connection performs a
/// SIEVE1 handshake before a single envelope flows.
pub async fn serve(fabric: Fabric, addr: &str, link: LinkConfig) -> Result<Network, FabricError> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    fabric.track_listener(tokio::spawn(async move {}));
    let net_fabric = fabric.clone();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let accepted_fabric = fabric.clone();
                    let fabric = fabric.clone();
                    let link = link.clone();
                    let t = tokio::spawn(async move {
                        if let Err(e) = inbound(fabric, stream, link, peer_addr.to_string()).await {
                            tracing::debug!(error = %e, "inbound connection closed");
                        }
                    });
                    accepted_fabric.track_link(t);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    break;
                }
            }
        }
    });
    Ok(Network {
        handle: task,
        local_addr,
        fabric: net_fabric,
    })
}

/// Handle to a running listener.
pub struct Network {
    handle: tokio::task::JoinHandle<()>,
    fabric: Fabric,
    /// The bound address (useful with port :0 in tests).
    pub local_addr: std::net::SocketAddr,
}

impl Network {
    /// Stop accepting AND tear down every established link (sockets close;
    /// the far end sees EOF and runs its crash detection).
    pub fn shutdown(&self) {
        self.handle.abort();
        self.fabric.crash_links();
    }
}

/// Inbound: SIEVE1 responder handshake, then hello + sealed frame pump.
async fn inbound(
    fabric: Fabric,
    stream: TcpStream,
    link: LinkConfig,
    peer_addr: String,
) -> Result<(), FabricError> {
    let (mut rd, mut wr) = stream.into_split();
    let channel = secure::responder(&mut rd, &mut wr, &link.identity, &link.peers).await?;
    let peer_host = channel.peer.host.clone();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer_task = spawn_writer(wr, rx, channel.tx);
    fabric.track_link(writer_task);
    fabric.attach_peer(&peer_host, tx);
    tracing::info!(peer = %peer_host, addr = %peer_addr, "secure link established (inbound)");

    // Pump sealed frames until EOF. ANY teardown (clean EOF, tamper,
    // error) counts as a peer crash: in-flight calls fail fast.
    let mut sec_rx = channel.rx;
    let mut raw = [0u8; 4];
    let result = loop {
        let read_res = async {
            rd.read_exact(&mut raw).await?;
            let len = u32::from_be_bytes(raw) as usize;
            if len > MAX_FRAME as usize {
                return Err(FabricError::Codec(format!("sealed frame too large: {len}")));
            }
            let mut sealed = vec![0u8; len];
            rd.read_exact(&mut sealed).await?;
            let plain = sec_rx.open(&sealed)?;
            Ok(plain)
        }
        .await;
        match read_res {
            Ok(plain) => {
                if dispatch_plain(&fabric, &plain, &peer_host).await.is_err() {
                    break Err(FabricError::Codec("dispatch failed".into()));
                }
            }
            Err(e) => break Err(e),
        }
    };
    fabric.peer_disconnected(&peer_host);
    result
}

/// Outbound: SIEVE1 initiator handshake, then attach + pump.
pub async fn connect_peer(
    fabric: &Fabric,
    alias: &str,
    addr: &str,
    link: &LinkConfig,
) -> Result<(), FabricError> {
    let alias = alias.to_string(); // owned: the reader task outlives this call
    let stream = TcpStream::connect(addr).await?;
    let (mut rd, mut wr) = stream.into_split();
    let channel = secure::initiator(&mut rd, &mut wr, &link.identity, &link.peers, &alias).await?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer_task = spawn_writer(wr, rx, channel.tx);
    fabric.track_link(writer_task);
    fabric.attach_peer(&alias, tx.clone());
    tracing::info!(peer = %alias, "secure link established (outbound)");

    // Announce ourselves INSIDE the encrypted channel (legacy hello).
    let hello = Envelope::new(
        Port::new("", "", ""),
        "__hello",
        fabric.host().to_string().into_bytes(),
    );
    let _ = tx.send(frame(&hello)?).await;

    let fabric2 = fabric.clone();
    let mut sec_rx = channel.rx;
    let reader = tokio::spawn(async move {
        let mut raw = [0u8; 4];
        loop {
            if rd.read_exact(&mut raw).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(raw) as usize;
            if len > MAX_FRAME as usize {
                tracing::warn!(len, "sealed frame too large; closing link");
                break;
            }
            let mut sealed = vec![0u8; len];
            if rd.read_exact(&mut sealed).await.is_err() {
                break;
            }
            match sec_rx.open(&sealed) {
                Ok(plain) => {
                    if dispatch_plain(&fabric2, &plain, &alias).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    // Replay/tamper: kill the link rather than risk state.
                    tracing::warn!(error = %e, "sealed frame rejected; closing link");
                    break;
                }
            }
        }
        // Link down (EOF/tamper/error): treat as peer crash.
        fabric2.peer_disconnected(&alias);
    });
    fabric.track_link(reader);
    Ok(())
}

/// Decode one inner framed envelope and hand it to the fabric.
async fn dispatch_plain(fabric: &Fabric, plain: &[u8], peer: &str) -> Result<(), FabricError> {
    match unframe(plain)? {
        Some((env, _)) => {
            if env.kind == "__hello" {
                return Ok(()); // identity already established by SIEVE1
            }
            if let Err(e) = fabric.deliver(env).await {
                tracing::warn!(error = %e, peer = %peer, "inbound envelope delivery failed");
            }
            Ok(())
        }
        None => Err(FabricError::Codec("truncated inner frame".into())),
    }
}

/// Writer half: seals payloads and writes `len | sealed` to the socket.
/// Returns the task handle (tracked by the fabric so crash teardown can
/// close the write half — otherwise an aborted reader leaves the socket
/// half-open and the far end never sees EOF).
fn spawn_writer(
    mut wr: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut sec: secure::SecureTx,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(plain) = rx.recv().await {
            let sealed = match sec.seal(&plain) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "seal failed; writer stopping");
                    break;
                }
            };
            if wr
                .write_all(&(sealed.len() as u32).to_be_bytes())
                .await
                .is_err()
            {
                break;
            }
            if wr.write_all(&sealed).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
        }
    })
}
