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
use crate::identity::{HostIdentity, KnownPeers, RotationStatement};
use crate::router::{Fabric, PeerTx};
use crate::secure;
use sieveplate_core::{Envelope, Port, Route};

const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Link security configuration: who we are, who we trust, and (after a
/// key rotation) the rotation statement we present to stale peers.
#[derive(Clone)]
pub struct LinkConfig {
    pub identity: HostIdentity,
    pub peers: Arc<KnownPeers>,
    /// Present when this host has rotated (ADR-0007): peers still pinning
    /// old keys verify the statement and re-pin during the handshake.
    pub rotation: Option<RotationStatement>,
}

impl LinkConfig {
    pub fn new(identity: HostIdentity, peers: Arc<KnownPeers>) -> Self {
        LinkConfig {
            identity,
            peers,
            rotation: None,
        }
    }

    /// Open the standard fabric directory layout:
    /// identity + latest rotation statement + known peers.
    pub fn open(dir: &std::path::Path, host: &str) -> Result<Self, FabricError> {
        let identity = HostIdentity::load_or_create(dir, host)?;
        let rotation = HostIdentity::latest_rotation(dir)
            .filter(|stmt| stmt.core.new_generation == identity.generation);
        let peers = Arc::new(KnownPeers::open(dir.join("known_peers.json"))?);
        Ok(LinkConfig {
            identity,
            peers,
            rotation,
        })
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

/// Sealed-frame pump shared by inbound and outbound links.
///
/// Peers are keyed by their FABRIC host name (the name routes are
/// announced under), which arrives in the first `__hello` frame. Until
/// hello arrives the link is attached under `attach_now` (the handshake
/// identity name / caller alias); when hello names a different fabric
/// host the entry is moved. On ANY teardown the final name is used for
/// crash detection, so route withdrawal hits the right entry.
async fn pump(
    fabric: Fabric,
    mut rd: tokio::net::tcp::OwnedReadHalf,
    mut sec_rx: secure::SecureRx,
    tx: PeerTx,
    attach_now: String,
) {
    fabric.attach_peer(&attach_now, tx.clone());
    let mut peer_name = attach_now;
    let mut raw = [0u8; 4];
    loop {
        let read_res = async {
            rd.read_exact(&mut raw).await?;
            let len = u32::from_be_bytes(raw) as usize;
            if len > MAX_FRAME as usize {
                return Err(FabricError::Codec(format!("sealed frame too large: {len}")));
            }
            let mut sealed = vec![0u8; len];
            rd.read_exact(&mut sealed).await?;
            sec_rx.open(&sealed)
        }
        .await;
        let plain = match read_res {
            Ok(p) => p,
            Err(_) => break, // EOF/IO error: link down
        };
        match unframe(&plain) {
            Ok(Some((env, _))) => {
                if env.kind == "__hello" {
                    // The remote's FABRIC name — routes are announced under
                    // it. Re-key the peer entry when it differs from the
                    // provisional attach name.
                    if let Ok(name) = String::from_utf8(env.payload) {
                        if !name.is_empty() && name != peer_name {
                            fabric.drop_peer(&peer_name);
                            fabric.attach_peer(&name, tx.clone());
                            peer_name = name;
                        }
                    }
                    continue;
                }
                if env.kind == crate::router::KIND_ROUTES {
                    match serde_json::from_slice::<crate::mesh::RouteAnnounce>(&env.payload) {
                        Ok(ann) => fabric.mesh_receive(&ann),
                        Err(e) => tracing::warn!(
                            error = %e,
                            peer = %peer_name,
                            "bad route announcement"
                        ),
                    }
                    continue;
                }
                if let Err(e) = fabric.deliver(env).await {
                    tracing::warn!(
                        error = %e,
                        peer = %peer_name,
                        "inbound envelope delivery failed"
                    );
                }
            }
            Ok(None) => {
                // Clean EOF or protocol error: same treatment either way.
            }
            Err(e) => {
                // Replay/tamper: kill the link rather than risk state.
                tracing::warn!(error = %e, peer = %peer_name, "sealed frame rejected; closing link");
            }
        }
    }
    // Link down (EOF/tamper/error): treat as peer crash under the name the
    // rest of the mesh knows us to route by.
    fabric.peer_disconnected(&peer_name);
}

/// Inbound: SIEVE1 responder handshake, then hello + sealed frame pump.
async fn inbound(
    fabric: Fabric,
    stream: TcpStream,
    link: LinkConfig,
    peer_addr: String,
) -> Result<(), FabricError> {
    let (mut rd, mut wr) = stream.into_split();
    let channel = secure::responder(
        &mut rd,
        &mut wr,
        &link.identity,
        &link.peers,
        link.rotation.as_ref(),
    )
    .await?;
    let id_host = channel.peer.host.clone(); // authenticator name (pinning)
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer_task = spawn_writer(wr, rx, channel.tx);
    fabric.track_link(writer_task);
    tracing::info!(peer = %id_host, addr = %peer_addr, "secure link established (inbound)");

    // Announce ourselves INSIDE the encrypted channel (fabric name).
    let hello = Envelope::new(
        Port::new("", "", ""),
        "__hello",
        fabric.host().to_string().into_bytes(),
    );
    let _ = tx.send(frame(&hello)?).await;

    pump(fabric, rd, channel.rx, tx, id_host).await;
    Ok(())
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
    let channel = secure::initiator(
        &mut rd,
        &mut wr,
        &link.identity,
        &link.peers,
        &alias,
        link.rotation.as_ref(),
    )
    .await?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer_task = spawn_writer(wr, rx, channel.tx);
    fabric.track_link(writer_task);
    tracing::info!(peer = %alias, "secure link established (outbound)");

    // Announce ourselves INSIDE the encrypted channel (fabric name). The
    // pump attaches the link under the remote's announced fabric name.
    let hello = Envelope::new(
        Port::new("", "", ""),
        "__hello",
        fabric.host().to_string().into_bytes(),
    );
    let _ = tx.send(frame(&hello)?).await;

    // Attach synchronously (alias) so callers can send immediately; the
    // pump re-keys the entry to the remote's announced fabric name.
    fabric.attach_peer(&alias, tx.clone());
    let reader = tokio::spawn(pump(fabric.clone(), rd, channel.rx, tx, alias));
    fabric.track_link(reader);
    Ok(())
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
