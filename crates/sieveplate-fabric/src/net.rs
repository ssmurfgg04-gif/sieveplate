//! Framed TCP transport — Phase 4 multi-host.
//!
//! Wire format: 4-byte big-endian length prefix + bincode-encoded
//! [`Envelope`]. One listener per host. Connections are bidirectional:
//! the *first* frame on either direction is a `__hello` handshake naming
//! the sender's host, so both sides learn how to route replies. Receiving
//! is event-driven (async read); there is no polling anywhere.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream,
};
use tokio::sync::mpsc;

use crate::error::FabricError;
use crate::router::Fabric;
use sieveplate_core::{Envelope, Port, Route};

const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Serialize an envelope into a length-prefixed frame.
pub fn frame(env: &Envelope) -> Result<Vec<u8>, FabricError> {
    let body = bincode::serialize(env).map_err(|e| FabricError::Codec(e.to_string()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse one frame from the buffer; returns (envelope, bytes consumed).
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

/// Run the accept loop for this host. Returns a [`Network`] handle whose
/// `shutdown()` stops the listener.
pub async fn serve(fabric: Fabric, addr: &str) -> Result<Network, FabricError> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let fabric = fabric.clone();
                    tokio::spawn(async move {
                        if let Err(e) = inbound(fabric, stream).await {
                            tracing::debug!(error = %e, "inbound connection closed");
                        }
                    });
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
    })
}

/// Handle to a running listener.
pub struct Network {
    handle: tokio::task::JoinHandle<()>,
    /// The bound address (useful with port :0 in tests).
    pub local_addr: std::net::SocketAddr,
}

impl Network {
    pub fn shutdown(&self) {
        self.handle.abort();
    }
}

/// Inbound connection: read the hello handshake, register this connection
/// as a writable peer under the announced name, then pump frames.
async fn inbound(fabric: Fabric, stream: TcpStream) -> Result<(), FabricError> {
    let (mut rd, wr) = stream.into_split();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    spawn_writer(wr, rx);

    // First frame: __hello announcing the remote's host name.
    let alias = read_hello(&fabric, &mut rd).await?;
    fabric.attach_peer(&alias, tx);

    frame_loop(fabric, rd).await
}

/// Outbound connection to a peer: announce ourselves, register the peer
/// under `alias`, and pump inbound frames for the life of the connection.
pub async fn connect_peer(fabric: &Fabric, alias: &str, addr: &str) -> Result<(), FabricError> {
    let stream = TcpStream::connect(addr).await?;
    let (rd, wr) = stream.into_split();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    spawn_writer(wr, rx);

    // Handshake: announce our own host name.
    let host = fabric.host().to_string();
    let hello = Envelope::new(Port::new("", "", ""), "__hello", host.into_bytes());
    tx.send(frame(&hello)?)
        .await
        .map_err(|_| FabricError::Codec("handshake send failed".into()))?;
    fabric.attach_peer(alias, tx);

    let fabric2 = fabric.clone();
    tokio::spawn(async move {
        if let Err(e) = frame_loop(fabric2, rd).await {
            tracing::debug!(error = %e, "outbound connection closed");
        }
    });
    Ok(())
}

/// Spawn the writer half: drains the frame channel into the socket.
fn spawn_writer(mut wr: OwnedWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
        }
    });
}

/// Read the handshake frame and return the announced host name.
async fn read_hello(fabric: &Fabric, rd: &mut OwnedReadHalf) -> Result<String, FabricError> {
    let mut acc: Vec<u8> = Vec::new();
    let (env, _) = loop {
        if let Some((env, consumed)) = unframe(&acc)? {
            acc.drain(..consumed);
            break (env, consumed);
        }
        let mut chunk = [0u8; 4096];
        let n = rd.read(&mut chunk).await?;
        if n == 0 {
            return Err(FabricError::Codec(
                "connection closed during handshake".into(),
            ));
        }
        acc.extend_from_slice(&chunk[..n]);
    };
    if env.kind != "__hello" {
        return Err(FabricError::Codec("expected __hello handshake".into()));
    }
    let alias = String::from_utf8_lossy(&env.payload).to_string();
    if alias.is_empty() {
        return Err(FabricError::Codec("empty host name in handshake".into()));
    }
    let _ = fabric;
    Ok(alias)
}

/// Event-driven frame pump: read → deliver, forever.
async fn frame_loop(fabric: Fabric, mut rd: OwnedReadHalf) -> Result<(), FabricError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = rd.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some((env, consumed)) = unframe(&buf)? {
            buf.drain(..consumed);
            if env.kind == "__hello" {
                continue; // late/duplicate handshake — ignore
            }
            let f = fabric.clone();
            tokio::spawn(async move {
                if let Err(e) = f.deliver(env).await {
                    tracing::warn!(error = %e, "inbound envelope delivery failed");
                }
            });
        }
    }
}
