//! Worker-protocol wire types and framing.
//!
//! The parent and the jailed worker exchange bincode frames over the
//! worker's stdin/stdout: `u32 big-endian length | bincode message`. The
//! channel is *mediated*: every envelope a worker emits flows through the
//! parent, which re-checks capabilities before routing — the worker has no
//! sockets, no files, no fork; its only I/O capability is this pipe.

use serde::{Deserialize, Serialize};
use sieveplate_core::{Continuation, Envelope};

pub const MAX_FRAME: u32 = 32 * 1024 * 1024;

/// Parent → Worker.
#[derive(Debug, Serialize, Deserialize)]
pub enum ParentToWorker {
    /// Instantiate the template (optionally restoring persisted state).
    Init {
        template: String,
        restore_state: Option<Vec<u8>>,
        caps: Vec<sieveplate_core::Cap>,
    },
    /// Deliver an envelope to the cell (or resolve a local promise when
    /// it is a `__reply`).
    Envelope(Envelope),
    /// Register a pipelined continuation (from `ctx.pipe`).
    Pipe { pid: u64, cont: Continuation },
    /// Ask the worker to serialize its state.
    SnapshotReq { req_id: u64 },
    /// Kernel-level wake probe (no handler invocation).
    Ping,
    /// Flush and exit cleanly.
    Shutdown,
}

/// Worker → Parent.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerToParent {
    /// Cell instantiated and ready to receive.
    Ready,
    /// An envelope produced by the cell (sends, calls, replies).
    Envelope(Envelope),
    /// Register a pipelined continuation with the parent's fabric.
    Pipe { pid: u64, cont: Continuation },
    /// State serialized (response to SnapshotReq).
    Snapshot { req_id: u64, state: Vec<u8> },
    /// State persisted after a committed turn (persist_on_turn).
    Persist { state: Vec<u8> },
    /// The turn failed (error or panic); state was rolled back.
    Fault { reason: String },
    /// Response to Ping.
    Pong,
}

/// Serialize + frame a message.
pub fn send_frame<W: std::io::Write + ?Sized, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> std::io::Result<()> {
    let body = bincode::serialize(msg).map_err(std::io::Error::other)?;
    if body.len() > MAX_FRAME as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read + deserialize one frame. `Ok(None)` = clean EOF.
pub fn recv_frame<R: std::io::Read + ?Sized, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> std::io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    let n = r.read(&mut len_buf)?;
    if n == 0 {
        return Ok(None); // EOF
    }
    if n < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated length",
        ));
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    bincode::deserialize(&body)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieveplate_core::Port;

    #[test]
    fn frames_roundtrip() {
        let env = Envelope::new(Port::new("h", "v", "c"), "add", vec![1, 2, 3]);
        let msg = ParentToWorker::Envelope(env);
        let mut buf = Vec::new();
        send_frame(&mut buf, &msg).unwrap();
        let back: ParentToWorker = recv_frame(&mut buf.as_slice()).unwrap().unwrap();
        match back {
            ParentToWorker::Envelope(e) => assert_eq!(e.kind, "add"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn eof_is_none() {
        let empty: &[u8] = &[];
        let mut cur: &[u8] = empty;
        let r: Option<ParentToWorker> = recv_frame(&mut cur).unwrap();
        assert!(r.is_none());
    }
}
