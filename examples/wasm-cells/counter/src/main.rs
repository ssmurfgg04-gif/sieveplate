//! The reference WASI cell: a counter compiled to `wasm32-wasip1`.
//!
//! This guest implements the **SIEVE-WASI ABI v1** (docs/wasm-abi.md):
//! it reads ONE JSON line from stdin per turn and writes JSON lines to
//! stdout. State lives in a single file, `/state/state.bin`, inside the
//! directory the runtime preopens — the only filesystem capability the
//! cell receives. Any language that can read stdin, write stdout and
//! touch one file can be a cell.
//!
//! Rebuild after editing:
//!
//! ```bash
//! cargo build --target wasm32-wasip1 --release \
//!   --manifest-path examples/wasm-cells/counter/Cargo.toml
//! cp examples/wasm-cells/counter/target/wasm32-wasip1/release/wasm_counter_cell.wasm \
//!    examples/cells/counter.wasm
//! ```

use std::fs;
use std::io::{Read, Write};

use base64::Engine as _;

const STATE_PATH: &str = "/state/state.bin";

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn emit(v: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn load_count() -> u64 {
    fs::read(STATE_PATH)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn save_count(n: u64) {
    let _ = fs::create_dir_all("/state");
    let _ = fs::write(STATE_PATH, n.to_string());
}

fn main() {
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() || line.trim().is_empty() {
        return; // nothing to do
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
        return;
    };
    match v["op"].as_str() {
        // Restore persisted state (the runtime materialized nothing yet —
        // the guest seeds its own /state file from the payload).
        Some("init") => {
            if let Some(s) = v["state_b64"].as_str() {
                let _ = fs::create_dir_all("/state");
                let _ = fs::write(STATE_PATH, b64_decode(s));
            }
        }
        Some("turn") => {
            let kind = v["kind"].as_str().unwrap_or("");
            let payload = v["payload_b64"].as_str().map(b64_decode).unwrap_or_default();
            let mut count = load_count();
            match kind {
                "add" => {
                    let inc = if payload.len() >= 8 {
                        u64::from_le_bytes(payload[..8].try_into().unwrap())
                    } else {
                        0
                    };
                    count += inc;
                    save_count(count);
                }
                "get" => {}
                "echo" => {}
                other => {
                    emit(serde_json::json!({
                        "op": "error",
                        "message": format!("unknown kind '{other}'"),
                    }));
                    return;
                }
            }
            // Resolve the caller's promise, if this turn was a call.
            if let Some(id) = v["reply_to"].as_u64() {
                let body: Vec<u8> = match kind {
                    "get" | "add" => count.to_le_bytes().to_vec(),
                    _ => payload,
                };
                emit(serde_json::json!({
                    "op": "reply",
                    "id": id,
                    "payload_b64": b64_encode(&body),
                }));
            }
        }
        _ => {
            emit(serde_json::json!({
                "op": "error",
                "message": "unknown op",
            }));
        }
    }
}
