//! Wasm cells (ADR-0008): Wasmtime/WASI template kind.
//!
//! The fixture module is the committed `examples/cells/counter.wasm`
//! (built from `examples/wasm-cells/counter`, a real Rust program compiled
//! to wasm32-wasip1 — see examples/wasm-cells/ for the guest source and
//! rebuild steps).

use std::time::Duration;

use sieveplate_core::Port;
use sieveplate_engine::{CapSpec, CellSpec, Host, HostConfig, Isolation};

fn wasm_module() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/cells/counter.wasm");
    format!("wasm:{}", path.canonicalize().unwrap().display())
}

fn wasm_spec(name: &str, caps: Vec<CapSpec>) -> CellSpec {
    CellSpec {
        name: name.into(),
        vat: "core".into(),
        template: wasm_module(),
        caps,
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: Isolation::Wasm,
        sandbox: Default::default(),
    }
}

fn host_cfg() -> HostConfig {
    HostConfig {
        host: "wasm-host".into(),
        vats: vec!["core".into()],
        mailbox_capacity: 1024,
        worker_exe: None,
        drain_on_shutdown: true,
    }
}

#[tokio::test]
async fn wasm_counter_turn_snapshot_scale_zero_and_wake() {
    let root = std::env::temp_dir().join(format!("sp-wasm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(host_cfg(), &root).unwrap();

    // The cell may call itself (reply routing) — minimal grant.
    host.create_cell(&wasm_spec(
        "wctr",
        vec![CapSpec {
            to: "core/wctr".into(),
            rights: vec!["send".into(), "call".into()],
        }],
    ))
    .await
    .unwrap();

    let port = Port::new("wasm-host", "core", "wctr");

    // Turn 1: add 5 — the guest reads state, mutates, persists, replies.
    host.fabric
        .call(
            port.clone(),
            "add",
            5u64.to_le_bytes().to_vec(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    // Turn 2: get — state survived the previous turn (fresh instance,
    // state re-materialized from the CAS).
    let n = host
        .fabric
        .call(port.clone(), "get", vec![], Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 5);

    // Snapshot: the state the cell persisted is in the CAS.
    let hash = host.snapshot_cell("core", "wctr").await.unwrap();
    let bytes = host.store.get(&hash).unwrap().unwrap();
    assert_eq!(bytes, b"5");

    // Scale to zero: structurally free for wasm cells (one instance per
    // turn); the persisted hash stays valid.
    let h2 = host.scale_to_zero("core", "wctr").await.unwrap();
    assert_eq!(h2, hash);

    // Wake: the kernel ping answers without invoking the guest handler.
    let wake_us = host.wake("core", "wctr").await.unwrap();
    assert!(wake_us > 0);

    // The cell still works after the wake.
    let n = host
        .fabric
        .call(
            port.clone(),
            "add",
            2u64.to_le_bytes().to_vec(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 7);

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn wasm_unknown_kind_fails_the_call_not_the_cell() {
    let root = std::env::temp_dir().join(format!("sp-wasm-err-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(host_cfg(), &root).unwrap();
    host.create_cell(&wasm_spec("werr", vec![])).await.unwrap();

    let port = Port::new("wasm-host", "core", "werr");

    // The guest reports an error for unknown kinds; the caller gets an
    // error (or empty resolution), the cell survives, and a valid turn
    // still works afterwards.
    let _ = host
        .fabric
        .call(port.clone(), "nope", vec![], Duration::from_secs(30))
        .await;
    let n = host
        .fabric
        .call(
            port.clone(),
            "add",
            9u64.to_le_bytes().to_vec(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 9);

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn wasm_thread_and_process_cells_coexist() {
    let root = std::env::temp_dir().join(format!("sp-wasm-mix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(host_cfg(), &root).unwrap();

    host.create_cell(&wasm_spec("wmix", vec![])).await.unwrap();
    host.create_cell(&CellSpec {
        name: "tmix".into(),
        vat: "core".into(),
        template: "builtin:counter".into(),
        caps: vec![],
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: Isolation::Thread,
        sandbox: Default::default(),
    })
    .await
    .unwrap();

    // Both cell kinds live in the same vat and answer through the same
    // fabric: 1 (thread) + 5 (wasm, into the thread cell) = 6.
    host.fabric
        .call(
            Port::new("wasm-host", "core", "tmix"),
            "add",
            1u64.to_le_bytes().to_vec(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    let n = host
        .fabric
        .call(
            Port::new("wasm-host", "core", "wmix"),
            "get",
            vec![],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 0);

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}
