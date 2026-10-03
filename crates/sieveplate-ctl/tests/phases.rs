//! Phase 2 + Phase 4: cross-cell promise pipelining and multi-host
//! transport. Phase 3: the sense → sleeping-cell wake path.

use std::time::Duration;

use sieveplate_core::Port;
use sieveplate_engine::{CellSpec, Host, HostConfig, Isolation};
use sieveplate_senses::{SensePump, Signal, SignalRoute};

fn spec(
    name: &str,
    template: &str,
    caps: Vec<sieveplate_engine::CapSpec>,
    sleep: Option<u64>,
) -> CellSpec {
    CellSpec {
        name: name.into(),
        vat: "core".into(),
        template: template.into(),
        caps,
        sleep_after_ms: sleep,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: Isolation::Thread,
        sandbox: Default::default(),
    }
}

/// Phase 2: multiple isolated cells sharing a vat, communicating via
/// promise-pipelined calls across the fabric.
#[tokio::test]
async fn phase2_pipelined_cross_cell_chain() {
    let root = std::env::temp_dir().join(format!("sp-p2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(
        HostConfig {
            host: "p2".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        &root,
    )
    .unwrap();

    host.create_cell(&spec("relay", "builtin:echo", vec![], None))
        .await
        .unwrap();
    host.create_cell(&spec("counter", "builtin:counter", vec![], None))
        .await
        .unwrap();

    // Pipelined chain: relay("pass") → counter("add"). The continuation is
    // registered BEFORE the first message is sent; the caller never blocks
    // on the first hop.
    let next = host
        .fabric
        .call_pipelined(
            Port::new("p2", "core", "relay"),
            "pass",
            7u64.to_le_bytes().to_vec(),
            Port::new("p2", "core", "counter"),
            "add",
        )
        .await
        .unwrap();
    let v = sieveplate_fabric::promise_value(host.fabric.promises(), next, Duration::from_secs(5))
        .await
        .unwrap();
    // The counter's auto-reply is its (empty) reply payload; the count
    // observable via get.
    assert_eq!(v.len(), 0);
    let c = host
        .fabric
        .call(
            Port::new("p2", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(c[..8].try_into().unwrap()), 7);

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 3: a sense signal wakes a sleeping cell (zero polling).
#[tokio::test]
async fn phase3_sense_wakes_sleeping_cell() {
    let root = std::env::temp_dir().join(format!("sp-p3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(
        HostConfig {
            host: "p3".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        &root,
    )
    .unwrap();

    // Greeter that sleeps after 100 ms of idleness.
    host.create_cell(&spec("greeter", "builtin:greeter", vec![], Some(100)))
        .await
        .unwrap();

    // Sense pump wired: sense:feed → core/greeter as "greet".
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let routes = vec![SignalRoute {
        sense_name: "feed".into(),
        target: Port::new("p3", "core", "greeter"),
        msg_kind: Some("greet".into()),
    }];
    let pump = SensePump::new(rx, std::sync::Arc::new(host.fabric.clone()), routes, None);
    let handle = tokio::spawn(pump.run());

    // Send a greeting while awake, then wait for sleep.
    tx.send(Signal {
        source: "feed".into(),
        name: "feed".into(),
        payload: b"alice".to_vec(),
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (vats, _) = host.status().await.unwrap();
    assert!(
        vats.iter()
            .any(|v| v.sleeping.iter().any(|c| c == "greeter")),
        "greeter must be asleep before the wake test"
    );

    // The signal wakes the sleeping cell.
    tx.send(Signal {
        source: "feed".into(),
        name: "feed".into(),
        payload: b"bob".to_vec(),
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let n = host
        .fabric
        .call(
            Port::new("p3", "core", "greeter"),
            "count",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 2); // alice + bob

    // Wake latency recorded by the runtime.
    let wake = host.metrics.summarize("wake_us");
    assert!(wake.is_some(), "wake latency must be recorded");

    drop(tx);
    let _ = handle.await;
    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 4: two hosts over framed TCP; a pipelined chain crosses the wire.
#[tokio::test]
async fn phase4_multi_host_tcp_pipeline() {
    let root_a = std::env::temp_dir().join(format!("sp-p4a-{}", std::process::id()));
    let root_b = std::env::temp_dir().join(format!("sp-p4b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);

    let host_a = Host::start(
        HostConfig {
            host: "node-a".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        &root_a,
    )
    .unwrap();
    let host_b = Host::start(
        HostConfig {
            host: "node-b".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        &root_b,
    )
    .unwrap();

    // node-b listens; node-a connects. Both sides use ephemeral test
    // identities with TOFU peer stores (the first connection pins).
    let mk_link = |tag: &str| {
        let dir = std::env::temp_dir().join(format!("sp-p4-link-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = sieveplate_fabric::HostIdentity::load_or_create(&dir, tag).unwrap();
        let peers = std::sync::Arc::new(
            sieveplate_fabric::KnownPeers::open(dir.join("known_peers.json")).unwrap(),
        );
        sieveplate_fabric::LinkConfig::new(identity, peers)
    };
    let link_b = mk_link("node-b");
    let net_b = sieveplate_fabric::serve(host_b.fabric.clone(), "127.0.0.1:0", link_b)
        .await
        .unwrap();
    let addr = net_b.local_addr;
    let link_a = mk_link("node-a");
    sieveplate_fabric::connect_peer(&host_a.fabric, "node-b", &addr.to_string(), &link_a)
        .await
        .unwrap();

    // Cells on both hosts.
    host_a
        .create_cell(&spec("counter", "builtin:counter", vec![], None))
        .await
        .unwrap();
    host_b
        .create_cell(&spec("relay", "builtin:echo", vec![], None))
        .await
        .unwrap();

    // Cross-host pipelined chain: A calls node-b/relay, whose reply is
    // piped into the local counter — the fabric completes the chain.
    let next = host_a
        .fabric
        .call_pipelined(
            Port::new("node-b", "core", "relay"),
            "pass",
            21u64.to_le_bytes().to_vec(),
            Port::new("node-a", "core", "counter"),
            "add",
        )
        .await
        .unwrap();
    sieveplate_fabric::promise_value(host_a.fabric.promises(), next, Duration::from_secs(5))
        .await
        .unwrap();

    let c = host_a
        .fabric
        .call(
            Port::new("node-a", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(c[..8].try_into().unwrap()), 21);

    net_b.shutdown();
    host_a.shutdown().await;
    host_b.shutdown().await;
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
}
