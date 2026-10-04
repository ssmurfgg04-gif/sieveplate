//! Mesh routing (ADR-0006): multi-hop delivery over hosts that have no
//! direct link, poison-withdrawal on peer crash, and recovery on relink.
//!
//! Topologies used:
//!
//! ```text
//! line : a ── b ── c          (a and c have NO direct link)
//! ring : a ── b ── c ── d
//!        └────────────────┘   (every host one link away from two others)
//! ```

use std::sync::Arc;
use std::time::Duration;

use sieveplate_core::Port;
use sieveplate_engine::{CellSpec, Host, HostConfig, Isolation};
use sieveplate_fabric::{connect_peer, serve, HostIdentity, KnownPeers, LinkConfig};

fn spec(name: &str, template: &str) -> CellSpec {
    CellSpec {
        name: name.into(),
        vat: "core".into(),
        template: template.into(),
        caps: vec![],
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: Isolation::Thread,
        sandbox: Default::default(),
    }
}

fn host_cfg(name: &str) -> HostConfig {
    HostConfig {
        host: name.into(),
        vats: vec!["core".into()],
        mailbox_capacity: 1024,
        worker_exe: None,
        drain_on_shutdown: true,
    }
}

fn mk_link(tag: &str) -> LinkConfig {
    // NOTE: the identity dir is NOT wiped between calls — a relinking host
    // keeps its keys (TOFU pinning on the far side must keep verifying).
    let dir = std::env::temp_dir().join(format!("sp-mesh-link-{tag}-{}", std::process::id()));
    let identity = HostIdentity::load_or_create(&dir, tag).unwrap();
    let peers = Arc::new(KnownPeers::open(dir.join("known_peers.json")).unwrap());
    LinkConfig::new(identity, peers)
}

async fn boot_host(tag: &str) -> (Host, sieveplate_fabric::Network) {
    let root = std::env::temp_dir().join(format!("sp-mesh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(host_cfg(tag), &root).unwrap();
    host.create_cell(&spec("counter", "builtin:counter"))
        .await
        .unwrap();
    host.create_cell(&spec("echo", "builtin:echo"))
        .await
        .unwrap();
    let link = mk_link(tag);
    let net = serve(host.fabric.clone(), "127.0.0.1:0", link)
        .await
        .unwrap();
    (host, net)
}

/// Wait until `from`'s table reports `dest` at the expected hop count.
async fn await_route(from: &Host, dest: &str, hops: u32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if from.fabric.mesh().hops(dest) == Some(hops) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "route to {dest} (hops={hops}) never converged on {}; table = {:?}",
            from.host,
            from.fabric.mesh().snapshot()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The line: a calls a counter that lives on c, with no a↔c link. The
/// envelope must travel a → b → c and the reply c → b → a.
#[tokio::test]
async fn mesh_line_three_hosts_multi_hop_call() {
    let (a, _na) = boot_host("mesh-a").await;
    let (b, _nb) = boot_host("mesh-b").await;
    let (c, _nc) = boot_host("mesh-c").await;

    // a ── b ── c (a is NOT connected to c).
    connect_peer(
        &a.fabric,
        "mesh-b",
        &_nb.local_addr.to_string(),
        &mk_link("a2b"),
    )
    .await
    .unwrap();
    connect_peer(
        &c.fabric,
        "mesh-b",
        &_nb.local_addr.to_string(),
        &mk_link("c2b"),
    )
    .await
    .unwrap();

    // Distance-vector convergence: a learns c at 2 hops via b (and
    // vice versa), b learns everyone at 1.
    await_route(&a, "mesh-c", 2).await;
    await_route(&c, "mesh-a", 2).await;
    await_route(&b, "mesh-a", 1).await;

    // Multi-hop call across the line, in both directions.
    let reply = a
        .fabric
        .call(
            Port::new("mesh-c", "core", "counter"),
            "add",
            5u64.to_le_bytes().to_vec(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let _ = reply;
    let n = a
        .fabric
        .call(
            Port::new("mesh-c", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 5);

    // And c → a (the echo cell on a answers through the same mesh).
    let echoed = c
        .fabric
        .call(
            Port::new("mesh-a", "core", "echo"),
            "pass",
            b"via-mesh".to_vec(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(echoed, b"via-mesh");

    // Pipelining survives the extra hop: a calls echo@c, the reply pipes
    // into counter@a — the fabric completes the chain across two links.
    let next = a
        .fabric
        .call_pipelined(
            Port::new("mesh-c", "core", "echo"),
            "pass",
            11u64.to_le_bytes().to_vec(),
            Port::new("mesh-a", "core", "counter"),
            "add",
        )
        .await
        .unwrap();
    sieveplate_fabric::promise_value(a.fabric.promises(), next, Duration::from_secs(5))
        .await
        .unwrap();

    for h in [&a, &b, &c] {
        h.shutdown().await;
    }
}

/// A relay dies mid-mesh: in-flight multi-hop calls fail FAST (never
/// hang), routes are poisoned, and after the relay returns the mesh
/// reconverges and traffic flows again.
#[tokio::test]
async fn mesh_relay_crash_fails_fast_then_recovers() {
    let (a, _na) = boot_host("mcrash-a").await;
    let (b, _nb) = boot_host("mcrash-b").await;
    let (c, _nc) = boot_host("mcrash-c").await;

    connect_peer(
        &a.fabric,
        "mcrash-b",
        &_nb.local_addr.to_string(),
        &mk_link("ca2b"),
    )
    .await
    .unwrap();
    connect_peer(
        &c.fabric,
        "mcrash-b",
        &_nb.local_addr.to_string(),
        &mk_link("cc2b"),
    )
    .await
    .unwrap();
    await_route(&a, "mcrash-c", 2).await;

    // Seed state so we can observe delivery after recovery.
    a.fabric
        .call(
            Port::new("mcrash-c", "core", "counter"),
            "add",
            3u64.to_le_bytes().to_vec(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // CRASH the relay: every link on b dies (both a and c see EOF).
    b.fabric.crash_links();

    // In-flight calls fail immediately — the promise registry resolves
    // with an error, no 5-second timeout wait.
    let started = std::time::Instant::now();
    let res = a
        .fabric
        .call(
            Port::new("mcrash-c", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(10),
        )
        .await;
    assert!(res.is_err(), "call through dead relay must fail");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "failure must be fast, took {:?}",
        started.elapsed()
    );

    // Route table on a no longer claims mcrash-c.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(a.fabric.mesh().next_hop("mcrash-c").is_none());

    // The relay comes back: relink both sides (SAME identity — a restart,
    // not a new host; pins still verify).
    let link = mk_link("mcrash-b");
    let net_b2 = serve(b.fabric.clone(), "127.0.0.1:0", link).await.unwrap();
    connect_peer(
        &a.fabric,
        "mcrash-b",
        &net_b2.local_addr.to_string(),
        &mk_link("ca2b2"),
    )
    .await
    .unwrap();
    connect_peer(
        &c.fabric,
        "mcrash-b",
        &net_b2.local_addr.to_string(),
        &mk_link("cc2b2"),
    )
    .await
    .unwrap();
    await_route(&a, "mcrash-c", 2).await;

    // Traffic flows again — and c's counter kept its state (3 from before).
    let n = a
        .fabric
        .call(
            Port::new("mcrash-c", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 3);

    for h in [&a, &b, &c] {
        h.shutdown().await;
    }
}

/// Ring with a redundant path: kill one hub and traffic reroutes the
/// long way around. Distance grows (2 → 3); delivery never stops.
#[tokio::test]
async fn mesh_ring_reroutes_around_dead_hub() {
    let (a, _na) = boot_host("ring-a").await;
    let (b, _nb) = boot_host("ring-b").await;
    let (c, _nc) = boot_host("ring-c").await;
    let (d, _nd) = boot_host("ring-d").await;

    connect_peer(
        &a.fabric,
        "ring-b",
        &_nb.local_addr.to_string(),
        &mk_link("rab"),
    )
    .await
    .unwrap();
    connect_peer(
        &b.fabric,
        "ring-c",
        &_nc.local_addr.to_string(),
        &mk_link("rbc"),
    )
    .await
    .unwrap();
    connect_peer(
        &c.fabric,
        "ring-d",
        &_nd.local_addr.to_string(),
        &mk_link("rcd"),
    )
    .await
    .unwrap();
    connect_peer(
        &d.fabric,
        "ring-a",
        &_na.local_addr.to_string(),
        &mk_link("rda"),
    )
    .await
    .unwrap();

    await_route(&a, "ring-c", 2).await;
    await_route(&c, "ring-a", 2).await;

    // Everything up: a → c works at 2 hops (via b or d).
    a.fabric
        .call(
            Port::new("ring-c", "core", "counter"),
            "add",
            1u64.to_le_bytes().to_vec(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // Kill hub b (both its links die).
    b.fabric.crash_links();

    // a must still reach c — now the long way (a → d → c), 2 hops VIA d.
    // Convergence: withdrawal of the via-b route, poison, then re-learn
    // through d's poison-response announcement.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if a.fabric.mesh().next_hop("ring-c") == Some("ring-d".into()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "ring never rerouted; a's table = {:?}",
            a.fabric.mesh().snapshot()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let n = a
        .fabric
        .call(
            Port::new("ring-c", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 1);

    for h in [&a, &b, &c, &d] {
        h.shutdown().await;
    }
}
