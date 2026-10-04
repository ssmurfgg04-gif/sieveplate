//! Identity rotation over the wire (ADR-0007): a host rotates its key
//! pair, reconnects, and peers re-pin automatically — while impostors
//! without a rotation statement still fail loudly.

use std::sync::Arc;
use std::time::Duration;

use sieveplate_core::Port;
use sieveplate_engine::{CellSpec, Host, HostConfig, Isolation};
use sieveplate_fabric::{connect_peer, serve, HostIdentity, LinkConfig};

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

#[tokio::test]
async fn identity_rotation_repins_peers_and_rejects_impostors() {
    let pid = std::process::id();
    let root_a = std::env::temp_dir().join(format!("sp-rot-a-{pid}"));
    let root_b = std::env::temp_dir().join(format!("sp-rot-b-{pid}"));
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);

    let host_a = Host::start(host_cfg("rot-a"), &root_a).unwrap();
    let host_b = Host::start(host_cfg("rot-b"), &root_b).unwrap();
    // The counter lives on B; A (rotating host) drives it across the link.
    host_b
        .create_cell(&spec("counter", "builtin:counter"))
        .await
        .unwrap();

    // Standard fabric dirs: identities + peer pins persist here.
    let link_a = LinkConfig::open(&root_a.join("fabric"), "rot-a").unwrap();
    let link_b = LinkConfig::open(&root_b.join("fabric"), "rot-b").unwrap();

    // First contact: B listens, A connects. Both pin each other at gen 0.
    let net_b = serve(host_b.fabric.clone(), "127.0.0.1:0", link_b.clone())
        .await
        .unwrap();
    connect_peer(
        &host_a.fabric,
        "rot-b",
        &net_b.local_addr.to_string(),
        &link_a,
    )
    .await
    .unwrap();

    let reply = host_a
        .fabric
        .call(
            Port::new("rot-b", "core", "counter"),
            "add",
            4u64.to_le_bytes().to_vec(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    let _ = reply;
    let peers_b = Arc::clone(&link_b.peers);
    let rec0 = peers_b.get("rot-a").unwrap();
    assert_eq!(rec0.generation, 0);

    // A rotates: fresh keys (gen 1) + statement persisted in A's dir.
    let old_identity = link_a.identity.clone();
    let (new_identity, stmt) = old_identity.rotate(&root_a.join("fabric")).unwrap();
    assert_eq!(stmt.core.new_generation, 1);

    // A reconnects using the STANDARD dir loader — it picks up the new
    // identity AND the latest rotation statement automatically.
    net_b.shutdown();
    host_a.fabric.crash_links();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let link_a2 = LinkConfig::open(&root_a.join("fabric"), "rot-a").unwrap();
    assert_eq!(link_a2.identity.ed_seed_hex, new_identity.ed_seed_hex);
    assert!(
        link_a2.rotation.is_some(),
        "rotated host must carry its statement"
    );
    let net_b2 = serve(host_b.fabric.clone(), "127.0.0.1:0", link_b.clone())
        .await
        .unwrap();
    connect_peer(
        &host_a.fabric,
        "rot-b",
        &net_b2.local_addr.to_string(),
        &link_a2,
    )
    .await
    .unwrap();

    // Handshake succeeded AND B re-pinned A at generation 1.
    let rec1 = peers_b.get("rot-a").unwrap();
    assert_eq!(rec1.generation, 1, "pin must advance with the statement");
    assert_eq!(rec1.ed_public, new_identity.public().ed_public);
    assert_ne!(rec1.fingerprint, rec0.fingerprint);

    // Traffic flows over the rotated identity.
    let n = host_a
        .fabric
        .call(
            Port::new("rot-b", "core", "counter"),
            "get",
            vec![],
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(n[..8].try_into().unwrap()), 4);

    // Impostor: claims "rot-a" with fresh keys and NO statement. Loudly
    // rejected by B's pin — the handshake fails and the pin does not move.
    let impostor = HostIdentity::generate("rot-a").unwrap();
    let dir = std::env::temp_dir().join(format!("sp-rot-imp-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let impostor_peers =
        Arc::new(sieveplate_fabric::KnownPeers::open(dir.join("kp.json")).unwrap());
    let impostor_link = LinkConfig::new(impostor, impostor_peers);
    net_b2.shutdown();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let net_b3 = serve(host_b.fabric.clone(), "127.0.0.1:0", link_b.clone())
        .await
        .unwrap();
    let res = connect_peer(
        &host_a.fabric.clone(),
        "rot-b",
        &net_b3.local_addr.to_string(),
        &impostor_link,
    )
    .await;
    assert!(
        res.is_err(),
        "impostor without a rotation statement must be rejected"
    );
    assert_eq!(
        peers_b.get("rot-a").unwrap().generation,
        1,
        "pin must NOT move for an impostor without a statement"
    );

    for h in [&host_a, &host_b] {
        h.shutdown().await;
    }
    let _ = net_b3;
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
}
