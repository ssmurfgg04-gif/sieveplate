//! `sieve bus` — the three-host demo over a GitHub issue-comment bus.
//!
//! Three processes on three different machines (GitHub Actions runners)
//! form a cell grid where NOBODY can accept inbound connections. The bus
//! is a fresh GitHub issue; sealed SIEVE1 frames travel as addressed
//! comments. The full fabric stack — hybrid post-quantum handshake, peer
//! pinning, route announcements, TTL-guarded multi-hop forwarding — runs
//! unmodified on top of it.
//!
//! Topology (deliberately NOT a clique):
//!   alpha ── beta ── gamma     (alpha and gamma have no link)
//! so alpha → gamma traffic MUST route through beta (mesh multi-hop).
//!
//! Roles:
//!   alpha : dials beta, waits for a mesh route to gamma, writes a value
//!           into gamma's ledger cell, reads it back, then verifies the
//!           SIGNED receipts from every host and prints the verdict.
//!   beta  : dials both, relays. Posts a receipt once both links are up.
//!   gamma : dials beta, waits until the value arrives in its own ledger,
//!           posts a receipt carrying the value.
//!
//! Exit code 0 only on the role's success condition — the workflow gates
//! on that.

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer as _;
use sieveplate_core::Port;
use sieveplate_engine::{CellSpec, Host, HostConfig};
use sieveplate_fabric::bus::{BusConfig, BusNode};
use sieveplate_fabric::net::LinkConfig;

pub struct BusArgs {
    pub name: String,
    pub repo: String,
    pub issue: u64,
    /// every participant
    pub peers: Vec<String>,
    /// who I dial (topology edges from my side)
    pub links: Vec<String>,
    pub role: String,
    pub root: String,
    /// seconds the demo may run before giving up
    pub window: u64,
    pub poll_ms: u64,
    pub token: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ledger_port(host: &str) -> Port {
    Port::new(host, "core", "ledger")
}

/// Build + sign a receipt comment body (Ed25519 + ML-DSA over the message).
fn receipt_body(
    args: &BusArgs,
    identity: &sieveplate_fabric::HostIdentity,
    pass: bool,
    note: &str,
) -> String {
    let msg = format!(
        "sieveplate-receipt|{}|{}|{}|{}|{}",
        args.name,
        args.role,
        pass,
        note,
        now()
    );
    let ed_sig = identity.ed_signing().sign(msg.as_bytes()).to_bytes();
    let pq_sig = identity
        .pq_signing()
        .sign_deterministic(msg.as_bytes(), b"sieveplate-sieve1")
        .expect("pq sign")
        .encode()
        .to_vec();
    format!(
        "SIEVE-RECEIPT {}",
        json!({
            "v": 1,
            "host": args.name,
            "role": args.role,
            "pass": pass,
            "note": note,
            "msg": msg,
            "ed": B64.encode(ed_sig),
            "pq": B64.encode(pq_sig),
        })
    )
}

pub async fn run(args: BusArgs) -> Result<()> {
    let root = std::path::PathBuf::from(&args.root);
    let _ = std::fs::create_dir_all(&root);
    let deadline = Instant::now() + Duration::from_secs(args.window);

    // Identity + peers (TOFU pinning happens during the handshake itself).
    let link = LinkConfig::open(&root.join("fabric"), &args.name)?;
    let _identity = link.identity.clone();

    println!(
        "sieve bus: host={} role={} repo={} issue={} peers={:?} links={:?}",
        args.name, args.role, args.repo, args.issue, args.peers, args.links
    );

    // The grid: one vat, one persistent ledger cell.
    let host = Host::start(
        HostConfig {
            host: args.name.clone(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        &root.join("runtime"),
    )?;
    host.create_cell(&CellSpec {
        name: "ledger".into(),
        vat: "core".into(),
        template: "builtin:kv".into(),
        caps: vec![],
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: sieveplate_engine::Isolation::Thread,
        sandbox: Default::default(),
    })
    .await?;

    // The bus: agent + accept loop.
    let (accept_tx, accept_rx) = tokio::sync::mpsc::channel::<(String, tokio::io::DuplexStream)>(64);
    let node = BusNode::new(
        args.name.clone(),
        BusConfig {
            repo: args.repo.clone(),
            issue: args.issue,
            token: args.token.clone(),
            poll_ms: args.poll_ms,
        },
        accept_tx,
    );
    let _agent = tokio::spawn(sieveplate_fabric::bus::serve_over_bus(
        node.clone(),
        host.fabric.clone(),
        link.clone(),
        accept_rx,
    ));
    let agent = {
        let n = node.clone();
        tokio::spawn(async move {
            let runner = n.clone();
            let loop_task = tokio::spawn(async move { runner.run().await });
            // serve_over_bus finished only when accept_tx drops — keep both
            let _ = loop_task.await;
        })
    };
    let _ = &agent;

    // Dial my links (retry until half the window is gone).
    let mut established: Vec<String> = Vec::new();
    for peer in &args.links {
        let mut ok = false;
        while !ok && Instant::now() < deadline - Duration::from_secs(args.window / 2).min(Duration::from_secs(30)) {
            let t = Instant::now();
            let res = tokio::time::timeout(
                Duration::from_secs(60),
                sieveplate_fabric::bus::connect_over_bus(&node, &host.fabric, peer, &link),
            )
            .await;
            match res {
                Ok(Ok(())) => {
                    println!(
                        "LINK-UP me={} peer={} via=bus handshake={:.1}s",
                        args.name,
                        peer,
                        t.elapsed().as_secs_f32()
                    );
                    established.push(peer.clone());
                    ok = true;
                }
                Ok(Err(e)) => {
                    println!("LINK-RETRY me={} peer={} err={e}", args.name, peer);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(_) => {
                    println!("LINK-RETRY me={} peer={} err=timeout", args.name, peer);
                }
            }
        }
        if !ok {
            bail!("could not establish link to {peer} within the window");
        }
    }

    // Who do I forward to / expect traffic from?
    // multi-hop target = peers − myself − my direct links (alpha: gamma).
    let remote_target: Option<String> = args
        .peers
        .iter()
        .filter(|p| **p != args.name && !args.links.contains(p))
        .next()
        .cloned();

    let host = std::sync::Arc::new(host);
    let exit_code =
        run_role(args, host.clone(), node.clone(), link, remote_target, deadline).await;

    node.stop();
    host.shutdown().await;
    let _ = agent;
    std::process::exit(exit_code);
}

async fn run_role(
    args: BusArgs,
    host: std::sync::Arc<Host>,
    node: std::sync::Arc<BusNode>,
    link: LinkConfig,
    remote_target: Option<String>,
    deadline: Instant,
) -> i32 {
    let identity = link.identity.clone();

    // ---- role-specific success conditions ------------------------------
    match args.role.as_str() {
        // alpha: multi-hop write to the remote target's ledger + verify receipts
        "alpha" => {
            let Some(target) = remote_target else {
                eprintln!("alpha needs a remote target (peers − links − self)");
                return 2;
            };
            // Wait for a mesh route to the target (learned via beta).
            let mut route_hops: Option<u32> = None;
            while Instant::now() < deadline {
                if let Some(h) = host.fabric.mesh().hops(&target) {
                    route_hops = Some(h);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            let Some(hops) = route_hops else {
                println!("BUS-DEMO FAIL reason=no-route-to-{target}");
                return 3;
            };
            println!("ROUTE-FOUND me={} target={target} hops={hops}", args.name);

            // Multi-hop write + read-back.
            let value = format!("hello-from-{}-via-mesh-{}", args.name, now());
            let payload = json!({"k": "greeting", "v": value}).to_string().into_bytes();
            let put = host
                .fabric
                .call(
                    ledger_port(&target),
                    "put",
                    payload,
                    Duration::from_secs(90),
                )
                .await;
            if let Err(e) = put {
                println!("BUS-DEMO FAIL reason=put-via-mesh err={e}");
                return 4;
            }
            let got = host
                .fabric
                .call(
                    ledger_port(&target),
                    "get",
                    b"greeting".to_vec(),
                    Duration::from_secs(90),
                )
                .await;
            match got {
                Ok(v) if String::from_utf8_lossy(&v) == value => {
                    println!("BUS-DEMO PASS multi-hop {0}->{target} value={value}", args.name);
                }
                other => {
                    println!(
                        "BUS-DEMO FAIL reason=readback-mismatch got={:?}",
                        other.map(|v| String::from_utf8_lossy(&v).to_string())
                    );
                    return 5;
                }
            }

            // Verify the other hosts' signed receipts.
            let expected: Vec<String> = args
                .peers
                .iter()
                .filter(|p| **p != args.name)
                .cloned()
                .collect();
            let verified = verify_receipts(&node, &link, &expected, deadline).await;
            if verified.len() == expected.len() {
                println!(
                    "BUS-DEMO RECEIPTS-VERIFIED hosts={} (Ed25519+ML-DSA, pinned keys)",
                    expected.len() + 1
                );
                println!("BUS-DEMO ALL-GREEN topology=alpha-beta-gamma multihop=true");
                0
            } else {
                println!("BUS-DEMO FAIL reason=missing-receipts got={verified:?}");
                6
            }
        }

        // gamma: wait until the multi-hop value lands in MY ledger.
        "gamma" => {
            let mut value = String::new();
            while Instant::now() < deadline {
                let res = host
                    .fabric
                    .call(
                        ledger_port(&args.name),
                        "get",
                        b"greeting".to_vec(),
                        Duration::from_secs(5),
                    )
                    .await;
                if let Ok(v) = res {
                    value = String::from_utf8_lossy(&v).to_string();
                    if !value.is_empty() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            if value.is_empty() {
                println!("BUS-DEMO FAIL reason=never-received-greeting");
                return 7;
            }
            println!("BUS-DEMO GAMMA-RECEIVED value={value}");
            let body = receipt_body(&args, &identity, true, &format!("received {value}"));
            let _ = node.post(body).await;
            println!("BUS-DEMO GAMMA-RECEIPT-POSTED");
            0
        }

        // beta: relay; receipt once both links are established.
        "beta" => {
            // links were already established above (run() bails otherwise)
            tokio::time::sleep(Duration::from_secs(5)).await;
            let body = receipt_body(
                &args,
                &identity,
                true,
                &format!("links up: {}", args.links.join(",")),
            );
            let _ = node.post(body).await;
            println!("BUS-DEMO BETA-RECEIPT-POSTED links={:?}", args.links);
            0
        }
        other => {
            eprintln!("unknown role '{other}' (alpha|beta|gamma)");
            2
        }
    }
}

/// Poll the bus for SIEVE-RECEIPT comments and verify each signature
/// against the PINNED peer key (pinned during the SIEVE1 handshake).
async fn verify_receipts(
    node: &std::sync::Arc<BusNode>,
    link: &LinkConfig,
    expected: &[String],
    deadline: Instant,
) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    while Instant::now() < deadline && seen.len() < expected.len() {
        // Re-fetch the bus page; receipt comments carry marker SIEVE-RECEIPT.
        let bodies = node.fetch_comment_bodies().await;
        for body in bodies {
            let Some(json_part) = body.strip_prefix("SIEVE-RECEIPT") else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(json_part.trim()) else {
                continue;
            };
            let host = v["host"].as_str().unwrap_or("").to_string();
            if !expected.contains(&host) || seen.contains(&host) {
                continue;
            }
            let Some(msg) = v["msg"].as_str().map(String::from) else {
                continue;
            };
            let ed = v["ed"].as_str().and_then(|s| B64.decode(s).ok());
            let pq = v["pq"].as_str().and_then(|s| B64.decode(s).ok());
            let (Some(ed), Some(pq)) = (ed, pq) else {
                continue;
            };            let Some(record) = link.peers.get(&host) else {
                println!("RECEIPT-REJECT host={host} reason=not-pinned");
                continue;
            };
            let pubk = sieveplate_fabric::HostPublic {
                host: host.clone(),
                ed_public: record.ed_public,
                pq_vk: record.pq_vk.clone(),
            };
            match pubk.verify(msg.as_bytes(), &ed, &pq) {
                Ok(()) => {
                    println!("RECEIPT-OK host={host} note={}", v["note"].as_str().unwrap_or(""));
                    seen.push(host);
                }
                Err(e) => println!("RECEIPT-REJECT host={host} err={e}"),
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    seen.sort();
    seen
}
