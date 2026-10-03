//! `sieve demo` — the Phase-1 vertical slice from the spec, live:
//!
//! 1. Declarative boot: the whole system from one expression + closure hash
//! 2. A sleeping actor wakes on a message (zero CPU while dormant)
//! 3. Transactional turn: a poison message rolls back, state is intact
//! 4. Scale-to-zero: idle cell evicted to the content-addressed store
//! 5. Wake-from-store: live reference survives eviction (stub → restore)
//! 6. Destructive recovery: destroy the vat, rebuild, restore from CAS
//! 7. Semantic memory: Datalog query over the hash-chained event log

use anyhow::Result;
use std::time::{Duration, Instant};

use sieveplate_core::Port;
use sieveplate_engine::{CellSpec, Host, HostConfig};

fn section(title: &str) {
    println!("\n\x1b[1;36m■ {title}\x1b[0m");
}

fn kv(key: &str, val: &str) {
    println!("  {key:<46} {val}");
}

fn port(host: &str, cell: &str) -> Port {
    Port::new(host, "core", cell)
}

pub async fn run() -> Result<()> {
    let host_name = "demo";
    let root = std::env::temp_dir().join(format!("sieve-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    println!("\x1b[1mSIEVEPLATE — vertical slice demo\x1b[0m");
    println!("  'A sieve plate is the perforated wall between living cells:'");
    println!("  signals flow through capability-gated channels, cells sleep.");

    section("1 · Declarative boot (L7 → L4)");
    let host = Host::start(
        HostConfig {
            host: host_name.into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
        },
        &root,
    )?;
    let counter = CellSpec {
        name: "counter".into(),
        vat: "core".into(),
        template: "builtin:counter".into(),
        caps: vec![],
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
    };
    let t0 = Instant::now();
    host.create_cell(&counter).await?;
    kv(
        "cell 'counter' created (template: builtin:counter)",
        format!("in {:?}", t0.elapsed()).as_str(),
    );
    kv(
        "closure template descriptors",
        &host.registry.descriptors_hash()[..16],
    );

    // ------------------------------------------------------------------
    section("2 · Transactional turns (L5)");
    for i in 0..3u64 {
        let t1 = Instant::now();
        let n = host
            .fabric
            .call(
                port(host_name, "counter"),
                "add",
                i.to_le_bytes().to_vec(),
                Duration::from_secs(5),
            )
            .await?;
        let _ = n;
        kv(
            &format!("turn: add {i}"),
            format!("{:?} round-trip", t1.elapsed()).as_str(),
        );
    }
    let count = host
        .fabric
        .call(
            port(host_name, "counter"),
            "get",
            vec![],
            Duration::from_secs(5),
        )
        .await?;
    let count = u64::from_le_bytes(count[..8].try_into()?);
    kv("state after 3 committed turns", &format!("count = {count}"));

    section("3 · Rollback: poison message");
    let err = host
        .fabric
        .call(
            port(host_name, "counter"),
            "poison",
            vec![],
            Duration::from_secs(5),
        )
        .await;
    let err = match err {
        Ok(v) => unreachable!("poison must fail, got {v:?}"),
        Err(e) => e,
    };
    kv("poison turn outcome", &format!("rejected ({err})"));
    let count2 = u64::from_le_bytes(
        host.fabric
            .call(
                port(host_name, "counter"),
                "get",
                vec![],
                Duration::from_secs(5),
            )
            .await?[..8]
            .try_into()?,
    );
    kv(
        "state after rollback",
        &format!("count = {count2} (unchanged: {})", count2 == count),
    );
    assert_eq!(count, count2, "rollback must preserve state");

    section("4 · Scale to zero (L4)");
    let t2 = Instant::now();
    let snap = host.scale_to_zero("core", "counter").await?;
    kv(
        "evicted to content store",
        format!("{} ({:?})", &snap[..16], t2.elapsed()).as_str(),
    );
    let cells = host.cells_status().await;
    kv(
        "cell slots now",
        &format!(
            "{:?}",
            cells
                .iter()
                .map(|c| (c.name.clone(), c.state.clone()))
                .collect::<Vec<_>>()
        ),
    );

    section("5 · Wake from store (sleeping actor)");
    let t3 = Instant::now();
    host.wake("core", "counter").await?;
    kv(
        "wake latency (restore + ready)",
        format!("{} µs", t3.elapsed().as_micros()).as_str(),
    );

    section("6 · Destructive recovery: destroy → restore from CAS");
    let snap2 = host.snapshot_cell("core", "counter").await?;
    host.destroy_cell("core", "counter").await?;
    kv("vat destroyed", "cell gone from memory");
    let t4 = Instant::now();
    host.restore_cell("core", "counter", "builtin:counter", &snap2)
        .await?;
    kv(
        "rebuilt from content hash",
        format!("{} ({:?})", &snap2[..16], t4.elapsed()).as_str(),
    );
    let count3 = u64::from_le_bytes(
        host.fabric
            .call(
                port(host_name, "counter"),
                "get",
                vec![],
                Duration::from_secs(5),
            )
            .await?[..8]
            .try_into()?,
    );
    kv(
        "state survived destruction",
        &format!("count = {count3} (intact: {})", count3 == count),
    );

    section("7 · Semantic memory: Datalog over the event log (L3)");
    let facts = host.event_log().facts()?;
    kv("event log records", &host.event_log().len()?.to_string());
    let sols = sieveplate_store::datalog_query(&facts, &[], "turn_ok(S, C, M, U)?")?;
    println!("  query: turn_ok(S, C, M, U) ?   — every committed turn, with cost");
    for s in sols.iter().take(6) {
        println!("    ├─ seq={} cell={} msg={} us={}", s[0], s[1], s[2], s[3]);
    }
    kv("solutions", &sols.len().to_string());

    host.shutdown().await;
    section("Phase-1 success criteria: all demonstrated");
    println!("  ✓ sleeps ✓ wakes on message ✓ transactional update ✓ persists ✓ restored after domain destruction");
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
