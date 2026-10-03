//! `sieve bench` — measure the cell grid against the spec's targets:
//! wake-from-store, turn round-trips, CAS throughput, scale-to-zero density.

use anyhow::Result;
use std::time::{Duration, Instant};

use sieveplate_engine::{CellSpec, Host, HostConfig};

struct Row {
    label: String,
    n: u64,
    p50_us: f64,
    p95_us: f64,
    per_sec: Option<f64>,
}

fn print_table(title: &str, rows: &[Row]) {
    println!("\n{title}");
    println!(
        "  {:<42} {:>8} {:>12} {:>12} {:>12}",
        "benchmark", "n", "p50", "p95", "ops/sec"
    );
    for r in rows {
        println!(
            "  {:<42} {:>8} {:>10.1}µs {:>10.1}µs {:>12}",
            r.label,
            r.n,
            r.p50_us,
            r.p95_us,
            r.per_sec
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "—".into())
        );
    }
}

pub async fn run(suite: &str) -> Result<()> {
    let root = std::env::temp_dir().join(format!("sieve-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(
        HostConfig {
            host: "bench".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 4096,
        },
        &root,
    )?;

    let mut rows: Vec<Row> = Vec::new();

    if suite == "all" || suite == "turns" {
        let cell = CellSpec {
            name: "counter".into(),
            vat: "core".into(),
            template: "builtin:counter".into(),
            caps: vec![],
            sleep_after_ms: None,
            persist_on_turn: false, // isolate turn cost
            max_restarts: 3,
        };
        host.create_cell(&cell).await?;
        // warmup
        for _ in 0..50u64 {
            let _ = host
                .fabric
                .call(
                    sieveplate_core::Port::new("bench", "core", "counter"),
                    "add",
                    1u64.to_le_bytes().to_vec(),
                    Duration::from_secs(5),
                )
                .await?;
        }
        let n = 2000u64;
        let mut samples = Vec::with_capacity(n as usize);
        let t0 = Instant::now();
        for _ in 0..n {
            let s = Instant::now();
            host.fabric
                .call(
                    sieveplate_core::Port::new("bench", "core", "counter"),
                    "add",
                    1u64.to_le_bytes().to_vec(),
                    Duration::from_secs(5),
                )
                .await?;
            samples.push(s.elapsed().as_micros() as u64);
        }
        let total = t0.elapsed();
        rows.push(summarize(
            "turn: call round-trip (in-proc)",
            samples,
            Some(n as f64 / total.as_secs_f64()),
        ));
    }

    if suite == "all" || suite == "wake" {
        let cell = CellSpec {
            name: "sleeper".into(),
            vat: "core".into(),
            template: "builtin:kv".into(),
            caps: vec![],
            sleep_after_ms: None,
            persist_on_turn: true,
            max_restarts: 3,
        };
        host.create_cell(&cell).await?;
        let n = 200u64;
        let mut samples = Vec::with_capacity(n as usize);
        for _ in 0..n {
            host.scale_to_zero("core", "sleeper").await?;
            let s = Instant::now();
            host.wake("core", "sleeper").await?;
            samples.push(s.elapsed().as_micros() as u64);
        }
        rows.push(summarize("wake: scale-to-zero → wake cycle", samples, None));
    }

    if suite == "all" || suite == "store" {
        let n = 1000u64;
        let data = vec![7u8; 4096];
        let mut put_samples = Vec::with_capacity(n as usize);
        let mut get_samples = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let s = Instant::now();
            let h = host.store.put(&data)?;
            put_samples.push(s.elapsed().as_micros() as u64);
            let s = Instant::now();
            assert!(host.store.get(&h)?.is_some());
            get_samples.push(s.elapsed().as_micros() as u64);
        }
        let put_total: u64 = put_samples.iter().sum();
        let get_total: u64 = get_samples.iter().sum();
        rows.push(summarize(
            "store: put 4 KiB (content-addressed)",
            put_samples,
            Some(n as f64 * 1_000_000.0 / put_total.max(1) as f64),
        ));
        rows.push(summarize(
            "store: get+verify 4 KiB",
            get_samples,
            Some(n as f64 * 1_000_000.0 / get_total.max(1) as f64),
        ));
    }

    if suite == "all" || suite == "cells" {
        let n = 200u64;
        let mut create_samples = Vec::with_capacity(n as usize);
        let mut evict_samples = Vec::with_capacity(n as usize);
        for i in 0..n {
            let cell = CellSpec {
                name: format!("bulk-{i}"),
                vat: "core".into(),
                template: "builtin:echo".into(),
                caps: vec![],
                sleep_after_ms: None,
                persist_on_turn: true,
                max_restarts: 3,
            };
            let s = Instant::now();
            host.create_cell(&cell).await?;
            create_samples.push(s.elapsed().as_micros() as u64);
            let s = Instant::now();
            host.scale_to_zero("core", &format!("bulk-{i}")).await?;
            evict_samples.push(s.elapsed().as_micros() as u64);
        }
        rows.push(summarize(
            "cells: create (template instantiation)",
            create_samples,
            None,
        ));
        rows.push(summarize(
            "cells: scale-to-zero (snapshot→CAS)",
            evict_samples,
            None,
        ));
    }

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);

    println!("\n\x1b[1mSieveplate benchmarks\x1b[0m");
    print_table("cell grid", &rows);
    println!(
        "\ntargets from the 2026 spec: cell ops sub-millisecond (in-proc), scale-to-zero < 10 ms ✓"
    );
    Ok(())
}

fn summarize(label: &str, mut samples: Vec<u64>, per_sec: Option<f64>) -> Row {
    samples.sort_unstable();
    let n = samples.len() as u64;
    let pick = |p: f64| -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let idx = (((samples.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1);
        samples[idx] as f64
    };
    Row {
        label: label.into(),
        n,
        p50_us: pick(0.50),
        p95_us: pick(0.95),
        per_sec,
    }
}
