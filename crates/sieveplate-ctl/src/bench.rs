//! `sieve bench` — measure the cell grid against the spec's targets:
//! wake-from-store, turn round-trips, CAS throughput, scale-to-zero density.
//!
//! The `linux` suite measures STANDARD Linux primitives on the same machine
//! in the same process, so every sieveplate number has an honest baseline:
//! UDS round-trip, TCP-loopback round-trip, pipe round-trip, fork+exec,
//! and the same payload pushed through a SIEVE1 sealed channel (to isolate
//! what our cryptography adds over raw sockets).

use anyhow::Result;
use std::time::{Duration, Instant};

use sieveplate_engine::{CellSpec, Host, HostConfig};

#[derive(Clone)]
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

pub async fn run(suite: &str, json_path: Option<&str>) -> Result<()> {
    let mut all_rows: Vec<Row> = Vec::new();
    let root = std::env::temp_dir().join(format!("sieve-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let host = Host::start(
        HostConfig {
            host: "bench".into(),
            vats: vec!["core".into()],
            mailbox_capacity: 4096,
            worker_exe: None,
            drain_on_shutdown: true,
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
            isolation: sieveplate_engine::Isolation::Thread,
            sandbox: Default::default(),
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
            isolation: sieveplate_engine::Isolation::Thread,
            sandbox: Default::default(),
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
                isolation: sieveplate_engine::Isolation::Thread,
                sandbox: Default::default(),
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

    // ---- honest isolation + security benchmarks (ADR-0004/0005) ----
    // Real costs the in-process rows never measured: an OS process spawn
    // under seccomp, and a full cryptographic handshake (Ed25519 +
    // ML-DSA-65 + X25519 + ML-KEM-768 + ChaCha20-Poly1305 key schedule).
    if suite == "all" || suite == "jail" {
        let jail_root =
            std::env::temp_dir().join(format!("sieve-bench-jail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&jail_root);
        let rt = jail_root.join("rt");
        let _ = std::fs::create_dir_all(&rt);
        if let Ok(exe) = std::env::current_exe() {
            let jhost = Host::start(
                HostConfig {
                    host: "bench-jail".into(),
                    vats: vec!["core".into()],
                    mailbox_capacity: 1024,
                    worker_exe: Some(exe),
                    drain_on_shutdown: true,
                },
                &rt,
            )?;
            let n = 20u64;
            let mut spawn_samples = Vec::new();
            let mut turn_samples = Vec::new();
            for i in 0..n {
                let name = format!("pc-{i}");
                let cell = CellSpec {
                    name: name.clone(),
                    vat: "core".into(),
                    template: "builtin:counter".into(),
                    caps: vec![],
                    sleep_after_ms: None,
                    persist_on_turn: true,
                    max_restarts: 3,
                    isolation: sieveplate_engine::Isolation::Process,
                    sandbox: sieveplate_jail::SandboxPolicy::default(),
                };
                let t = Instant::now();
                jhost.create_cell(&cell).await?;
                spawn_samples.push(t.elapsed().as_micros() as u64);
                let t = Instant::now();
                let _ = jhost
                    .fabric
                    .call(
                        sieveplate_core::Port::new("bench-jail", "core", &name),
                        "get",
                        vec![],
                        Duration::from_secs(30),
                    )
                    .await?;
                turn_samples.push(t.elapsed().as_micros() as u64);
            }
            rows.push(summarize(
                "jail: process cell spawn (fork+exec+seccomp+init)",
                spawn_samples,
                None,
            ));
            rows.push(summarize(
                "jail: first turn round-trip (pipe-mediated, caps re-checked)",
                turn_samples,
                None,
            ));
            jhost.shutdown().await;
            let _ = std::fs::remove_dir_all(&jail_root);
        }
    }

    if suite == "all" || suite == "handshake" {
        let n = 50u64;
        let mut samples = Vec::new();
        for i in 0..n {
            let dir =
                std::env::temp_dir().join(format!("sieve-bench-hs-{}-{i}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let a = sieveplate_fabric::HostIdentity::generate("a")?;
            let b = sieveplate_fabric::HostIdentity::generate("b")?;
            let peers_a =
                std::sync::Arc::new(sieveplate_fabric::KnownPeers::open(dir.join("pa.json"))?);
            let peers_b =
                std::sync::Arc::new(sieveplate_fabric::KnownPeers::open(dir.join("pb.json"))?);
            let (c2s, s2c) = tokio::io::duplex(1 << 20);
            let (mut i_rd, mut i_wr) = tokio::io::split(c2s);
            let (mut r_rd, mut r_wr) = tokio::io::split(s2c);
            let t = Instant::now();
            let (ri, rr) = tokio::join!(
                sieveplate_fabric::secure::initiator(&mut i_rd, &mut i_wr, &a, &peers_a, "b", None),
                sieveplate_fabric::secure::responder(&mut r_rd, &mut r_wr, &b, &peers_b, None),
            );
            ri?;
            rr?;
            samples.push(t.elapsed().as_micros() as u64);
            let _ = std::fs::remove_dir_all(&dir);
        }
        rows.push(summarize(
            "handshake: SIEVE1 full (hybrid PQ key exchange + dual signatures)",
            samples,
            None,
        ));
    }

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);

    if suite == "all" || suite == "linux" {
        linux_suite(&mut rows).await?;
    }

    all_rows.extend(rows.iter().cloned());

    println!("\nSieveplate benchmarks");
    print_table("cell grid", &rows);
    println!("\nWhat each row MEASURES (and nothing else):");
    println!("  turns/store/cells rows = in-process actor operations; no OS boundary crossed;");
    println!("                           not comparable to VM boot or process spawn costs");
    println!("  jail rows              = REAL fork+exec+seccomp sandbox + mediated pipe");
    println!("  handshake rows         = full SIEVE1 handshake over in-memory duplex");
    println!("  linux rows             = STANDARD Linux primitives, same machine, same process");

    if suite == "all" || suite == "linux" {
        print_comparison(&rows);
    }

    if let Some(path) = json_path {
        let doc = serde_json::json!({
            "timestamp_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "hostname": std::env::var("RUNNER_NAME").unwrap_or_else(|_| whoami()),
            "suite": suite,
            "rows": all_rows.iter().map(|r| serde_json::json!({
                "label": r.label,
                "n": r.n,
                "p50_us": r.p50_us,
                "p95_us": r.p95_us,
                "ops_per_sec": r.per_sec,
            })).collect::<Vec<_>>(),
        });
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        println!("\nresults written to {path}");
    }
    Ok(())
}

fn whoami() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
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

// ---------------------------------------------------------------------------
// linux suite: standard primitives, same machine, same process
// ---------------------------------------------------------------------------

const BENCH_PAYLOAD: usize = 64; // mirrors a typical cell turn payload

async fn linux_suite(rows: &mut Vec<Row>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // --- UDS round-trip -------------------------------------------------
    let (a, b) = tokio::net::UnixStream::pair()?;
    tokio::spawn(async move {
        let mut b = b;
        let mut buf = [0u8; BENCH_PAYLOAD];
        loop {
            match b.read_exact(&mut buf).await {
                Ok(_) => {
                    if b.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let (mut a_rd, mut a_wr) = a.into_split();
    let n = 2000u64;
    let mut samples = Vec::with_capacity(n as usize);
    let payload = vec![0xABu8; BENCH_PAYLOAD];
    // warmup
    for _ in 0..100u64 {
        a_wr.write_all(&payload).await?;
        let mut buf = [0u8; BENCH_PAYLOAD];
        a_rd.read_exact(&mut buf).await?;
    }
    let t0 = Instant::now();
    for _ in 0..n {
        let s = Instant::now();
        a_wr.write_all(&payload).await?;
        let mut buf = [0u8; BENCH_PAYLOAD];
        a_rd.read_exact(&mut buf).await?;
        samples.push(s.elapsed().as_micros() as u64);
    }
    let total = t0.elapsed();
    rows.push(summarize(
        "linux: UDS round-trip (64 B)",
        samples,
        Some(n as f64 / total.as_secs_f64()),
    ));

    // --- TCP loopback round-trip ----------------------------------------
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; BENCH_PAYLOAD];
            loop {
                match sock.read_exact(&mut buf).await {
                    Ok(_) => {
                        if sock.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });
    let sock = tokio::net::TcpStream::connect(addr).await?;
    let (mut c_rd, mut c_wr) = sock.into_split();
    let mut samples = Vec::with_capacity(n as usize);
    for _ in 0..100u64 {
        c_wr.write_all(&payload).await?;
        let mut buf = [0u8; BENCH_PAYLOAD];
        c_rd.read_exact(&mut buf).await?;
    }
    let t0 = Instant::now();
    for _ in 0..n {
        let s = Instant::now();
        c_wr.write_all(&payload).await?;
        let mut buf = [0u8; BENCH_PAYLOAD];
        c_rd.read_exact(&mut buf).await?;
        samples.push(s.elapsed().as_micros() as u64);
    }
    let total = t0.elapsed();
    rows.push(summarize(
        "linux: TCP loopback round-trip (64 B)",
        samples,
        Some(n as f64 / total.as_secs_f64()),
    ));

    // --- pipe round-trip (blocking threads; the classic cheap IPC) ------
    let n_pipe = 2000u64;
    let mut samples = Vec::with_capacity(n_pipe as usize);
    for _ in 0..n_pipe {
        let (mut rd, mut wr) = os_pipe::pipe()?;
        let (mut rd2, mut wr2) = os_pipe::pipe()?;
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; BENCH_PAYLOAD];
            use std::io::{Read, Write};
            rd.read_exact(&mut buf).ok()?;
            wr2.write_all(&buf).ok()?;
            Some(())
        });
        let s = Instant::now();
        use std::io::{Read, Write};
        wr.write_all(&payload)?;
        let mut buf = [0u8; BENCH_PAYLOAD];
        rd2.read_exact(&mut buf)?;
        samples.push(s.elapsed().as_micros() as u64);
        drop(t.join());
    }
    rows.push(summarize(
        "linux: pipe round-trip (64 B, 2 pipes)",
        samples,
        None,
    ));

    // --- fork+exec /bin/true ---------------------------------------------
    let n_spawn = 50u64;
    let mut samples = Vec::new();
    for _ in 0..n_spawn {
        let s = Instant::now();
        let st = std::process::Command::new("/bin/true").status()?;
        debug_assert!(st.success());
        samples.push(s.elapsed().as_micros() as u64);
    }
    rows.push(summarize(
        "linux: fork+exec /bin/true (wait)",
        samples,
        None,
    ));

    // --- SIEVE1 sealed round-trip over UDS (what our crypto adds) --------
    let dir = std::env::temp_dir().join(format!("sieve-bench-seal-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let id_a = sieveplate_fabric::HostIdentity::generate("a")?;
    let id_b = sieveplate_fabric::HostIdentity::generate("b")?;
    let pa = std::sync::Arc::new(sieveplate_fabric::KnownPeers::open(dir.join("pa.json"))?);
    let pb = std::sync::Arc::new(sieveplate_fabric::KnownPeers::open(dir.join("pb.json"))?);
    let (sa, sb) = tokio::net::UnixStream::pair()?;
    let (mut a_rd2, mut a_wr2) = tokio::io::split(sa);
    let (mut b_rd2, mut b_wr2) = tokio::io::split(sb);
    let (ia, rb) = tokio::join!(
        sieveplate_fabric::secure::initiator(&mut a_rd2, &mut a_wr2, &id_a, &pa, "b", None),
        sieveplate_fabric::secure::responder(&mut b_rd2, &mut b_wr2, &id_b, &pb, None),
    );
    let (chan_a, mut chan_b) = (ia?, rb?);
    // Echo over the sealed channel: open, re-seal, reply.
    tokio::spawn(async move {
        loop {
            let mut hdr = [0u8; 4];
            if b_rd2.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
            if b_rd2.read_exact(&mut body).await.is_err() {
                break;
            }
            let Ok(plain) = chan_b.rx.open(&body) else {
                break;
            };
            let Ok(sealed) = chan_b.tx.seal(&plain) else {
                break;
            };
            if b_wr2
                .write_all(&(sealed.len() as u32).to_be_bytes())
                .await
                .is_err()
            {
                break;
            }
            if b_wr2.write_all(&sealed).await.is_err() {
                break;
            }
        }
    });
    let (mut tx, mut rx) = (chan_a.tx, chan_a.rx);
    async fn rt_once(
        tx: &mut sieveplate_fabric::secure::SecureTx,
        rx: &mut sieveplate_fabric::secure::SecureRx,
        wr: &mut (impl tokio::io::AsyncWrite + Unpin),
        rd: &mut (impl tokio::io::AsyncRead + Unpin),
        payload: &[u8],
    ) -> Result<()> {
        let sealed = tx.seal(payload)?;
        wr.write_all(&(sealed.len() as u32).to_be_bytes()).await?;
        wr.write_all(&sealed).await?;
        let mut hdr = [0u8; 4];
        rd.read_exact(&mut hdr).await?;
        let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
        rd.read_exact(&mut body).await?;
        let plain = rx.open(&body)?;
        debug_assert_eq!(plain.len(), BENCH_PAYLOAD);
        Ok(())
    }
    let mut samples = Vec::with_capacity(n as usize);
    for _ in 0..100u64 {
        rt_once(&mut tx, &mut rx, &mut a_wr2, &mut a_rd2, &payload).await?;
    }
    let t0 = Instant::now();
    for _ in 0..n {
        let s = Instant::now();
        rt_once(&mut tx, &mut rx, &mut a_wr2, &mut a_rd2, &payload).await?;
        samples.push(s.elapsed().as_micros() as u64);
    }
    let total = t0.elapsed();
    rows.push(summarize(
        "linux: SIEVE1 sealed round-trip (64 B)",
        samples,
        Some(n as f64 / total.as_secs_f64()),
    ));
    let _ = std::fs::remove_dir_all(&dir);

    Ok(())
}

/// Print honest side-by-side comparisons between sieveplate rows and the
/// standard-Linux rows measured in the same run.
fn print_comparison(rows: &[Row]) {
    let find = |needle: &str| -> Option<&Row> { rows.iter().find(|r| r.label.contains(needle)) };
    let pairs = [
        ("turn: call round-trip (in-proc)", "linux: pipe round-trip"),
        ("jail: process cell spawn", "linux: fork+exec"),
        ("linux: SIEVE1 sealed round-trip", "linux: UDS round-trip"),
    ];
    println!("\nsame-machine comparison (sieveplate vs standard Linux)");
    for (ours, base) in pairs {
        let (Some(a), Some(b)) = (find(ours), find(base)) else {
            continue;
        };
        let ratio = if b.p50_us > 0.0 {
            a.p50_us / b.p50_us
        } else {
            0.0
        };
        println!(
            "  {:<44} {:>10.1}µs   vs   {:<38} {:>10.1}µs   (x{ratio:.2})",
            a.label, a.p50_us, b.label, b.p50_us
        );
    }
    println!("  note: the in-proc turn is NOT OS-mediated; pipe is shown as the");
    println!("        cheapest kernel IPC for calibration, not as an equivalent.");
}
