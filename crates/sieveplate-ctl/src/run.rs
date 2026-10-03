//! `sieve run` / `apply` / `plan` / `rollback` / `status`.
//!
//! `run` = apply + execute: boot the declarative system, wire senses and
//! routes, serve the network (if configured), until Ctrl-C.

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;

use sieveplate_engine::{Host, HostConfig};
use sieveplate_senses::{SensePump, SignalRoute};
use sieveplate_sysdef::{Plan, PlanStore, SystemSpec};

fn read_spec(file: &str) -> Result<SystemSpec> {
    let src =
        std::fs::read_to_string(file).with_context(|| format!("cannot read spec '{file}'"))?;
    SystemSpec::from_toml(&src).map_err(|e| anyhow!("spec error: {e}"))
}

fn registry() -> sieveplate_core::TemplateRegistry {
    sieveplate_cells::builtin_registry()
}

/// Validate + materialize + record the plan. Prints the closure hash.
pub fn apply(file: &str, root: &str) -> Result<()> {
    let spec = read_spec(file)?;
    let reg = registry();
    let plan =
        Plan::from_spec(&spec, |t| reg.descriptor(t)).map_err(|e| anyhow!("plan error: {e}"))?;
    let store = PlanStore::open(root)?;
    let h = store.record(&plan)?;
    println!("✓ spec valid");
    println!("  closure: {}", plan.closure);
    println!("  plan:    {h} (HEAD)");
    println!("  cells:   {}", plan.cells.len());
    println!("  senses:  {}", plan.senses.len());
    println!("  routes:  {}", plan.routes.len());
    Ok(())
}

/// Dry-run: closure hash + diff against the applied plan.
pub fn plan(file: &str, root: &str) -> Result<()> {
    let spec = read_spec(file)?;
    let reg = registry();
    let next =
        Plan::from_spec(&spec, |t| reg.descriptor(t)).map_err(|e| anyhow!("plan error: {e}"))?;
    let store = PlanStore::open(root)?;
    let prev = store.head()?.map(|(_, p)| p);
    let diff = Plan::diff(prev.as_ref(), &next);
    println!(
        "closure: {}{}",
        next.closure,
        if diff.is_empty() { " (no changes)" } else { "" }
    );
    if let Some(from) = &diff.closure_from {
        println!("     was: {from}");
    }
    for c in &diff.added_cells {
        println!("  + cell {}/{}", c.vat, c.name);
    }
    for c in &diff.removed_cells {
        println!("  - cell {}/{}", c.vat, c.name);
    }
    if diff.changed_cells > 0 {
        println!("  ~ changed cells: {}", diff.changed_cells);
    }
    Ok(())
}

pub fn rollback(root: &str) -> Result<()> {
    let store = PlanStore::open(root)?;
    match store.previous()? {
        Some(plan) => {
            println!("✓ rolled back to closure {}", plan.closure);
            println!("  run `sieve run -f <spec>` to execute it (plan saved as HEAD)");
            Ok(())
        }
        None => Err(anyhow!("nothing to roll back (need ≥2 applied plans)")),
    }
}

pub fn status(root: &str) -> Result<()> {
    let store = PlanStore::open(root)?;
    match store.head()? {
        Some((h, plan)) => {
            println!("HEAD plan: {h}");
            println!("  closure: {}", plan.closure);
            println!("  system:  {}", plan.system);
            for c in &plan.cells {
                println!(
                    "  cell {}/{} <{}> sleep={:?}",
                    c.vat, c.name, c.template, c.sleep_after_ms
                );
            }
        }
        None => println!("no plan applied"),
    }
    Ok(())
}

/// Execute a declarative system until Ctrl-C.
pub async fn run_file(file: &str, root: &str) -> Result<()> {
    let spec = read_spec(file)?;

    // Record the plan first (apply semantics).
    {
        let reg = registry();
        let plan = Plan::from_spec(&spec, |t| reg.descriptor(t))
            .map_err(|e| anyhow!("plan error: {e}"))?;
        let store = PlanStore::open(root)?;
        let h = store.record(&plan)?;
        println!("✓ applied closure {} (plan {h})", plan.closure);
    }

    let host = Host::start(
        HostConfig {
            host: spec.system.name.clone(),
            vats: dedup_vats(&spec),
            mailbox_capacity: 1024,
            worker_exe: None,
            drain_on_shutdown: true,
        },
        root,
    )?;

    // Create cells (declaratively).
    for c in &spec.cells {
        let cs = sieveplate_engine::CellSpec {
            name: c.name.clone(),
            vat: c.vat.clone(),
            template: c.template.clone(),
            caps: c
                .caps
                .iter()
                .map(|cap| sieveplate_engine::CapSpec {
                    to: cap.to.clone(),
                    rights: cap.rights.clone(),
                })
                .collect(),
            sleep_after_ms: c.sleep_after_ms,
            persist_on_turn: c.persist_on_turn,
            max_restarts: c.max_restarts,
            isolation: match c.isolation.as_deref() {
                Some("process") => sieveplate_engine::Isolation::Process,
                _ => sieveplate_engine::Isolation::Thread,
            },
            sandbox: c.sandbox.clone().unwrap_or_default(),
        };
        host.create_cell(&cs).await?;
        println!("✓ cell {}/{} <{}>", c.vat, c.name, c.template);
    }

    // Network (Phase 4) if configured. Links are always secured (SIEVE1:
    // hybrid Ed25519+ML-DSA identity, X25519+ML-KEM-768 keys, AEAD frames).
    let mut network = None;
    if let Some(net) = &spec.network {
        let link = {
            let dir = std::path::Path::new(root).join("fabric");
            let identity = sieveplate_fabric::HostIdentity::load_or_create(&dir, &host.host)?;
            let peers = std::sync::Arc::new(sieveplate_fabric::KnownPeers::open(
                dir.join("known_peers.json"),
            )?);
            sieveplate_fabric::LinkConfig::new(identity, peers)
        };
        if let Some(listen) = &net.listen {
            network =
                Some(sieveplate_fabric::serve(host.fabric.clone(), listen, link.clone()).await?);
            println!("✓ listening on {listen} (secure link)");
        }
        for peer in &net.peers {
            // peers are "alias=addr"
            let (alias, addr) = match peer.split_once('=') {
                Some(x) => x,
                None => return Err(anyhow!("peer '{peer}' must be alias=addr")),
            };
            sieveplate_fabric::connect_peer(&host.fabric, alias, addr, &link).await?;
            println!("✓ peer {alias} @ {addr} (secure link)");
        }
    }

    // Senses (L1) + pump.
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let mut handles = Vec::new();
    for s in &spec.senses {
        match s.kind.as_str() {
            "timer" => handles.push(sieveplate_senses::spawn_timer(
                &s.name,
                s.period_ms.unwrap_or(1000),
                tx.clone(),
            )),
            "tcp" => handles.push(sieveplate_senses::spawn_tcp(
                &s.name,
                s.listen.as_deref().unwrap_or("127.0.0.1:7780"),
                tx.clone(),
            )),
            "file" => handles.push(sieveplate_senses::spawn_file_tail(
                &s.name,
                std::path::PathBuf::from(s.path.as_deref().unwrap_or("./events.in")),
                tx.clone(),
            )),
            other => return Err(anyhow!("unknown sense kind '{other}'")),
        }
        println!("✓ sense {} (kind={})", s.name, s.kind);
    }
    drop(tx);

    let routes: Vec<SignalRoute> = spec
        .routes
        .iter()
        .filter_map(|r| {
            if !r.from.starts_with("sense:") {
                return None;
            }
            let sense_name = r.from["sense:".len()..].to_string();
            let target = sieveplate_core::parse_port(&r.to, &spec.system.name, "core").ok()?;
            Some(SignalRoute {
                sense_name,
                target,
                msg_kind: r.name.clone(),
            })
        })
        .collect();
    for r in &routes {
        println!("✓ route sense:{} → {}", r.sense_name, r.target);
    }

    let pump = SensePump::new(
        rx,
        Arc::new(host.fabric.clone()),
        routes,
        Some(host.event_log()),
    );
    let pump_handle = tokio::spawn(pump.run());

    println!("\n\x1b[1mSieveplate running — Ctrl-C to stop\x1b[0m");
    tokio::signal::ctrl_c().await?;

    println!("\nshutting down…");
    for h in handles {
        h.abort();
    }
    pump_handle.abort();
    if let Some(n) = network {
        n.shutdown();
    }
    host.shutdown().await;
    println!("✓ clean shutdown (state persisted, rollback available)");
    Ok(())
}

fn dedup_vats(spec: &SystemSpec) -> Vec<String> {
    let mut vats: Vec<String> = spec.cells.iter().map(|c| c.vat.clone()).collect();
    vats.push("core".into());
    vats.sort();
    vats.dedup();
    vats
}
