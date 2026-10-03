//! **sieveplate-engine** — Layer 4: the Cell Instantiation Engine
//! ("the Membrane").
//!
//! A [`Host`] owns vats, cells, the fabric, the content store and the event
//! log. Lifecycle API (mirroring the spec):
//! - `create_cell`   — instantiate from a content-addressed template
//! - `destroy_cell`  — terminate
//! - `snapshot_cell` — persist state → content hash
//! - `restore_cell`  — rebuild from a snapshot hash
//! - `scale_to_zero` — evict an idle cell (stub keeps live references)
//! - `wake`          — force-restore a sleeping cell and measure latency
//!
//! Performance targets from the 2026 spec: cell creation/wake in the
//! sub-millisecond range in-process; scale-to-zero < 10 ms.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use sieveplate_cells::builtin_registry;
use sieveplate_core::{
    spawn_vat, Cap, CapTable, CellError, Metrics, Port, Promises, Rights, VatCtrl, VatDeps,
    VatHandle, VatStatus,
};
use sieveplate_fabric::Fabric;
use sieveplate_store::{ContentStore, EventLog, Hash};

/// Declarative capability grant: `to` is a port path, rights are names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapSpec {
    pub to: String,
    pub rights: Vec<String>,
}

/// Everything needed to instantiate one cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellSpec {
    pub name: String,
    pub vat: String,
    pub template: String,
    #[serde(default)]
    pub caps: Vec<CapSpec>,
    /// Idle duration before scale-to-zero (ms). None = never sleeps.
    #[serde(default)]
    pub sleep_after_ms: Option<u64>,
    #[serde(default = "default_persist")]
    pub persist_on_turn: bool,
    #[serde(default)]
    pub max_restarts: u32,
}

fn default_persist() -> bool {
    true
}

/// Host configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub host: String,
    #[serde(default = "default_vats")]
    pub vats: Vec<String>,
    #[serde(default = "default_mailbox")]
    pub mailbox_capacity: usize,
}

fn default_vats() -> Vec<String> {
    vec!["core".to_string()]
}

fn default_mailbox() -> usize {
    1024
}

/// Status of one cell slot (active or sleeping).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellStatus {
    pub name: String,
    pub vat: String,
    pub state: String,
}

/// A running host.
pub struct Host {
    pub host: String,
    pub fabric: Fabric,
    pub store: Arc<ContentStore>,
    pub log: Arc<EventLog>,
    pub metrics: Arc<Metrics>,
    pub registry: Arc<sieveplate_core::TemplateRegistry>,
    vats: Vec<(String, VatHandle)>,
}

impl Host {
    /// Boot a host: store + log + registry + fabric + vats.
    pub fn start(cfg: HostConfig, root: impl AsRef<Path>) -> Result<Self, CellError> {
        let root = root.as_ref().to_path_buf();
        let store = Arc::new(ContentStore::open(root.join("objects"))?);
        let log = Arc::new(EventLog::open(root.join("events.jsonl"))?);
        let metrics = Arc::new(Metrics::new());
        let registry = Arc::new(builtin_registry());
        let promises = Promises::new();
        let fabric = Fabric::new(cfg.host.clone(), promises);

        let mut vats = Vec::new();
        for name in &cfg.vats {
            let handle = spawn_vat(VatDeps {
                host: cfg.host.clone(),
                name: name.clone(),
                store: Arc::clone(&store),
                log: Arc::clone(&log),
                metrics: Arc::clone(&metrics),
                fabric: Arc::new(fabric.clone()),
                registry: Arc::clone(&registry),
                promises: Arc::new(fabric.promises().clone()),
                mailbox_capacity: cfg.mailbox_capacity,
            });
            fabric.attach_local_vat(name, handle.sender());
            vats.push((name.clone(), handle));
        }

        let _ = log.append(
            "host.boot",
            vec![
                ("host".into(), cfg.host.clone()),
                ("vats".into(), cfg.vats.join(",")),
            ],
        );

        Ok(Host {
            host: cfg.host,
            fabric,
            store,
            log,
            metrics,
            registry,
            vats,
        })
    }

    fn vat_handle(&self, vat: &str) -> Result<&VatHandle, CellError> {
        self.vats
            .iter()
            .find(|(n, _)| n == vat)
            .map(|(_, h)| h)
            .ok_or_else(|| CellError::NotFound(format!("vat '{vat}'")))
    }

    /// Create a cell from a template, with capability grants.
    pub async fn create_cell(&self, spec: &CellSpec) -> Result<(), CellError> {
        let cell = self.registry.build(&spec.template)?;
        let mut table = CapTable::default();
        for c in &spec.caps {
            let target = sieveplate_core::parse_port(&c.to, &self.host, &spec.vat)?;
            let rights = Rights::parse(&c.rights)?;
            table.insert(Cap { target, rights });
        }
        let policy = sieveplate_core::SleepPolicy {
            after_idle_ms: spec.sleep_after_ms,
            persist_on_turn: spec.persist_on_turn,
        };
        let restart = sieveplate_core::RestartPolicy {
            max_restarts: spec.max_restarts,
            ..Default::default()
        };
        let (tx, rx) = oneshot::channel();
        self.vat_handle(&spec.vat)?
            .ctrl(VatCtrl::Inject {
                name: spec.name.clone(),
                template: spec.template.clone(),
                cell,
                caps: table,
                policy,
                restart,
                reply: tx,
            })
            .await?;
        rx.await
            .map_err(|_| CellError::VatClosed(spec.vat.clone()))??;
        Ok(())
    }

    /// Destroy a cell (terminates it; content-addressed state remains).
    pub async fn destroy_cell(&self, vat: &str, name: &str) -> Result<(), CellError> {
        let (tx, rx) = oneshot::channel();
        self.vat_handle(vat)?
            .ctrl(VatCtrl::Destroy {
                name: name.into(),
                reply: tx,
            })
            .await?;
        rx.await
            .map_err(|_| CellError::VatClosed(vat.to_string()))??;
        let _ = self
            .log
            .append("cell.destroy", vec![("cell".into(), name.into())]);
        Ok(())
    }

    /// Snapshot a cell now; returns the content hash.
    pub async fn snapshot_cell(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let (tx, rx) = oneshot::channel();
        self.vat_handle(vat)?
            .ctrl(VatCtrl::Snapshot {
                name: name.into(),
                reply: tx,
            })
            .await?;
        let h = rx
            .await
            .map_err(|_| CellError::VatClosed(vat.to_string()))??;
        let _ = self.log.append(
            "cell.snapshot",
            vec![("cell".into(), name.into()), ("hash".into(), h.clone())],
        );
        Ok(h)
    }

    /// Restore a cell from a snapshot hash (build + restore + inject).
    pub async fn restore_cell(
        &self,
        vat: &str,
        name: &str,
        template: &str,
        hash: &Hash,
    ) -> Result<(), CellError> {
        let bytes = self
            .store
            .get(hash)?
            .ok_or_else(|| CellError::Store(format!("snapshot {hash} missing")))?;
        let mut cell = self.registry.build(template)?;
        cell.restore(&bytes)?;

        let policy = sieveplate_core::SleepPolicy {
            after_idle_ms: None,
            persist_on_turn: true,
        };
        let (tx, rx) = oneshot::channel();
        self.vat_handle(vat)?
            .ctrl(VatCtrl::Inject {
                name: name.into(),
                template: template.into(),
                cell,
                caps: CapTable::default(),
                policy,
                restart: Default::default(),
                reply: tx,
            })
            .await?;
        rx.await
            .map_err(|_| CellError::VatClosed(vat.to_string()))??;
        let _ = self.log.append(
            "cell.restore",
            vec![("cell".into(), name.into()), ("hash".into(), hash.clone())],
        );
        Ok(())
    }

    /// Scale a cell to zero (evict → content-addressed snapshot).
    pub async fn scale_to_zero(&self, vat: &str, name: &str) -> Result<Hash, CellError> {
        let (tx, rx) = oneshot::channel();
        self.vat_handle(vat)?
            .ctrl(VatCtrl::Evict {
                name: name.into(),
                reply: tx,
            })
            .await?;
        rx.await
            .map_err(|_| CellError::VatClosed(vat.to_string()))?
    }

    /// Force-wake a sleeping (or absent-but-stubbed) cell via the
    /// kernel-level `__ping`; returns wake latency in microseconds.
    pub async fn wake(&self, vat: &str, name: &str) -> Result<u64, CellError> {
        let port = Port::new(&self.host, vat, name);
        let start = Instant::now();
        let reply = self
            .fabric
            .call(
                port,
                sieveplate_core::Envelope::KIND_PING,
                Vec::new(),
                Duration::from_secs(5),
            )
            .await?;
        if &reply != b"pong" {
            return Err(CellError::Other("unexpected ping reply".into()));
        }
        Ok(start.elapsed().as_micros() as u64)
    }

    /// Status of all vats + metrics snapshot.
    pub async fn status(&self) -> Result<(Vec<VatStatus>, serde_json::Value), CellError> {
        let mut out = Vec::new();
        for (_, h) in &self.vats {
            let (tx, rx) = oneshot::channel();
            h.ctrl(VatCtrl::Status { reply: tx }).await?;
            out.push(rx.await.map_err(|_| CellError::VatClosed(h.name.clone()))?);
        }
        Ok((out, self.metrics.snapshot_json()))
    }

    /// Flat list of cell slots for status output.
    pub async fn cells_status(&self) -> Vec<CellStatus> {
        let (vats, _) = self.status().await.unwrap_or_default();
        let mut out = Vec::new();
        for v in vats {
            for c in v.active {
                out.push(CellStatus {
                    name: c,
                    vat: v.name.clone(),
                    state: "active".into(),
                });
            }
            for c in v.sleeping {
                out.push(CellStatus {
                    name: c,
                    vat: v.name.clone(),
                    state: "sleeping".into(),
                });
            }
        }
        out
    }

    /// Shut the host down (all vats exit).
    pub async fn shutdown(&self) {
        for (_, h) in &self.vats {
            let (tx, rx) = oneshot::channel();
            if h.ctrl(VatCtrl::Shutdown { reply: tx }).await.is_ok() {
                let _ = rx.await;
            }
        }
        let _ = self.log.append("host.shutdown", vec![]);
    }

    /// Access the event log (for Datalog queries over system history).
    pub fn event_log(&self) -> Arc<EventLog> {
        Arc::clone(&self.log)
    }
}
