//! Plans: the materialized system, content-addressed and diffable.
//!
//! - [`Plan::from_spec`] materializes a validated spec into a plan.
//! - The plan's `closure` hash = sha256(canonical spec + template
//!   descriptors) — the single hash that identifies the whole system
//!   (L7: `system_state = f(input_hashes)`).
//! - [`PlanStore`] persists applied plans as content-addressed objects,
//!   enabling `sieve rollback` = apply(previous plan).
//! - [`Plan::diff`] computes the changes needed to move from the running
//!   plan to the next one (idempotent converge, Nix-style).

use serde::{Deserialize, Serialize};
use sha2::Digest;

use sieveplate_store::{ContentStore, Hash};

use crate::error::SpecError;
use crate::spec::SystemSpec;

/// A materialized, comparable system plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub system: String,
    /// The closure hash: identifies the exact system (spec + templates).
    pub closure: Hash,
    pub cells: Vec<sieveplate_engine::CellSpec>,
    pub senses: Vec<crate::spec::SenseCfg>,
    pub routes: Vec<crate::spec::RouteCfg>,
    pub network: Option<crate::spec::NetworkCfg>,
}

impl Plan {
    /// Materialize a validated spec. `template_descriptor(tpl)` resolves
    /// template ids to their content descriptors (they feed the closure).
    pub fn from_spec(
        spec: &SystemSpec,
        mut template_descriptor: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, SpecError> {
        spec.validate()?;

        // Canonical input: spec JSON + sorted template descriptors.
        let mut descriptors: Vec<(String, String)> = Vec::new();
        for c in &spec.cells {
            let d = template_descriptor(&c.template).ok_or_else(|| {
                SpecError::Validation(format!("unknown template '{}'", c.template))
            })?;
            descriptors.push((c.template.clone(), d));
        }
        descriptors.sort();
        let mut input = spec.canonical_json();
        input.push('\u{0}');
        for (id, d) in &descriptors {
            input.push_str(id);
            input.push('@');
            input.push_str(d);
            input.push('\n');
        }
        let closure = sha2::Sha256::digest(input.as_bytes());
        let closure = hex::encode(closure);

        let cells = spec
            .cells
            .iter()
            .map(|c| sieveplate_engine::CellSpec {
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
            })
            .collect();

        Ok(Plan {
            system: spec.system.name.clone(),
            closure,
            cells,
            senses: spec.senses.clone(),
            routes: spec.routes.clone(),
            network: spec.network.clone(),
        })
    }

    /// Difference between the currently-applied plan (if any) and `self`.
    pub fn diff(prev: Option<&Plan>, next: &Plan) -> PlanDiff {
        let empty: Vec<sieveplate_engine::CellSpec> = Vec::new();
        let prev_cells = prev.map(|p| &p.cells).unwrap_or(&empty);
        let key = |c: &sieveplate_engine::CellSpec| (c.name.clone(), c.vat.clone());

        let added = next
            .cells
            .iter()
            .filter(|c| !prev_cells.iter().any(|p| key(p) == key(c)))
            .cloned()
            .collect();
        let removed = prev_cells
            .iter()
            .filter(|c| !next.cells.iter().any(|n| key(n) == key(c)))
            .cloned()
            .collect();
        let changed = next
            .cells
            .iter()
            .filter(|c| {
                prev_cells.iter().any(|p| {
                    key(p) == key(c)
                        && serde_json::to_string(p).unwrap() != serde_json::to_string(c).unwrap()
                })
            })
            .count();

        PlanDiff {
            added_cells: added,
            removed_cells: removed,
            changed_cells: changed,
            closure_from: prev.map(|p| p.closure.clone()),
            closure_to: next.closure.clone(),
        }
    }

    /// Serialize for the plan store.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse from the plan store.
    pub fn from_json(s: &str) -> Result<Self, SpecError> {
        serde_json::from_str(s).map_err(|e| SpecError::Validation(e.to_string()))
    }
}

/// Result of [`Plan::diff`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDiff {
    pub closure_from: Option<Hash>,
    pub closure_to: Hash,
    pub added_cells: Vec<sieveplate_engine::CellSpec>,
    pub removed_cells: Vec<sieveplate_engine::CellSpec>,
    pub changed_cells: usize,
}

impl PlanDiff {
    pub fn is_empty(&self) -> bool {
        self.added_cells.is_empty()
            && self.removed_cells.is_empty()
            && self.changed_cells == 0
            && self.closure_from.as_deref() == Some(self.closure_to.as_str())
    }
}

/// Store of applied plans (content-addressed via the L3 CAS).
pub struct PlanStore {
    root: std::path::PathBuf,
    store: ContentStore,
}

impl PlanStore {
    pub fn open(root: impl Into<std::path::PathBuf>) -> Result<Self, SpecError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| SpecError::Io(e.to_string()))?;
        let store = ContentStore::open(root.join("objects"))
            .map_err(|e| SpecError::Store(e.to_string()))?;
        Ok(PlanStore { root, store })
    }

    /// Record an applied plan; returns its content hash. Keeps `HEAD`.
    pub fn record(&self, plan: &Plan) -> Result<Hash, SpecError> {
        let bytes = plan.to_json().into_bytes();
        let h = self
            .store
            .put(&bytes)
            .map_err(|e| SpecError::Store(e.to_string()))?;
        std::fs::write(self.root.join("HEAD"), &h).map_err(|e| SpecError::Io(e.to_string()))?;

        // History line: "<hash> <closure>" per applied plan.
        use std::io::Write;
        let mut hist = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("history.log"))
            .map_err(|e| SpecError::Io(e.to_string()))?;
        writeln!(hist, "{h} {}", plan.closure).map_err(|e| SpecError::Io(e.to_string()))?;
        Ok(h)
    }

    /// The currently applied plan (if any).
    pub fn head(&self) -> Result<Option<(Hash, Plan)>, SpecError> {
        let h = match std::fs::read_to_string(self.root.join("HEAD")) {
            Ok(s) => s.trim().to_string(),
            Err(_) => return Ok(None),
        };
        let bytes = self
            .store
            .get(&h)
            .map_err(|e| SpecError::Store(e.to_string()))?
            .ok_or_else(|| SpecError::Store(format!("HEAD object {h} missing")))?;
        Ok(Some((
            h,
            Plan::from_json(&String::from_utf8_lossy(&bytes))?,
        )))
    }

    /// Apply a rollback: switch HEAD to the previous plan in history.
    /// Returns the plan to apply (the pre-HEAD one), and rewrites HEAD.
    pub fn previous(&self) -> Result<Option<Plan>, SpecError> {
        let hist_path = self.root.join("history.log");
        let hist = std::fs::read_to_string(&hist_path).unwrap_or_default();
        let lines: Vec<&str> = hist.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() < 2 {
            return Ok(None); // nothing to roll back to
        }
        // The second-to-last entry is the plan before HEAD.
        let target = lines[lines.len() - 2];
        let h = target
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        let bytes = self
            .store
            .get(&h)
            .map_err(|e| SpecError::Store(e.to_string()))?
            .ok_or_else(|| SpecError::Store(format!("plan object {h} missing")))?;
        let plan = Plan::from_json(&String::from_utf8_lossy(&bytes))?;
        // Move HEAD back and truncate the last history entry.
        std::fs::write(self.root.join("HEAD"), &h).map_err(|e| SpecError::Io(e.to_string()))?;
        let kept: Vec<&str> = lines[..lines.len() - 1].to_vec();
        std::fs::write(&hist_path, kept.join("\n") + "\n")
            .map_err(|e| SpecError::Io(e.to_string()))?;
        Ok(Some(plan))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::SystemSpec;
    use sieveplate_cells::builtin_registry;

    const DEMO: &str = r#"
[system]
name = "demo"

[[cell]]
name = "counter"
vat = "core"
template = "builtin:counter"
"#;

    #[test]
    fn closure_hash_stable_and_input_sensitive() {
        let reg = builtin_registry();
        let spec = SystemSpec::from_toml(DEMO).unwrap();
        let p1 = Plan::from_spec(&spec, |t| reg.descriptor(t)).unwrap();
        let p2 = Plan::from_spec(&spec, |t| reg.descriptor(t)).unwrap();
        assert_eq!(p1.closure, p2.closure); // deterministic

        let changed = DEMO.replace("builtin:counter", "builtin:kv");
        let spec2 = SystemSpec::from_toml(&changed).unwrap();
        let p3 = Plan::from_spec(&spec2, |t| reg.descriptor(t)).unwrap();
        assert_ne!(p1.closure, p3.closure); // input-sensitive
    }

    #[test]
    fn diff_adds_and_removes() {
        let reg = builtin_registry();
        let spec1 = SystemSpec::from_toml(DEMO).unwrap();
        let p1 = Plan::from_spec(&spec1, |t| reg.descriptor(t)).unwrap();

        let with_kv = DEMO.replace(
            "template = \"builtin:counter\"",
            "template = \"builtin:counter\"\nsleep_after_ms = 99",
        );
        let spec2 = SystemSpec::from_toml(&with_kv).unwrap();
        let p2 = Plan::from_spec(&spec2, |t| reg.descriptor(t)).unwrap();
        let d = Plan::diff(Some(&p1), &p2);
        assert!(d.added_cells.is_empty());
        assert!(d.removed_cells.is_empty());
        assert_eq!(d.changed_cells, 1); // sleep policy changed

        let d2 = Plan::diff(Some(&p1), &p1);
        assert!(d2.is_empty());
    }

    #[test]
    fn plan_store_rollback() {
        let dir = std::env::temp_dir().join(format!("sp-plans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = PlanStore::open(&dir).unwrap();
        assert!(store.head().unwrap().is_none());

        let reg = builtin_registry();
        let s1 = SystemSpec::from_toml(DEMO).unwrap();
        let p1 = Plan::from_spec(&s1, |t| reg.descriptor(t)).unwrap();
        store.record(&p1).unwrap();
        assert_eq!(store.head().unwrap().unwrap().1.closure, p1.closure);

        let changed = DEMO.replace("builtin:counter", "builtin:kv");
        let s2 = SystemSpec::from_toml(&changed).unwrap();
        let p2 = Plan::from_spec(&s2, |t| reg.descriptor(t)).unwrap();
        store.record(&p2).unwrap();

        let back = store.previous().unwrap().unwrap();
        assert_eq!(back.closure, p1.closure);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
