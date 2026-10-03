//! The declarative system spec (TOML) — L7.
//!
//! ```toml
//! [system]
//! name = "demo"              # becomes the host alias
//!
//! [network]                  # optional: Phase-4 multi-host
//! listen = "127.0.0.1:7770"
//! peers = []
//!
//! [[sense]]                  # L1 sources
//! name = "tick"
//! kind = "timer"             # timer | tcp | file
//! period_ms = 500
//!
//! [[cell]]                   # L5 cells on L4 vats
//! name = "counter"
//! vat = "core"
//! template = "builtin:counter"
//! sleep_after_ms = 250
//! [[cell.caps]]              # L2 capability grants (no ambient authority)
//! to = "core/counter"
//! rights = ["send", "call"]
//!
//! [[route]]                  # L6 wiring: sense → cell
//! from = "sense:tick"
//! to = "core/counter"
//! name = "add"
//! ```
//!
//! The closure hash is sha256 over the canonical spec JSON plus the content
//! descriptors of every referenced template — change any input (even a
//! cell's semantics) and the system closure changes.

use serde::{Deserialize, Serialize};

use crate::error::SpecError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemSpec {
    pub system: SystemMeta,
    #[serde(default)]
    pub network: Option<NetworkCfg>,
    #[serde(default, rename = "sense")]
    pub senses: Vec<SenseCfg>,
    #[serde(default, rename = "cell")]
    pub cells: Vec<CellCfg>,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMeta {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCfg {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenseCfg {
    pub name: String,
    /// timer | tcp | file
    pub kind: String,
    #[serde(default)]
    pub period_ms: Option<u64>,
    /// file: path to watch
    #[serde(default)]
    pub path: Option<String>,
    /// tcp: listen address
    #[serde(default)]
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellCfg {
    pub name: String,
    #[serde(default = "default_vat")]
    pub vat: String,
    pub template: String,
    #[serde(default)]
    pub caps: Vec<CapCfg>,
    #[serde(default)]
    pub sleep_after_ms: Option<u64>,
    #[serde(default = "default_persist")]
    pub persist_on_turn: bool,
    #[serde(default = "default_restarts")]
    pub max_restarts: u32,
    /// `thread` (default) or `process` (jailed OS process with seccomp +
    /// Landlock). See ADR-0005.
    #[serde(default)]
    pub isolation: Option<String>,
    /// Sandbox policy JSON for process cells.
    #[serde(default)]
    pub sandbox: Option<sieveplate_jail::SandboxPolicy>,
}

fn default_vat() -> String {
    "core".into()
}
fn default_persist() -> bool {
    true
}
fn default_restarts() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapCfg {
    /// Port path of the target (vat/cell or host/vat/cell).
    pub to: String,
    /// send | call | persist | spawn | control
    pub rights: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCfg {
    /// `sense:<name>`
    pub from: String,
    /// `[host/]vat/cell`
    pub to: String,
    /// Optional message kind override (default: the signal's name).
    #[serde(default)]
    pub name: Option<String>,
}

impl SystemSpec {
    /// Parse from TOML text.
    pub fn from_toml(src: &str) -> Result<Self, SpecError> {
        let spec: SystemSpec = toml::from_str(src).map_err(|e| SpecError::Toml(e.to_string()))?;
        spec.validate()?;
        Ok(spec)
    }

    /// Canonical JSON (fields in struct order; serde_json preserves order of
    /// struct fields via serde's default serializer for structs).
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Validate structure: unique names, known sense kinds, routes pointing
    /// at declared senses, capability right names.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.system.name.trim().is_empty() {
            return Err(SpecError::Validation("system.name must be set".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.senses {
            if !seen.insert(format!("sense:{}", s.name)) {
                return Err(SpecError::Validation(format!(
                    "duplicate sense '{}'",
                    s.name
                )));
            }
            match s.kind.as_str() {
                "timer" => {
                    if s.period_ms.is_none() {
                        return Err(SpecError::Validation(format!(
                            "sense '{}' kind=timer requires period_ms",
                            s.name
                        )));
                    }
                }
                "tcp" => {
                    if s.listen.is_none() {
                        return Err(SpecError::Validation(format!(
                            "sense '{}' kind=tcp requires listen",
                            s.name
                        )));
                    }
                }
                "file" => {
                    if s.path.is_none() {
                        return Err(SpecError::Validation(format!(
                            "sense '{}' kind=file requires path",
                            s.name
                        )));
                    }
                }
                other => {
                    return Err(SpecError::Validation(format!(
                        "sense '{}' has unknown kind '{other}' (timer|tcp|file)",
                        s.name
                    )))
                }
            }
        }
        let mut cell_names = std::collections::BTreeSet::new();
        for c in &self.cells {
            if !cell_names.insert(format!("cell:{}", c.name)) {
                return Err(SpecError::Validation(format!(
                    "duplicate cell '{}'",
                    c.name
                )));
            }
            if !c.template.starts_with("builtin:") && !c.template.starts_with("cas:") {
                return Err(SpecError::Validation(format!(
                    "cell '{}' template '{}' must start with builtin: or cas:",
                    c.name, c.template
                )));
            }
        }
        for r in &self.routes {
            if !r.from.starts_with("sense:") {
                return Err(SpecError::Validation(format!(
                    "route from '{}' must be sense:<name>",
                    r.from
                )));
            }
            let sense = &r.from["sense:".len()..];
            if !self.senses.iter().any(|s| s.name == sense) {
                return Err(SpecError::Validation(format!(
                    "route references unknown sense '{sense}'"
                )));
            }
            // Target: strip host if 3 segments.
            let segs: Vec<&str> = r.to.split('/').filter(|s| !s.is_empty()).collect();
            let cell_ref = match segs.len() {
                3 => segs[2],
                2 => segs[1],
                1 => segs[0],
                _ => {
                    return Err(SpecError::Validation(format!(
                        "route to '{}' not a port path",
                        r.to
                    )))
                }
            };
            if !cell_names.contains(&format!("cell:{cell_ref}")) {
                return Err(SpecError::Validation(format!(
                    "route references unknown cell '{cell_ref}'"
                )));
            }
        }
        for c in &self.cells {
            for cap in &c.caps {
                for r in &cap.rights {
                    if !["send", "call", "persist", "spawn", "control"]
                        .contains(&r.to_lowercase().as_str())
                    {
                        return Err(SpecError::Validation(format!(
                            "cell '{}' cap right '{}' invalid",
                            c.name, r
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = r#"
[system]
name = "demo"

[[sense]]
name = "tick"
kind = "timer"
period_ms = 500

[[cell]]
name = "counter"
vat = "core"
template = "builtin:counter"
sleep_after_ms = 250
[[cell.caps]]
to = "core/counter"
rights = ["send"]

[[route]]
from = "sense:tick"
to = "core/counter"
name = "add"
"#;

    #[test]
    fn parses_and_validates() {
        let spec = SystemSpec::from_toml(DEMO).unwrap();
        assert_eq!(spec.cells.len(), 1);
        assert_eq!(spec.routes.len(), 1);
        assert_eq!(spec.cells[0].caps[0].rights, vec!["send"]);
    }

    #[test]
    fn rejects_unknown_sense_kind() {
        let bad = DEMO.replace("kind = \"timer\"", "kind = \"wifi\"");
        assert!(SystemSpec::from_toml(&bad).is_err());
    }

    #[test]
    fn rejects_dangling_route() {
        let bad = DEMO.replace("to = \"core/counter\"", "to = \"core/ghost\"");
        assert!(SystemSpec::from_toml(&bad).is_err());
    }
}
