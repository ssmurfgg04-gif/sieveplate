//! Ports — the stable, human-readable addressing scheme of the cell grid.
//!
//! A [`Port`] names a cell as `host/vat/cell`. Ports are what capabilities
//! point at and what routes resolve; they map 1:1 onto seL4-style
//! capability targets when the stack is ported to the verified kernel
//! (see `platforms/sel4/README.md`).

use serde::{Deserialize, Serialize};

/// Address of a cell: `host/vat/cell`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Port {
    pub host: String,
    pub vat: String,
    pub cell: String,
}

impl Port {
    pub fn new(host: impl Into<String>, vat: impl Into<String>, cell: impl Into<String>) -> Self {
        Port {
            host: host.into(),
            vat: vat.into(),
            cell: cell.into(),
        }
    }

    /// Render as `host/vat/cell`.
    pub fn to_path(&self) -> String {
        format!("{}/{}/{}", self.host, self.vat, self.cell)
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.host, self.vat, self.cell)
    }
}

/// Parse a port path. Accepted forms:
/// - `host/vat/cell`
/// - `vat/cell` (host defaults to `default_host`)
/// - `cell` (host and vat default to `default_host` / `default_vat`)
pub fn parse_port(
    s: &str,
    default_host: &str,
    default_vat: &str,
) -> Result<Port, crate::error::CellError> {
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [h, v, c] => Ok(Port::new(*h, *v, *c)),
        [v, c] => Ok(Port::new(default_host, *v, *c)),
        [c] => Ok(Port::new(default_host, default_vat, *c)),
        _ => Err(crate::error::CellError::Other(format!(
            "cannot parse port '{s}' (expected host/vat/cell, vat/cell or cell)"
        ))),
    }
}
