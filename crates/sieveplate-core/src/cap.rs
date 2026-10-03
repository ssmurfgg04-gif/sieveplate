//! Capability tables — the L2 authority model, userspace edition.
//!
//! Mapping to seL4: a [`Cap`] is an unforgeable authority token naming a
//! target port plus a rights mask; a [`CapTable`] is the CNode. Cells never
//! address other cells directly — they hold *capability slots* (CPtr-like
//! indices). Authorities flow only by explicit mint/attenuate/copy, and
//! revocation removes the slot immediately.
//!
//! On the seL4 port (see `platforms/sel4/README.md`) this table is backed by
//! real kernel capabilities inside a Microkit protection domain; the
//! semantics here are intentionally identical so the port is mechanical.

use serde::{Deserialize, Serialize};

use crate::port::Port;
use crate::CellError;

/// Rights bits. `SEND` covers one-way async sends; `CALL` covers
/// request/reply; `PERSIST` allows a cell to commit snapshots; `SPAWN`
/// allows creating child cells; `CONTROL` allows lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rights(pub u8);

impl Rights {
    pub const SEND: u8 = 1 << 0;
    pub const CALL: u8 = 1 << 1;
    pub const PERSIST: u8 = 1 << 2;
    pub const SPAWN: u8 = 1 << 3;
    pub const CONTROL: u8 = 1 << 4;

    pub const fn all() -> Self {
        Rights(0b0001_1111)
    }
    pub const fn ro() -> Self {
        Rights(0)
    }

    pub fn has(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Rights named in config strings (`send`, `call`, ...).
    pub fn parse(names: &[String]) -> Result<Self, CellError> {
        let mut r = 0u8;
        for n in names {
            match n.to_ascii_lowercase().as_str() {
                "send" => r |= Rights::SEND,
                "call" => r |= Rights::CALL,
                "persist" => r |= Rights::PERSIST,
                "spawn" => r |= Rights::SPAWN,
                "control" => r |= Rights::CONTROL,
                other => {
                    return Err(CellError::Other(format!(
                        "unknown right '{other}' (send|call|persist|spawn|control)"
                    )))
                }
            }
        }
        Ok(Rights(r))
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.has(Rights::SEND) {
            v.push("send");
        }
        if self.has(Rights::CALL) {
            v.push("call");
        }
        if self.has(Rights::PERSIST) {
            v.push("persist");
        }
        if self.has(Rights::SPAWN) {
            v.push("spawn");
        }
        if self.has(Rights::CONTROL) {
            v.push("control");
        }
        v
    }
}

/// An unforgeable authority: target port + rights mask.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap {
    pub target: Port,
    pub rights: Rights,
}

/// Per-cell capability table (the CNode analogue).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapTable {
    slots: Vec<Option<Cap>>,
}

impl CapTable {
    pub fn from_caps(caps: Vec<Cap>) -> Self {
        CapTable {
            slots: caps.into_iter().map(Some).collect(),
        }
    }

    /// Insert a capability into the next free slot; returns the slot index
    /// (the CPtr the cell uses to refer to it).
    pub fn insert(&mut self, cap: Cap) -> u32 {
        if let Some((i, _)) = self.slots.iter().enumerate().find(|(_, s)| s.is_none()) {
            self.slots[i] = Some(cap);
            return i as u32;
        }
        self.slots.push(Some(cap));
        (self.slots.len() - 1) as u32
    }

    pub fn get(&self, idx: u32) -> Option<&Cap> {
        self.slots.get(idx as usize).and_then(|s| s.as_ref())
    }

    /// Attenuation: derive a narrower capability from slot `idx`.
    /// New rights must be a subset of the parent's (least privilege).
    pub fn attenuate(&mut self, idx: u32, rights: Rights) -> Result<u32, CellError> {
        let parent = self
            .get(idx)
            .ok_or_else(|| CellError::NotFound(format!("cap slot {idx}")))?;
        if parent.rights.0 & rights.0 != rights.0 {
            return Err(CellError::NoCap {
                needed: "attenuation (subset of parent)".into(),
                target: parent.target.to_path(),
            });
        }
        let child = Cap {
            target: parent.target.clone(),
            rights,
        };
        Ok(self.insert(child))
    }

    /// Revocation: remove the slot. Immediate and propagates by construction
    /// (any later resolution of this slot fails).
    pub fn revoke(&mut self, idx: u32) -> bool {
        if let Some(slot) = self.slots.get_mut(idx as usize) {
            let existed = slot.is_some();
            *slot = None;
            existed
        } else {
            false
        }
    }

    /// Does this table grant `bit` on `target`?
    pub fn grants(&self, target: &Port, bit: u8) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|c| &c.target == target && c.rights.has(bit))
    }

    /// Snapshot of all live caps (for status/audit output).
    pub fn list(&self) -> Vec<(u32, Cap)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|c| (i as u32, c.clone())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(name: &str) -> Port {
        Port::new("h", "v", name)
    }

    #[test]
    fn attenuate_is_subset_only() {
        let mut t = CapTable::from_caps(vec![Cap {
            target: port("counter"),
            rights: Rights(Rights::SEND | Rights::CALL),
        }]);
        // narrower: ok
        let child = t.attenuate(0, Rights(Rights::SEND)).unwrap();
        assert!(t.get(child).unwrap().rights.has(Rights::SEND));
        // broader: denied
        assert!(t.attenuate(0, Rights(Rights::CONTROL)).is_err());
    }

    #[test]
    fn revoke_is_immediate() {
        let mut t = CapTable::from_caps(vec![Cap {
            target: port("counter"),
            rights: Rights::all(),
        }]);
        assert!(t.grants(&port("counter"), Rights::SEND));
        assert!(t.revoke(0));
        assert!(!t.grants(&port("counter"), Rights::SEND));
        assert!(!t.revoke(0));
    }
}
