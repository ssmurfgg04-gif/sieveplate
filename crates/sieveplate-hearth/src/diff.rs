//! Logical diff — the branch-level view of change.
//!
//! `diff(a, b)` walks two snapshot *trees* (key → blob) and reports which
//! keys were added, removed, or updated. It says **what changed**, keyed by
//! meaning. Its sibling [`crate::ddelta`] says **which bytes moved** between
//! two snapshots. Same store, two levels of description.

use serde::{Deserialize, Serialize};
use sieveplate_store::Hash;

use crate::tree::Tree;

/// One added key (carries the blob hash so the set is appliable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Added {
    pub key: String,
    pub new: Hash,
}

/// One removed key (carries the old blob hash so the set is invertible).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub key: String,
    pub old: Hash,
}

/// One updated key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Updated {
    pub key: String,
    pub old: Hash,
    pub new: Hash,
}

/// A logical change set between two trees. Self-contained: applying it to
/// the source tree reconstructs the target tree exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub added: Vec<Added>,
    pub removed: Vec<Removed>,
    pub updated: Vec<Updated>,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.updated.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.removed.len() + self.updated.len()
    }

    /// Human-readable one-line-per-change summary (keys sorted).
    pub fn summary(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for a in &self.added {
            lines.push(format!("+ {} ({})", a.key, &a.new[..12.min(a.new.len())]));
        }
        for r in &self.removed {
            lines.push(format!("- {} ({})", r.key, &r.old[..12.min(r.old.len())]));
        }
        for u in &self.updated {
            lines.push(format!(
                "~ {} ({} → {})",
                u.key,
                &u.old[..12.min(u.old.len())],
                &u.new[..12.min(u.new.len())]
            ));
        }
        lines
    }
}

/// Diff two trees (directional: a → b).
pub fn diff_trees(a: &Tree, b: &Tree) -> ChangeSet {
    let mut cs = ChangeSet::default();
    for (k, ha) in a {
        match b.get(k) {
            None => cs.removed.push(Removed {
                key: k.clone(),
                old: ha.clone(),
            }),
            Some(hb) if hb != ha => cs.updated.push(Updated {
                key: k.clone(),
                old: ha.clone(),
                new: hb.clone(),
            }),
            Some(_) => {}
        }
    }
    for (k, hb) in b {
        if !a.contains_key(k) {
            cs.added.push(Added {
                key: k.clone(),
                new: hb.clone(),
            });
        }
    }
    cs
}

/// Invert a change set (apply b → a).
pub fn invert(cs: &ChangeSet) -> ChangeSet {
    ChangeSet {
        added: cs
            .removed
            .iter()
            .map(|r| Added {
                key: r.key.clone(),
                new: r.old.clone(),
            })
            .collect(),
        removed: cs
            .added
            .iter()
            .map(|a| Removed {
                key: a.key.clone(),
                old: a.new.clone(),
            })
            .collect(),
        updated: cs
            .updated
            .iter()
            .map(|u| Updated {
                key: u.key.clone(),
                old: u.new.clone(),
                new: u.old.clone(),
            })
            .collect(),
    }
}

/// Apply a change set to a tree, using `lookup` to resolve blob hashes for
/// added keys (the caller supplies the target tree's blobs).
pub fn apply_to_tree(tree: &mut Tree, cs: &ChangeSet) {
    for a in &cs.added {
        tree.insert(a.key.clone(), a.new.clone());
    }
    for u in &cs.updated {
        tree.insert(u.key.clone(), u.new.clone());
    }
    for r in &cs.removed {
        tree.remove(&r.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(pairs: &[(&str, &str)]) -> Tree {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn diff_added_removed_updated() {
        let a = t(&[("keep", "h0"), ("gone", "h1"), ("edit", "h2")]);
        let b = t(&[("keep", "h0"), ("edit", "h9"), ("new", "h3")]);
        let cs = diff_trees(&a, &b);
        assert_eq!(cs.added.len(), 1);
        assert_eq!(cs.added[0].key, "new");
        assert_eq!(cs.removed.len(), 1);
        assert_eq!(cs.removed[0].key, "gone");
        assert_eq!(cs.updated.len(), 1);
        assert_eq!(cs.updated[0].key, "edit");
        assert_eq!(cs.total_changes(), 3);
        // invert: applying the inverse to b restores a
        let mut back = b.clone();
        apply_to_tree(&mut back, &invert(&cs));
        assert_eq!(back, a);
    }

    #[test]
    fn identical_trees_diff_empty() {
        let a = t(&[("x", "h")]);
        assert!(diff_trees(&a, &a).is_empty());
    }
}
