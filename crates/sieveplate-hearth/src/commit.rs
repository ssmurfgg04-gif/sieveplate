//! Commits and branch refs — the mutable pointers over immutable history.
//!
//! A commit is a content-addressed object `{parent, tree, branch, message,
//! ts_ms}`; the CAS hash *is* the commit id. A branch is a mutable pointer
//! file (`refs.json`) guarded by a mutex, with an append-only reflog
//! (`reflog.jsonl`) recording every pointer move — so branch history is
//! auditable even though branches themselves are mutable.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sieveplate_store::{ContentStore, Hash};

use crate::error::HearthError;
use crate::tree::{get_tree, put_tree, Tree};

/// A commit object. The CAS hash of its canonical encoding is its id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Parent commit (None = root).
    #[serde(default)]
    pub parent: Option<Hash>,
    /// Snapshot tree this commit pins.
    pub tree: Hash,
    /// Branch the commit was recorded on.
    pub branch: String,
    pub message: String,
    pub ts_ms: u128,
}

/// Branch pointer table (mutable state, kept outside the CAS).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Refs {
    /// Branch name → current tip commit (None = branch with no commits).
    branches: BTreeMap<String, Option<Hash>>,
}

/// One reflog entry: a pointer move.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflogEntry {
    pub branch: String,
    pub old: Option<Hash>,
    pub new: Option<Hash>,
    pub action: String,
    pub ts_ms: u128,
}

pub struct Hearth {
    pub(crate) store: Arc<ContentStore>,
    refs_path: PathBuf,
    reflog_path: PathBuf,
    refs: Mutex<Refs>,
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

impl Hearth {
    /// Open (or initialize) Hearth under a runtime root. Objects go to the
    /// shared CAS (`root/objects`); refs and reflog to `root/hearth/`.
    pub fn open(root: impl Into<PathBuf>, store: Arc<ContentStore>) -> Result<Self, HearthError> {
        let root = root.into();
        let hearth_dir = root.join("hearth");
        std::fs::create_dir_all(&hearth_dir)?;
        let refs_path = hearth_dir.join("refs.json");
        let reflog_path = hearth_dir.join("reflog.jsonl");
        let refs = if refs_path.exists() {
            serde_json::from_slice(&std::fs::read(&refs_path)?)
                .map_err(|e| HearthError::Codec(e.to_string()))?
        } else {
            Refs::default()
        };
        Ok(Hearth {
            store,
            refs_path,
            reflog_path,
            refs: Mutex::new(refs),
        })
    }

    fn save_refs(&self, refs: &Refs) -> Result<(), HearthError> {
        let tmp = self.refs_path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(refs).map_err(|e| HearthError::Codec(e.to_string()))?,
        )?;
        std::fs::rename(&tmp, &self.refs_path)?;
        Ok(())
    }

    fn log_ref(&self, entry: &ReflogEntry) -> Result<(), HearthError> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.reflog_path)?;
        writeln!(
            f,
            "{}",
            serde_json::to_string(entry).map_err(|e| HearthError::Codec(e.to_string()))?
        )?;
        Ok(())
    }

    // -- blobs and trees ---------------------------------------------------

    /// Write a blob into the CAS.
    pub fn write_blob(&self, data: &[u8]) -> Result<Hash, HearthError> {
        Ok(self.store.put(data)?)
    }

    /// Persist a snapshot tree; returns the tree hash.
    pub fn snapshot(&self, entries: Vec<(String, Hash)>) -> Result<Hash, HearthError> {
        let tree: Tree = entries.into_iter().collect();
        put_tree(&self.store, &tree)
    }

    /// Read a snapshot tree.
    pub fn read_tree(&self, tree: &Hash) -> Result<Tree, HearthError> {
        get_tree(&self.store, tree)
    }

    // -- commits and branches ---------------------------------------------

    /// Record a commit on a branch: parent = the branch's current tip.
    /// Returns the commit id.
    pub fn commit(&self, branch: &str, tree: &Hash, message: &str) -> Result<Hash, HearthError> {
        let parent = self.branch_tip(branch)?;
        let commit = Commit {
            parent,
            tree: tree.clone(),
            branch: branch.to_string(),
            message: message.to_string(),
            ts_ms: now_ms(),
        };
        let bytes = serde_json::to_vec(&commit).map_err(|e| HearthError::Codec(e.to_string()))?;
        let id = self.store.put(&bytes)?;
        self.update_ref(branch, id.clone(), "commit")?;
        Ok(id)
    }

    /// Read a commit object.
    pub fn read_commit(&self, id: &Hash) -> Result<Commit, HearthError> {
        let bytes = self
            .store
            .get(id)?
            .ok_or_else(|| HearthError::CommitNotFound(id.clone()))?;
        serde_json::from_slice(&bytes).map_err(|e| HearthError::Codec(e.to_string()))
    }

    /// Current tip commit of a branch (None if the branch doesn't exist).
    pub fn branch_tip(&self, branch: &str) -> Result<Option<Hash>, HearthError> {
        Ok(self
            .refs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .branches
            .get(branch)
            .cloned()
            .flatten())
    }

    /// Create a branch pointing at `from` (which may be None = empty).
    pub fn create_branch(&self, name: &str, from: Option<Hash>) -> Result<(), HearthError> {
        let mut refs = self.refs.lock().unwrap_or_else(|p| p.into_inner());
        if refs.branches.contains_key(name) {
            return Err(HearthError::BranchExists(name.to_string()));
        }
        refs.branches.insert(name.to_string(), from.clone());
        drop(refs);
        self.log_ref(&ReflogEntry {
            branch: name.to_string(),
            old: None,
            new: from,
            action: "create".into(),
            ts_ms: now_ms(),
        })?;
        self.persist_refs()
    }

    /// All branches with their tips.
    pub fn list_branches(&self) -> Result<Vec<(String, Hash)>, HearthError> {
        Ok(self
            .refs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .branches
            .iter()
            .filter_map(|(k, v)| v.clone().map(|h| (k.clone(), h)))
            .collect())
    }

    /// Delete a branch (its commits remain in the CAS).
    pub fn delete_branch(&self, name: &str) -> Result<(), HearthError> {
        let mut refs = self.refs.lock().unwrap_or_else(|p| p.into_inner());
        let old = refs
            .branches
            .remove(name)
            .ok_or_else(|| HearthError::BranchNotFound(name.to_string()))?;
        drop(refs);
        self.log_ref(&ReflogEntry {
            branch: name.to_string(),
            old,
            new: None,
            action: "delete".into(),
            ts_ms: now_ms(),
        })?;
        self.persist_refs()
    }

    fn update_ref(&self, branch: &str, new: Hash, action: &str) -> Result<(), HearthError> {
        let mut refs = self.refs.lock().unwrap_or_else(|p| p.into_inner());
        let old = refs
            .branches
            .insert(branch.to_string(), Some(new.clone()))
            .flatten();
        drop(refs);
        self.log_ref(&ReflogEntry {
            branch: branch.to_string(),
            old,
            new: Some(new),
            action: action.into(),
            ts_ms: now_ms(),
        })?;
        self.persist_refs()
    }

    fn persist_refs(&self) -> Result<(), HearthError> {
        let refs = self.refs.lock().unwrap_or_else(|p| p.into_inner());
        self.save_refs(&refs)
    }

    /// The shared CAS behind this Hearth (for materialization helpers).
    pub fn store_arc(&self) -> Arc<ContentStore> {
        Arc::clone(&self.store)
    }

    /// Walk a branch's first-parent history, newest first.
    pub fn log(&self, branch: &str) -> Result<Vec<(Hash, Commit)>, HearthError> {
        let mut out = Vec::new();
        let mut cur = self
            .branch_tip(branch)?
            .ok_or_else(|| HearthError::BranchNotFound(branch.to_string()))?;
        loop {
            let commit = self.read_commit(&cur)?;
            out.push((cur.clone(), commit.clone()));
            match commit.parent {
                Some(p) => cur = p,
                None => break,
            }
        }
        Ok(out)
    }

    /// The reflog (audit trail of pointer moves).
    pub fn reflog(&self) -> Result<Vec<ReflogEntry>, HearthError> {
        if !self.reflog_path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&self.reflog_path)?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line).map_err(|e| HearthError::Codec(e.to_string()))?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hearth(tag: &str) -> (Hearth, Arc<ContentStore>, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("hearth-cm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Arc::new(ContentStore::open(root.join("objects")).unwrap());
        (
            Hearth::open(&root, Arc::clone(&store)).unwrap(),
            store,
            root,
        )
    }

    #[test]
    fn commit_branch_log_roundtrip() {
        let (h, _s, root) = hearth("round");
        let t1 = h
            .snapshot(vec![("k".into(), h.write_blob(b"v1").unwrap())])
            .unwrap();
        let c1 = h.commit("main", &t1, "first").unwrap();
        let t2 = h
            .snapshot(vec![("k".into(), h.write_blob(b"v2").unwrap())])
            .unwrap();
        let c2 = h.commit("main", &t2, "second").unwrap();
        let lg = h.log("main").unwrap();
        assert_eq!(lg.len(), 2);
        assert_eq!(lg[0].0, c2);
        assert_eq!(lg[0].1.parent, Some(c1.clone()));
        assert_eq!(lg[1].0, c1);
        // branch from c1, independent tips
        h.create_branch("experiment", Some(c1.clone())).unwrap();
        assert_eq!(h.branch_tip("experiment").unwrap(), Some(c1));
        assert_eq!(h.branch_tip("main").unwrap(), Some(c2));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_branch_and_missing_commit() {
        let (h, _s, root) = hearth("dup");
        h.create_branch("b", None).unwrap();
        assert!(matches!(
            h.create_branch("b", None),
            Err(HearthError::BranchExists(_))
        ));
        let missing = "0".repeat(64);
        assert!(matches!(
            h.read_commit(&missing),
            Err(HearthError::CommitNotFound(_))
        ));
        assert!(matches!(h.log("nope"), Err(HearthError::BranchNotFound(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refs_survive_reopen_and_reflog_grows() {
        let (h, _s, root) = hearth("reopen");
        let t = h
            .snapshot(vec![("k".into(), h.write_blob(b"x").unwrap())])
            .unwrap();
        let _c = h.commit("main", &t, "m").unwrap();
        drop(h);
        let store = Arc::new(ContentStore::open(root.join("objects")).unwrap());
        let h2 = Hearth::open(&root, store).unwrap();
        assert!(h2.branch_tip("main").unwrap().is_some());
        assert_eq!(h2.reflog().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}
