//! **sieveplate-hearth** — the Hearth layer: versioned, content-addressed
//! state over the CAS.
//!
//! Two levels of change description, deliberately shaped alike:
//!
//! | view | API | granularity | typical question |
//! |---|---|---|---|
//! | branch level | [`Hearth::diff`] / [`Hearth::diff_branches`] | logical keys | "what changed between main and experiment?" |
//! | snapshot level | [`Hearth::ddiff`] / [`Hearth::apply_ddiff`] | bytes (copy/insert ops) | "how much of snapshot A survives in B?" |
//!
//! Everything immutable (blobs, trees, commits, deltas) lives in the CAS and
//! is verified on read; only branch pointers are mutable, and every pointer
//! move is recorded in an append-only reflog.

mod commit;
mod ddelta;
mod diff;
mod error;
mod tree;

pub use commit::{Commit, Hearth, ReflogEntry};
pub use ddelta::{
    apply as apply_delta_raw, ddiff as ddiff_streams, get_delta, put_delta, Delta, DeltaOp, BLOCK,
};
pub use diff::{apply_to_tree, diff_trees, invert, ChangeSet, Updated};
pub use error::HearthError;
pub use tree::{
    canonical_stream, get_tree, materialize, materialize as materialize_tree, put_tree, tree_hash,
    Materialized, Tree,
};

use sieveplate_store::{content_hash, ContentStore, Hash};
use std::sync::Arc;

impl Hearth {
    // Facade methods tying both views together (defined here to keep the
    // sub-modules focused on their own level).

    /// Logical diff between two tree hashes.
    pub fn diff(&self, a_tree: &str, b_tree: &str) -> Result<ChangeSet, HearthError> {
        let a = self.read_tree(&a_tree.to_string())?;
        let b = self.read_tree(&b_tree.to_string())?;
        Ok(diff_trees(&a, &b))
    }

    /// Logical diff between two branch tips.
    pub fn diff_branches(&self, a: &str, b: &str) -> Result<ChangeSet, HearthError> {
        let ta = self
            .branch_tip(a)?
            .ok_or_else(|| HearthError::BranchNotFound(a.to_string()))?;
        let tb = self
            .branch_tip(b)?
            .ok_or_else(|| HearthError::BranchNotFound(b.to_string()))?;
        let ca = self.read_commit(&ta)?;
        let cb = self.read_commit(&tb)?;
        self.diff(&ca.tree, &cb.tree)
    }

    /// Byte-level delta between two tree hashes, persisted as a CAS object.
    pub fn ddiff(&self, base_tree: &str, target_tree: &str) -> Result<(Hash, Delta), HearthError> {
        let base = self.read_tree(&base_tree.to_string())?;
        let target = self.read_tree(&target_tree.to_string())?;
        let base_stream = canonical_stream(&base, &self.store)?;
        let target_stream = canonical_stream(&target, &self.store)?;
        let delta = ddiff_streams(
            &base_stream,
            &sieveplate_store::content_hash(&base_stream),
            &target_stream,
            &sieveplate_store::content_hash(&target_stream),
        );
        let hash = put_delta(&self.store, &delta)?;
        Ok((hash, delta))
    }

    /// Apply a stored delta to a base tree, reconstructing (and verifying)
    /// the target tree hash. Returns the reconstructed tree hash.
    pub fn apply_ddiff(&self, base_tree: &str, delta_hash: &str) -> Result<Hash, HearthError> {
        let base = self.read_tree(&base_tree.to_string())?;
        let base_stream = canonical_stream(&base, &self.store)?;
        let delta = get_delta(&self.store, &delta_hash.to_string())?;
        if delta.base != sieveplate_store::content_hash(&base_stream) {
            return Err(HearthError::DeltaMismatch(
                delta.base.clone(),
                delta.target.clone(),
                "base tree does not match the delta's recorded base".into(),
            ));
        }
        let target_stream = apply_delta_raw(&base_stream, &delta)?;
        // The reconstructed stream must decode back into a tree whose
        // canonical stream re-hashes identically (round-trip guarantee).
        let tree = decode_stream(&target_stream, &self.store)?;
        let rebuilt = canonical_stream(&tree, &self.store)?;
        if content_hash(&rebuilt) != delta.target {
            return Err(HearthError::DeltaMismatch(
                delta.base.clone(),
                delta.target.clone(),
                "reconstructed stream does not re-encode to the recorded target".into(),
            ));
        }
        put_tree(&self.store, &tree)
    }
}

/// Decode a canonical stream (see [`canonical_stream`]) back into a tree,
/// putting every blob it references into the CAS.
pub fn decode_stream(stream: &[u8], store: &Arc<ContentStore>) -> Result<Tree, HearthError> {
    let mut tree = Tree::new();
    let mut pos = 0usize;
    let take = |s: &[u8], pos: &mut usize, n: usize| -> Result<Vec<u8>, HearthError> {
        if *pos + n > s.len() {
            return Err(HearthError::Codec("truncated stream".into()));
        }
        let out = s[*pos..*pos + n].to_vec();
        *pos += n;
        Ok(out)
    };
    while pos < stream.len() {
        let klen = u64::from_be_bytes(take(stream, &mut pos, 8)?.try_into().unwrap()) as usize;
        let key = String::from_utf8(take(stream, &mut pos, klen)?)
            .map_err(|_| HearthError::Codec("invalid key utf8".into()))?;
        let blen = u64::from_be_bytes(take(stream, &mut pos, 8)?.try_into().unwrap()) as usize;
        let blob = take(stream, &mut pos, blen)?;
        let h = store.put(&blob)?;
        tree.insert(key, h);
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieveplate_store::content_hash;

    fn hearth(tag: &str) -> (Hearth, Arc<ContentStore>, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("hearth-lib-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Arc::new(ContentStore::open(root.join("objects")).unwrap());
        (
            Hearth::open(&root, Arc::clone(&store)).unwrap(),
            store,
            root,
        )
    }

    #[test]
    fn facade_diff_and_ddiff_end_to_end() {
        let (h, _s, root) = hearth("facade");
        let big: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let b1 = h.write_blob(&big).unwrap();
        let b1b = h.write_blob(&big[512..]).unwrap();
        let ta = h
            .snapshot(vec![
                ("a".into(), b1.clone()),
                ("b".into(), h.write_blob(b"v1").unwrap()),
            ])
            .unwrap();
        let tb = h
            .snapshot(vec![
                ("a".into(), b1b),
                ("c".into(), h.write_blob(b"new").unwrap()),
            ])
            .unwrap();
        // logical
        let cs = h.diff(&ta, &tb).unwrap();
        assert_eq!(cs.added.len(), 1);
        assert_eq!(cs.added[0].key, "c");
        assert_eq!(cs.removed.len(), 1);
        assert_eq!(cs.removed[0].key, "b");
        assert_eq!(cs.updated.len(), 1);
        // byte-level
        let (dh, delta) = h.ddiff(&ta, &tb).unwrap();
        let rebuilt = h.apply_ddiff(&ta, &dh).unwrap();
        assert_eq!(rebuilt, tb);
        // a fresh tree object for the rebuilt hash equals the original tree
        let tree = h.read_tree(&rebuilt).unwrap();
        let stream = canonical_stream(&tree, &_s).unwrap();
        assert_eq!(content_hash(&stream), delta.target);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ddiff_on_wrong_base_is_rejected() {
        let (h, _s, root) = hearth("mismatch");
        let t1 = h
            .snapshot(vec![("a".into(), h.write_blob(b"1").unwrap())])
            .unwrap();
        let t2 = h
            .snapshot(vec![("a".into(), h.write_blob(b"2").unwrap())])
            .unwrap();
        let t3 = h
            .snapshot(vec![("a".into(), h.write_blob(b"3").unwrap())])
            .unwrap();
        let (dh, _d) = h.ddiff(&t1, &t2).unwrap();
        // applying to a different base must fail the base check
        assert!(h.apply_ddiff(&t3, &dh).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
