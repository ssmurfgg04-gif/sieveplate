//! Snapshot trees — the logical structure of a Hearth snapshot.
//!
//! A snapshot is a map `key → blob hash`, stored as one content-addressed
//! JSON object (keys sorted, so identical trees hash identically). Blobs
//! live in the CAS; every read verifies content, so a corrupted blob is
//! detected the moment a snapshot is materialized.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sieveplate_store::{content_hash, ContentStore, Hash};

use crate::error::HearthError;

/// One entry of a snapshot: a logical key pointing at a blob.
pub type Tree = BTreeMap<String, Hash>;

/// Serialize a tree into its canonical byte stream.
///
/// Format: for every key in sorted order — `u64 len(key) | key | u64 len(blob) | blob`.
/// This is the byte stream that [`crate::ddelta`] diffs (snapshot level),
/// while [`crate::diff`] walks the *structure* (branch level). Both views
/// address the same snapshot.
pub fn canonical_stream(tree: &Tree, store: &ContentStore) -> Result<Vec<u8>, HearthError> {
    let mut out = Vec::new();
    for (key, hash) in tree {
        out.extend_from_slice(&(key.len() as u64).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        let blob = store
            .get(hash)?
            .ok_or_else(|| HearthError::TreeNotFound(hash.clone()))?;
        out.extend_from_slice(&(blob.len() as u64).to_be_bytes());
        out.extend_from_slice(&blob);
    }
    Ok(out)
}

/// Persist a tree object; returns its content hash.
pub fn put_tree(store: &Arc<ContentStore>, tree: &Tree) -> Result<Hash, HearthError> {
    // BTreeMap iterates in sorted order: canonical.
    let json = serde_json::to_vec(tree).map_err(|e| HearthError::Codec(e.to_string()))?;
    Ok(store.put(&json)?)
}

/// Read and validate a tree object.
pub fn get_tree(store: &Arc<ContentStore>, hash: &Hash) -> Result<Tree, HearthError> {
    let bytes = store
        .get(hash)?
        .ok_or_else(|| HearthError::TreeNotFound(hash.clone()))?;
    serde_json::from_slice(&bytes).map_err(|e| HearthError::Codec(e.to_string()))
}

/// Content hash of a tree without persisting it (used in tests).
pub fn tree_hash(tree: &Tree) -> Hash {
    let json = serde_json::to_vec(tree).unwrap_or_default();
    content_hash(&json)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A materialized snapshot: keys with their full bytes.
pub struct Materialized(pub BTreeMap<String, Vec<u8>>);

/// Materialize a snapshot: fetch + verify every blob.
pub fn materialize(tree: &Tree, store: &Arc<ContentStore>) -> Result<Materialized, HearthError> {
    let mut out = BTreeMap::new();
    for (key, hash) in tree {
        let blob = store
            .get(hash)?
            .ok_or_else(|| HearthError::TreeNotFound(hash.clone()))?;
        out.insert(key.clone(), blob);
    }
    Ok(Materialized(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> Arc<ContentStore> {
        let dir = std::env::temp_dir().join(format!("hearth-tree-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(ContentStore::open(dir).unwrap())
    }

    #[test]
    fn tree_roundtrip_is_canonical() {
        let store = tmp_store("rt");
        let h1 = store.put(b"one").unwrap();
        let h2 = store.put(b"two").unwrap();
        let t1: Tree = BTreeMap::from([("a".into(), h1.clone()), ("b".into(), h2.clone())]);
        // Same tree built in any order hashes identically.
        let t2: Tree = BTreeMap::from([("b".into(), h2.clone()), ("a".into(), h1.clone())]);
        assert_eq!(tree_hash(&t1), tree_hash(&t2));
        let th = put_tree(&store, &t1).unwrap();
        let back = get_tree(&store, &th).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(tree_hash(&back), tree_hash(&t1));
    }

    #[test]
    fn materialize_detects_corrupted_blob() {
        // Corruption is detected by the CAS verify-on-read: write a blob,
        // flip a byte on disk, then materialize must fail.
        let root = std::env::temp_dir().join(format!("hearth-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Arc::new(ContentStore::open(&root).unwrap());
        let h = store.put(b"payload-bytes").unwrap();
        let tree: Tree = BTreeMap::from([("k".into(), h.clone())]);
        // Corrupt the object on disk (2-char fan-out layout).
        let hash = sieveplate_store::content_hash(b"payload-bytes");
        let obj = root.join("objects").join(&hash[..2]).join(&hash[2..]);
        let mut data = std::fs::read(&obj).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xff;
        std::fs::write(&obj, &data).unwrap();
        // get() must refuse (verify-on-read).
        assert!(store.get(&h).is_err());
        // And materialize surfaces it.
        assert!(materialize(&tree, &store).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
