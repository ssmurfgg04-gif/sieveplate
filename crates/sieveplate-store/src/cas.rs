//! Content-addressable storage (CAS).
//!
//! Every object is immutable and identified by the SHA-256 of its bytes.
//! This is the foundation of the L3 "Memory": actor snapshots, system plans
//! and cell templates all live here, so any state in the system can be
//! addressed, verified and restored by a single hash.
//!
//! Write path: write-to-temp → fsync → atomic rename → verify-on-read.
//! Corruption is detected on read because every get() re-hashes the object.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::StoreError;

/// A content hash: lowercase hex SHA-256 (64 chars).
pub type Hash = String;

/// Compute the SHA-256 content hash of `data`.
pub fn content_hash(data: &[u8]) -> Hash {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Statistics returned by [`ContentStore::stats`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreStats {
    pub objects: u64,
    pub bytes: u64,
}

/// A filesystem-backed, content-addressed object store.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self { root })
    }

    /// Store `data`, returning its content hash. Idempotent: putting the
    /// same bytes twice is a no-op the second time.
    pub fn put(&self, data: &[u8]) -> Result<Hash, StoreError> {
        let hash = content_hash(data);
        let obj_path = self.object_path(&hash);
        if obj_path.exists() {
            return Ok(hash);
        }

        // Write to a unique temp file, fsync, then atomically rename.
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.{}", std::process::id(), unique_suffix()));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&tmp, &obj_path)?;
        Ok(hash)
    }

    /// Fetch the object stored under `hash`, verifying integrity on read.
    /// Returns `Ok(None)` when the object is absent.
    pub fn get(&self, hash: &str) -> Result<Option<Vec<u8>>, StoreError> {
        if !is_valid_hash(hash) {
            return Err(StoreError::MalformedHash(hash.to_string()));
        }
        let path = self.object_path(hash);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(&path)?;
        let actual = content_hash(&data);
        if actual != hash {
            return Err(StoreError::Integrity {
                expected: hash.to_string(),
                found: actual,
            });
        }
        Ok(Some(data))
    }

    /// Does an object with this hash exist?
    pub fn has(&self, hash: &str) -> bool {
        is_valid_hash(hash) && self.object_path(hash).exists()
    }

    /// Delete an object. Returns true if it existed.
    pub fn delete(&self, hash: &str) -> Result<bool, StoreError> {
        if !is_valid_hash(hash) {
            return Ok(false);
        }
        Ok(fs::remove_file(self.object_path(hash)).is_ok())
    }

    /// Remove every object not listed in `reachable`. Returns count removed.
    pub fn gc<I: IntoIterator<Item = Hash>>(&self, reachable: I) -> Result<usize, StoreError> {
        let mut keep: std::collections::HashSet<Hash> = reachable.into_iter().collect();
        let mut removed = 0usize;
        for (full, path) in walk_objects(&self.root.join("objects"))? {
            if !keep.remove(&full) {
                let _ = fs::remove_file(&path);
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Object count + total bytes.
    pub fn stats(&self) -> Result<StoreStats, StoreError> {
        let mut objects = 0u64;
        let mut bytes = 0u64;
        for (_, entry) in walk_objects(&self.root.join("objects"))? {
            if let Ok(md) = fs::metadata(&entry) {
                objects += 1;
                bytes += md.len();
            }
        }
        Ok(StoreStats { objects, bytes })
    }

    /// All hashes currently stored (used by `sieve store gc`).
    pub fn list(&self) -> Result<Vec<Hash>, StoreError> {
        Ok(walk_objects(&self.root.join("objects"))?
            .into_iter()
            .map(|(full, _)| full)
            .filter(|s| is_valid_hash(s))
            .collect())
    }

    fn object_path(&self, hash: &str) -> PathBuf {
        // 2-char fan-out keeps directories small, git-style.
        self.root.join("objects").join(&hash[..2]).join(&hash[2..])
    }
}

fn is_valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unique_suffix() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    now.wrapping_add(c)
}

fn walk_objects(dir: &Path) -> Result<Vec<(String, PathBuf)>, StoreError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for sub in fs::read_dir(dir)? {
        let sub = sub?.path();
        if !sub.is_dir() {
            continue;
        }
        let prefix = sub
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        for f in fs::read_dir(&sub)? {
            let p = f?.path();
            if p.is_file() {
                let suffix = p
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                out.push((format!("{prefix}{suffix}"), p));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip_and_verify() {
        let dir = std::env::temp_dir().join(format!("sp-cas-{}", unique_suffix()));
        let store = ContentStore::open(&dir).unwrap();
        let data = b"hello sieveplate";
        let h = store.put(data).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(store.get(&h).unwrap().unwrap(), data);
        // idempotent
        assert_eq!(store.put(data).unwrap(), h);
        // integrity: corrupt and expect error
        let obj = dir.join("objects").join(&h[..2]).join(&h[2..]);
        std::fs::write(&obj, b"tampered").unwrap();
        assert!(store.get(&h).is_err());
        assert!(store.delete(&h).unwrap());
        assert!(store.get(&h).unwrap().is_none());
    }

    #[test]
    fn gc_removes_unreachable() {
        let dir = std::env::temp_dir().join(format!("sp-gc-{}", unique_suffix()));
        let store = ContentStore::open(&dir).unwrap();
        let h1 = store.put(b"keep me").unwrap();
        let _h2 = store.put(b"drop me").unwrap();
        let removed = store.gc([h1.clone()]).unwrap();
        assert_eq!(removed, 1);
        assert!(store.has(&h1));
    }
}
