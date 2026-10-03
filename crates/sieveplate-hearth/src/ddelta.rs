//! Byte-level delta — the snapshot-level view of change (`ddiff`).
//!
//! Where [`crate::diff`] answers "which keys changed" between two branches,
//! `ddiff` answers "which bytes can be reused" between two *snapshots*. It
//! chunk-matches the canonical byte streams (rsync-style fixed blocks) and
//! emits a [`Delta`] of `Copy`/`Insert` ops that reconstructs the target
//! stream exactly. Deltas are content-addressed objects like everything else
//! in Hearth, and `apply` verifies the reconstructed hash — a wrong or
//! tampered delta cannot materialize silently.

use serde::{Deserialize, Serialize};
use sieveplate_store::{content_hash, ContentStore, Hash};

use crate::error::HearthError;

/// Block size for byte matching (bytes). Small enough that a single edited
/// byte invalidates at most the block containing it plus one match window.
pub const BLOCK: usize = 256;

/// One delta operation: reuse `len` bytes from `offset` in the base stream,
/// or insert literal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaOp {
    Copy { offset: u64, len: u32 },
    Insert { data: Vec<u8> },
}

/// A byte-level delta between two canonical snapshot streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    /// Content hash of the base snapshot's canonical stream.
    pub base: Hash,
    /// Content hash of the target snapshot's canonical stream.
    pub target: Hash,
    pub ops: Vec<DeltaOp>,
}

impl Delta {
    /// Bytes the target stream borrows from the base (copy coverage).
    pub fn copied_bytes(&self) -> u64 {
        self.ops
            .iter()
            .map(|op| match op {
                DeltaOp::Copy { len, .. } => *len as u64,
                DeltaOp::Insert { .. } => 0,
            })
            .sum()
    }

    /// Bytes the delta itself carries (insert payload + encoding overhead
    /// of the ops list).
    pub fn carried_bytes(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match op {
                DeltaOp::Copy { .. } => 16,
                DeltaOp::Insert { data } => data.len() + 8,
            })
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

fn block_key(block: &[u8]) -> u64 {
    // FNV-1a 64 — deterministic, cheap, non-cryptographic (the delta is
    // verified by content hash on apply, so this only guides matching).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in block {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Compute the delta `base_stream → target_stream`.
///
/// Both streams are the canonical encodings of the two snapshots (see
/// [`crate::tree::canonical_stream`]); `base_hash`/`target_hash` are their
/// content hashes, stored in the delta and re-checked on apply.
pub fn ddiff(
    base_stream: &[u8],
    base_hash: &Hash,
    target_stream: &[u8],
    target_hash: &Hash,
) -> Delta {
    let mut ops: Vec<DeltaOp> = Vec::new();
    if base_hash == target_hash {
        return Delta {
            base: base_hash.clone(),
            target: target_hash.clone(),
            ops,
        };
    }
    // Index aligned blocks of the base stream.
    let mut index: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    let mut off = 0usize;
    while off + BLOCK <= base_stream.len() {
        index
            .entry(block_key(&base_stream[off..off + BLOCK]))
            .or_default()
            .push(off as u64);
        off += BLOCK;
    }
    // Greedy scan of the target stream.
    let mut insert_buf: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let flush = |insert_buf: &mut Vec<u8>, ops: &mut Vec<DeltaOp>| {
        if !insert_buf.is_empty() {
            ops.push(DeltaOp::Insert {
                data: std::mem::take(insert_buf),
            });
        }
    };
    while pos < target_stream.len() {
        let remaining = target_stream.len() - pos;
        if remaining >= BLOCK {
            let key = block_key(&target_stream[pos..pos + BLOCK]);
            if let Some(offsets) = index.get(&key) {
                if let Some(&boff) = offsets.first() {
                    flush(&mut insert_buf, &mut ops);
                    ops.push(DeltaOp::Copy {
                        offset: boff,
                        len: BLOCK as u32,
                    });
                    pos += BLOCK;
                    continue;
                }
            }
        }
        insert_buf.push(target_stream[pos]);
        pos += 1;
    }
    flush(&mut insert_buf, &mut ops);
    Delta {
        base: base_hash.clone(),
        target: target_hash.clone(),
        ops,
    }
}

/// Apply a delta to a base stream; verifies the reconstruction matches the
/// delta's recorded target hash.
pub fn apply(base_stream: &[u8], delta: &Delta) -> Result<Vec<u8>, HearthError> {
    // Identical snapshots: empty delta means "no change" — return the base.
    if delta.ops.is_empty() && delta.base == delta.target {
        return Ok(base_stream.to_vec());
    }
    let mut out = Vec::with_capacity(base_stream.len());
    for op in &delta.ops {
        match op {
            DeltaOp::Copy { offset, len } => {
                let start = *offset as usize;
                let end = start + *len as usize;
                if end > base_stream.len() {
                    return Err(HearthError::DeltaMismatch(
                        delta.base.clone(),
                        delta.target.clone(),
                        format!(
                            "copy range {start}..{end} exceeds base len {}",
                            base_stream.len()
                        ),
                    ));
                }
                out.extend_from_slice(&base_stream[start..end]);
            }
            DeltaOp::Insert { data } => out.extend_from_slice(data),
        }
    }
    let got = content_hash(&out);
    if got != delta.target {
        return Err(HearthError::DeltaMismatch(
            delta.base.clone(),
            delta.target.clone(),
            format!("reconstructed {got}, expected {}", delta.target),
        ));
    }
    Ok(out)
}

/// Persist a delta object into the CAS; returns its hash.
pub fn put_delta(store: &ContentStore, delta: &Delta) -> Result<Hash, HearthError> {
    let bytes = bincode::serialize(delta).map_err(|e| HearthError::Codec(e.to_string()))?;
    Ok(store.put(&bytes)?)
}

/// Read a delta object from the CAS.
pub fn get_delta(store: &ContentStore, hash: &Hash) -> Result<Delta, HearthError> {
    let bytes = store
        .get(hash)?
        .ok_or_else(|| HearthError::TreeNotFound(hash.clone()))?;
    bincode::deserialize(&bytes).map_err(|e| HearthError::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(tree: &[(&str, &[u8])]) -> (Vec<u8>, Hash) {
        let mut out = Vec::new();
        for (k, v) in tree {
            out.extend_from_slice(&(k.len() as u64).to_be_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&(v.len() as u64).to_be_bytes());
            out.extend_from_slice(v);
        }
        let h = content_hash(&out);
        (out, h)
    }

    #[test]
    fn identical_snapshots_empty_delta() {
        let (s, h) = stream(&[("a", b"1"), ("b", b"2")]);
        let d = ddiff(&s, &h, &s, &h);
        assert!(d.is_empty());
        assert_eq!(apply(&s, &d).unwrap(), s);
    }

    #[test]
    fn similar_snapshots_mostly_copy() {
        // One 1 KiB blob, then a small edit at the end.
        let blob1 = vec![7u8; 1024];
        let mut blob2 = blob1.clone();
        blob2.extend_from_slice(b"appended-tail");
        let (base, bh) = stream(&[("big", &blob1), ("meta", b"v1")]);
        let (target, th) = stream(&[("big", &blob2), ("meta", b"v2")]);
        let d = ddiff(&base, &bh, &target, &th);
        // The large unchanged region must be copies, not inserts.
        assert!(d.copied_bytes() >= 768, "copied={}", d.copied_bytes());
        // Round trip is exact.
        assert_eq!(apply(&base, &d).unwrap(), target);
        // Delta is much smaller than the target stream.
        assert!(d.carried_bytes() < target.len() / 2);
    }

    #[test]
    fn tampered_delta_fails_hash_check() {
        let (base, bh) = stream(&[("a", b"hello-world-0123456789")]);
        let (target, th) = stream(&[("a", b"hello-world-0123456789!"), ("b", b"x")]);
        let mut d = ddiff(&base, &bh, &target, &th);
        assert_eq!(apply(&base, &d).unwrap(), target);
        // Tamper: an op claiming a copy beyond the base length.
        d.ops.push(DeltaOp::Copy {
            offset: base.len() as u64,
            len: 10,
        });
        assert!(apply(&base, &d).is_err());
    }

    #[test]
    fn disjoint_snapshots_full_insert() {
        let (base, bh) = stream(&[("a", b"aaaaaaaaaaaaaaaaaaaaaaaa")]);
        let (target, th) = stream(&[("z", b"zzzzzzzzzzzzzzzzzzzzzzzz")]);
        let d = ddiff(&base, &bh, &target, &th);
        assert_eq!(d.copied_bytes(), 0);
        assert_eq!(apply(&base, &d).unwrap(), target);
    }
}
