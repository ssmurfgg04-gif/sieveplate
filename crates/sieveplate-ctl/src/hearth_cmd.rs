//! `sieve hearth` — the versioning layer, on the command line.
//!
//! Snapshots are `key=blobhash` trees; commits pin a tree on a branch;
//! `diff` describes branch-level change (logical keys); `ddiff` describes
//! snapshot-level change (byte-level copy/insert delta). Both live in the
//! CAS and verify on read.

use anyhow::Result;
use sieveplate_hearth::Hearth;
use sieveplate_store::ContentStore;
use std::sync::Arc;

fn open(root: &str) -> Result<(Hearth, Arc<ContentStore>)> {
    let store = Arc::new(ContentStore::open(format!("{root}/objects"))?);
    Ok((
        Hearth::open(format!("{root}/runtime"), store.clone())?,
        store,
    ))
}

/// `sieve hearth write KEY --text T | --file F`: put a blob, print its hash.
pub fn write(root: &str, key: &str, text: &Option<String>, file: &Option<String>) -> Result<()> {
    let (h, _store) = open(root)?;
    let data = match (text, file) {
        (Some(t), _) => t.clone().into_bytes(),
        (None, Some(f)) => std::fs::read(f)?,
        _ => anyhow::bail!("need --text or --file"),
    };
    let hash = h.write_blob(&data)?;
    println!("{key}\t{hash}");
    Ok(())
}

/// `sieve hearth snapshot BRANCH key=hash ... --message M`: commit a tree.
pub fn snapshot(root: &str, branch: &str, entries: &[String], message: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    let mut list = Vec::new();
    for e in entries {
        let (k, v) = e
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("entry '{e}' must be key=blobhash"))?;
        list.push((k.to_string(), v.to_string()));
    }
    let tree = h.snapshot(list)?;
    let commit = h.commit(branch, &tree, message)?;
    println!("tree   {tree}");
    println!("commit {commit}");
    Ok(())
}

/// `sieve hearth branches`
pub fn branches(root: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    for (name, tip) in h.list_branches()? {
        println!("{name}\t{tip}");
    }
    Ok(())
}

/// `sieve hearth log BRANCH`
pub fn log(root: &str, branch: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    for (id, c) in h.log(branch)? {
        println!(
            "{}\t{}\t{}\t{}",
            &id[..12.min(id.len())],
            c.ts_ms,
            c.branch,
            c.message
        );
    }
    Ok(())
}

/// `sieve hearth diff BRANCH_A BRANCH_B`
pub fn diff(root: &str, a: &str, b: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    let cs = h.diff_branches(a, b)?;
    for l in cs.summary() {
        println!("{l}");
    }
    println!(
        "--- {} change(s): {} added, {} removed, {} updated",
        cs.total_changes(),
        cs.added.len(),
        cs.removed.len(),
        cs.updated.len()
    );
    Ok(())
}

/// `sieve hearth ddiff TREE_A TREE_B`: byte-level delta between snapshots.
pub fn ddiff(root: &str, a: &str, b: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    let (delta_hash, delta) = h.ddiff(a, b)?;
    let target_bytes = delta.copied_bytes();
    println!("delta   {delta_hash}");
    println!("ops     {}", delta.ops.len());
    println!("copied  {target_bytes} bytes reused from base");
    println!("carried {} bytes of literal payload", delta.carried_bytes());
    Ok(())
}

/// `sieve hearth apply-delta BASE_TREE DELTA_HASH`: reconstruct + verify.
pub fn apply_delta(root: &str, base: &str, delta_hash: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    let rebuilt = h.apply_ddiff(base, delta_hash)?;
    println!("rebuilt {rebuilt}");
    Ok(())
}

/// `sieve hearth checkout COMMIT --out DIR`: materialize a snapshot.
pub fn checkout(root: &str, commit_hash: &str, out: &str) -> Result<()> {
    let (h, _s) = open(root)?;
    let commit = h.read_commit(&commit_hash.to_string())?;
    let tree = h.read_tree(&commit.tree)?;
    let materialized = sieveplate_hearth::materialize_tree(&tree, &h.store_arc())?;
    std::fs::create_dir_all(out)?;
    for (key, data) in &materialized.0 {
        let path = std::path::Path::new(out).join(key.replace('/', "_"));
        std::fs::write(path, data)?;
    }
    println!("checked out {} keys into {out}", materialized.0.len());
    Ok(())
}
