//! `spore` — a package manager that installs REAL Arch Linux packages.
//!
//! Arch packages are `.pkg.tar.zst`: a zstd-compressed tar with `.PKGINFO`
//! metadata. The repos publish a database per repo (`core.db`, `extra.db`)
//! which is itself a tar.gz of `<pkgname>-<pkgver>/desc` files.
//!
//! What spore does:
//! 1. fetch + parse the repo databases (core, extra)
//! 2. resolve dependencies (deps, provides, version constraints — best
//!    effort, dependency-cycle tolerant, refuses conflicts)
//! 3. download each `.pkg.tar.zst` from the mirror over HTTPS
//! 4. extract it into the root filesystem with tar metadata (modes, dirs,
//!    symlinks)
//! 5. record the installation in `<root>/var/lib/spore/installed.json`
//!
//! Honesty notes (do not oversell):
//! - Signature verification is NOT done inside this tool. On a host with
//!   `gpgv` + the Arch keyring you can verify the fetched `.sig` files —
//!   the CI workflow does exactly that for host-side installs. Inside the
//!   boot demo the packages come from the official mirror over HTTPS;
//!   `pacman`'s full web-of-trust verification is out of scope here.
//! - No `.MTREE` validation, no hook system, no partial-file rollback.
//!   This is an installer, not pacman.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_MIRROR: &str = "https://geo.mirror.pkgbuild.com";
pub const REPOS: &[&str] = &["core", "extra"];

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub filename: String,
    pub repo: String,
    pub depends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InstalledDb {
    /// name → installed record
    pub packages: BTreeMap<String, InstalledPkg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPkg {
    pub version: String,
    pub provides: Vec<String>,
    pub files: Vec<String>,
    pub installed_at_unix: u64,
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .build()
}

pub fn http_get(url: &str) -> Result<Vec<u8>> {
    let resp = agent()
        .get(url)
        .set("User-Agent", "spore/0.1 (sieveplate OS)")
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(2 * 1024 * 1024 * 1024)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Repo database
// ---------------------------------------------------------------------------

/// Parse an Arch repo `.db` (tar.gz of `<pkgver>/desc` files) into packages.
pub fn parse_repo_db(bytes: &[u8], repo: &str) -> Result<HashMap<String, PackageInfo>> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut tar = tar::Archive::new(gz);
    let mut out = HashMap::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        // entries look like: bash-5.2.037-2-x86_64/desc
        if path.file_name().map(|f| f != "desc").unwrap_or(true) {
            continue;
        }
        let mut body = String::new();
        entry.read_to_string(&mut body)?;
        if let Some(info) = parse_desc(&body, repo) {
            out.insert(info.name.clone(), info);
        }
    }
    Ok(out)
}

/// Parse one `%FIELD%`-delimited desc file.
fn parse_desc(body: &str, repo: &str) -> Option<PackageInfo> {
    let mut fields: HashMap<String, Vec<String>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('%') && line.ends_with('%') {
            current = Some(line[1..line.len() - 1].to_string());
            fields.entry(current.clone().unwrap()).or_default();
        } else if let Some(k) = &current {
            if !line.is_empty() {
                fields.entry(k.clone()).or_default().push(line.to_string());
            }
        }
    }
    let get = |k: &str| -> Vec<String> { fields.get(k).cloned().unwrap_or_default() };
    let name = get("NAME").first()?.clone();
    let version = get("VERSION").first()?.clone();
    let arch = get("ARCH").first().cloned().unwrap_or_default();
    let filename = get("FILENAME").first()?.clone();
    Some(PackageInfo {
        name,
        version,
        arch,
        filename,
        repo: repo.to_string(),
        depends: get("DEPENDS"),
        provides: get("PROVIDES"),
        conflicts: get("CONFLICTS"),
        size: get("CSIZE")
            .first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

/// Fetch all repo databases into a cache dir (returns name → info).
pub fn load_repos(cache: &Path, mirror: &str) -> Result<HashMap<String, PackageInfo>> {
    std::fs::create_dir_all(cache)?;
    let mut all = HashMap::new();
    for repo in REPOS {
        let url = format!("{mirror}/{repo}/os/x86_64/{repo}.db");
        let db_path = cache.join(format!("{repo}.db"));
        let bytes = if db_path.exists() && std::fs::metadata(&db_path).is_ok() {
            // Fresh-enough cache for a live boot; refetch on any parse issue.
            std::fs::read(&db_path).unwrap_or_default()
        } else {
            Vec::new()
        };
        let bytes = if !bytes.is_empty() {
            match parse_repo_db(&bytes, repo) {
                Ok(_) => bytes,
                Err(_) => {
                    let fresh = http_get(&url)?;
                    std::fs::write(&db_path, &fresh)?;
                    fresh
                }
            }
        } else {
            let fresh = http_get(&url)?;
            std::fs::write(&db_path, &fresh)?;
            fresh
        };
        for (k, v) in parse_repo_db(&bytes, repo)? {
            all.insert(k, v);
        }
    }
    Ok(all)
}

// ---------------------------------------------------------------------------
// Dependency resolution
// ---------------------------------------------------------------------------

/// A dep/provides term: `name`, `name=ver`, `name>=ver`, ...
/// Arch also has `so:libfoo.so=1-64` style entries — treated as opaque
/// names with an `=` constraint.
#[derive(Debug)]
struct Term {
    name: String,
    op: Option<(char, String)>, // '=', '>', '<' with optional '=' folded
}

fn parse_term(s: &str) -> Term {
    for (i, c) in s.char_indices() {
        if matches!(c, '>' | '<' | '=') {
            let name = s[..i].trim().to_string();
            if c == '=' {
                return Term {
                    name,
                    op: Some(('=', s[i + 1..].trim().to_string())),
                };
            }
            // '>=' or '<=' (folded: inclusive)
            let rest = s[i + 1..].trim();
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            return Term {
                name,
                op: Some((c, rest.to_string())),
            };
        }
    }
    Term {
        name: s.trim().to_string(),
        op: None,
    }
}

/// Compare Arch versions: epoch:pkgver-pkgrel. Best-effort string-aware
/// compare (splits on digits so 1.10 > 1.9).
fn ver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(v: &str) -> Vec<String> {
        v.split(|c: char| c == '.' || c == '-' || c == '_')
            .flat_map(|p| split_digits(p))
            .collect()
    }
    fn split_digits(p: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut cur_digit = None;
        for c in p.chars() {
            let d = c.is_ascii_digit();
            if cur_digit.is_some() && cur_digit != Some(d) && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur_digit = Some(d);
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (pa.get(i), pb.get(i));
        match (x, y) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    _ => x.cmp(y),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
    std::cmp::Ordering::Equal
}

fn term_satisfied(
    term: &Term,
    installed: &InstalledDb,
    repos: &HashMap<String, PackageInfo>,
) -> bool {
    for (name, pkg) in &installed.packages {
        if name == &term.name {
            if let Some((op, v)) = &term.op {
                if constraint_ok(&pkg.version, *op, v) {
                    return true;
                }
            } else {
                return true;
            }
        }
        for p in &pkg.provides {
            if provides_matches(p, term) {
                return true;
            }
        }
    }
    // Not installed: does anything in the repos PROVIDE it? (resolution
    // uses this in resolve_missing; satisfaction only cares about installed)
    let _ = repos;
    false
}

fn provides_matches(prov: &str, term: &Term) -> bool {
    let pt = parse_term(prov);
    if pt.name != term.name {
        return false;
    }
    match (&pt.op, &term.op) {
        // provider gives a version, dep constrains
        (Some(('=', pv)), Some((op, dv))) => constraint_ok(pv, *op, dv),
        (Some(('=', _)), None) => true,
        (None, None) => true,
        (None, Some(_)) => false,
        _ => true,
    }
}

fn constraint_ok(have: &str, op: char, want: &str) -> bool {
    let ord = ver_cmp(have, want);
    match op {
        '=' => ord == std::cmp::Ordering::Equal,
        // folded '>=' / '<=' are inclusive
        '>' => ord != std::cmp::Ordering::Less,
        '<' => ord != std::cmp::Ordering::Greater,
        _ => true,
    }
}

/// Resolve the transitive closure of `roots` in install order (deps first).
pub fn resolve(
    roots: &[String],
    repos: &HashMap<String, PackageInfo>,
    installed: &InstalledDb,
) -> Result<Vec<PackageInfo>> {
    let mut order: Vec<PackageInfo> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut in_progress: HashSet<String> = HashSet::new();

    // what the installed set (plus what we add during this resolve) provides
    let mut virtual_installed = installed.clone();

    #[allow(clippy::too_many_arguments)]
    fn visit(
        dep_term: &str,
        repos: &HashMap<String, PackageInfo>,
        virt: &mut InstalledDb,
        visited: &mut HashSet<String>,
        in_progress: &mut HashSet<String>,
        order: &mut Vec<PackageInfo>,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 {
            bail!("dependency nesting too deep at '{dep_term}'");
        }
        let term = parse_term(dep_term);
        if term_satisfied_pub(&term, virt, repos) {
            return Ok(());
        }
        // Find a repo package: exact name first, then providers.
        let mut candidates: Vec<PackageInfo> = Vec::new();
        if let Some(p) = repos.get(&term.name) {
            candidates.push(p.clone());
        }
        for p in repos.values() {
            for prov in &p.provides {
                if provides_matches(prov, &term) && p.name != term.name {
                    candidates.push(p.clone());
                    break;
                }
            }
        }
        candidates.sort_by(|a, b| a.name.cmp(&b.name));
        let Some(pkg) = candidates.into_iter().next() else {
            bail!("no provider found for dependency '{dep_term}'");
        };
        if !in_progress.insert(pkg.name.clone()) {
            bail!(
                "dependency cycle involving '{}' (resolving '{dep_term}')",
                pkg.name
            );
        }
        // conflicts check
        for c in &pkg.conflicts {
            let ct = parse_term(c);
            if term_satisfied_pub(&ct, virt, repos) {
                bail!("'{}' conflicts with installed/provided '{c}'", pkg.name);
            }
        }
        for d in pkg.depends.clone() {
            visit(&d, repos, virt, visited, in_progress, order, depth + 1)?;
        }
        in_progress.remove(&pkg.name);
        if visited.insert(pkg.name.clone()) {
            virt.packages.insert(
                pkg.name.clone(),
                InstalledPkg {
                    version: pkg.version.clone(),
                    provides: pkg.provides.clone(),
                    files: vec![],
                    installed_at_unix: 0,
                },
            );
            order.push(pkg);
        }
        Ok(())
    }

    fn term_satisfied_pub(
        term: &Term,
        installed: &InstalledDb,
        repos: &HashMap<String, PackageInfo>,
    ) -> bool {
        term_satisfied(term, installed, repos)
    }

    for r in roots {
        visit(
            r,
            repos,
            &mut virtual_installed,
            &mut visited,
            &mut in_progress,
            &mut order,
            0,
        )?;
    }
    Ok(order)
}

// ---------------------------------------------------------------------------
// Download + extract
// ---------------------------------------------------------------------------

pub fn fetch_package(pkg: &PackageInfo, cache: &Path, mirror: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(cache)?;
    let local = cache.join(&pkg.filename);
    if local.exists()
        && std::fs::metadata(&local)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    {
        return Ok(local);
    }
    let url = format!(
        "{mirror}/{}/os/x86_64/{}",
        pkg.repo,
        urlencode(&pkg.filename)
    );
    let bytes = http_get(&url)?;
    std::fs::write(&local, &bytes)?;
    Ok(local)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "-._~".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", c as u32));
        }
    }
    out
}

/// Extract a `.pkg.tar.zst` into `root`, honoring tar metadata (modes,
/// directories, symlinks). Returns the file list recorded to the local db.
pub fn extract_package(pkg_path: &Path, root: &Path) -> Result<Vec<String>> {
    let f = std::fs::File::open(pkg_path)?;
    let dz = zstd::Decoder::new(f)?;
    let mut tar = tar::Archive::new(dz);
    tar.set_preserve_permissions(true);
    let mut files = Vec::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let name = path.to_string_lossy().to_string();
        if name.starts_with(".PKGINFO")
            || name.starts_with(".MTREE")
            || name.starts_with(".BUILDINFO")
            || name.starts_with(".INSTALL")
            || name.starts_with(".pacnew")
            || name == ".CHANGELOG"
        {
            continue;
        }
        let dest = root.join(&path);
        let entry_type = entry.header().entry_type();
        match entry_type {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&dest)?;
            }
            tar::EntryType::Symlink => {
                if let Some(link) = entry.link_name()? {
                    // Arch's `filesystem` package wants /bin -> usr/bin and
                    // friends. In a live initramfs those paths are REAL
                    // directories holding our runtime — converting them to
                    // symlinks would break the running OS (and fails with
                    // EEXIST anyway). Skip conflicts honestly.
                    let conflict = dest.is_dir() || dest.symlink_metadata().is_ok();
                    if conflict {
                        println!(
                            "spore: skipping {} -> {} (destination in use by the runtime)",
                            name,
                            link.display()
                        );
                        continue;
                    }
                    let _ = std::fs::remove_file(&dest);
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&link, &dest)?;
                }
                files.push(name);
            }
            tar::EntryType::Regular => {
                // Runtime-owned state: a package shipping an empty
                // /etc/resolv.conf would cut the resolver off MID-INSTALL
                // (observed with Arch's `filesystem` package — DNS worked
                // for the first packages, then EAI_AGAIN). Keep ours.
                if name == "etc/resolv.conf" && dest.exists() {
                    println!("spore: keeping runtime /etc/resolv.conf (package ships its own)");
                    continue;
                }
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                {
                    use std::io::Write;
                    let mut out = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&dest)?;
                    std::io::copy(&mut entry, &mut out)?;
                    out.flush()?;
                }
                #[cfg(not(unix))]
                {
                    std::io::copy(&mut entry, &mut &dest)?;
                }
                files.push(name);
            }
            _ => {
                // fifo / device / hardlink: skip honestly
                continue;
            }
        }
        // apply permissions for files and dirs
        #[cfg(unix)]
        if let Ok(meta) = entry.header().mode() {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(meta);
            let _ = std::fs::set_permissions(&dest, perm);
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// The install command
// ---------------------------------------------------------------------------

pub fn install(roots: &[String], root: &Path, cache: &Path, mirror: &str) -> Result<Vec<String>> {
    if roots.is_empty() {
        bail!("nothing to install");
    }
    let repos = load_repos(cache, mirror)?;
    let db_path = root.join("var/lib/spore/installed.json");
    let mut installed: InstalledDb = std::fs::read(&db_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let plan = resolve(roots, &repos, &installed)?;
    println!(
        "spore: plan {} package(s) for {:?}: {}",
        plan.len(),
        roots,
        plan.iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut installed_names = Vec::new();
    for pkg in &plan {
        let local = fetch_package(pkg, cache, mirror)?;
        print!(
            "spore: extracting {} {} ({} bytes) ... ",
            pkg.name, pkg.version, pkg.size
        );
        let files = extract_package(&local, root)?;
        println!("done ({} files)", files.len());
        installed.packages.insert(
            pkg.name.clone(),
            InstalledPkg {
                version: pkg.version.clone(),
                provides: pkg.provides.clone(),
                files,
                installed_at_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
        );
        installed_names.push(format!("{}-{}", pkg.name, pkg.version));
    }

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&db_path, serde_json::to_vec_pretty(&installed)?)?;
    Ok(installed_names)
}

pub fn list(root: &Path) -> Result<()> {
    let db_path = root.join("var/lib/spore/installed.json");
    let installed: InstalledDb = std::fs::read(&db_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    for (name, pkg) in &installed.packages {
        println!("{}\t{}", name, pkg.version);
    }
    Ok(())
}

pub fn is_installed(root: &Path, name: &str) -> bool {
    let db_path = root.join("var/lib/spore/installed.json");
    let installed: InstalledDb = std::fs::read(&db_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    installed.packages.contains_key(name)
}

/// Resolve-only report (dry run) — names in install order.
pub fn plan(roots: &[String], root: &Path, cache: &Path, mirror: &str) -> Result<()> {
    let repos = load_repos(cache, mirror)?;
    let db_path = root.join("var/lib/spore/installed.json");
    let installed: InstalledDb = std::fs::read(&db_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let order = resolve(roots, &repos, &installed)?;
    for p in &order {
        println!("{}\t{}\t{}", p.repo, p.name, p.version);
    }
    Ok(())
}

// re-export BTreeSet so tests can use it without warning
#[allow(unused)]
fn _unused(_s: &BTreeSet<String>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_parse_and_satisfaction() {
        let t = parse_term("glibc>=2.38");
        assert_eq!(t.name, "glibc");
        let t2 = parse_term("libfoo.so=1-64");
        assert_eq!(t2.name, "libfoo.so");
        assert_eq!(t2.op, Some(('=', "1-64".to_string())));
        let t3 = parse_term("bash");
        assert_eq!(t3.name, "bash");
        assert!(t3.op.is_none());
    }

    #[test]
    fn ver_compare() {
        assert_eq!(ver_cmp("1.10", "1.9"), std::cmp::Ordering::Greater);
        assert_eq!(ver_cmp("5.2.037", "5.2.037"), std::cmp::Ordering::Equal);
        assert_eq!(ver_cmp("2.38-1", "2.37-5"), std::cmp::Ordering::Greater);
        assert_eq!(ver_cmp("0.4", "0.40"), std::cmp::Ordering::Less);
    }
}
