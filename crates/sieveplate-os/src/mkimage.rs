//! `sieve-os mkimage` — assemble a bootable sieveplate image:
//!   vmlinuz (from the Arch `linux` package)
//! + initramfs.cpio (our static `init`, busybox, NIC modules)
//! = everything QEMU needs: `-kernel vmlinuz -initrd initramfs.cpio`.
//!
//! The root filesystem IS the initramfs (tmpfs): a live OS. Packages
//! installed by `spore` land in the tmpfs `/usr` — real binaries, real
//! dynamic linking against the real Arch glibc the packages ship.
//!
//! Module selection: Arch ships drivers as modules; we parse
//! `modules.dep` from the linux package and pull the closure of the NIC
//! drivers we need (virtio-net + e1000 chains), decompressing `.ko.zst`.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cpio::{CpioWriter, Entry, EntryKind};
use crate::pkg::http_get;

pub const MIRROR: &str = crate::pkg::DEFAULT_MIRROR;

/// busybox applets we symlink into /bin.
const APPLETS: &[&str] = &[
    "sh", "ash", "mount", "umount", "mkdir", "mknod", "hostname", "sleep", "cat", "ls", "ln",
    "echo", "ifconfig", "route", "udhcpc", "poweroff", "reboot", "halt", "insmod", "lsmod",
    "uname", "grep", "sed", "cp", "mv", "rm", "date", "touch", "ps", "kill", "chmod", "head",
    "tail", "wc", "printf", "seq", "sync", "env", "clear", "true", "false", "dd", "free",
];

/// Kernel modules (by module NAME, no path) needed to see a QEMU NIC.
const WANTED_MODULES: &[&str] = &["virtio_net", "e1000", "8139cp", "af_packet"];

pub struct MkimageOpts {
    pub out: PathBuf,
    pub init_bin: PathBuf,
    /// skip downloads if cache already populated (idempotent CI)
    pub force_refetch: bool,
}

pub fn mkimage(opts: MkimageOpts) -> Result<()> {
    let cache = opts.out.join("cache");
    std::fs::create_dir_all(&cache)?;
    let staging = opts.out.join("staging");
    let _ = std::fs::remove_dir_all(&staging);
    let dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "etc", "proc", "sys", "dev", "tmp", "run", "var/cache/spore", "modules", "root", "home", "mnt"];
    for d in dirs {
        std::fs::create_dir_all(staging.join(d))?;
    }

    // ---- 1. fetch the linux package: kernel + modules.dep -----------------
    println!("mkimage: fetching Arch repo db ...");
    let repos = crate::pkg::load_repos(&cache, MIRROR)?;
    let linux = repos
        .get("linux")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("'linux' not found in repos"))?;
    let busybox = repos
        .get("busybox")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("'busybox' not found in repos"))?;
    println!(
        "mkimage: linux {} ({}), busybox {} ({})",
        linux.version,
        human(linux.size),
        busybox.version,
        human(busybox.size)
    );

    let linux_pkg = fetch_to_cache(&linux, &cache, opts.force_refetch)?;
    let busybox_pkg = fetch_to_cache(&busybox, &cache, opts.force_refetch)?;

    // ---- 2. pull vmlinuz + module closure out of the linux package -------
    // Arch does not ship modules.dep (depmod generates it at install
    // time), so we parse each module's embedded .modinfo `depends=` line
    // ourselves: pass 1 maps module stems to tar paths (cheap), pass 2
    // decompresses only the closure we need.
    println!("mkimage: selecting kernel + NIC module closure ...");
    let mut vmlinuz: Option<Vec<u8>> = None;
    let mut module_paths: HashMap<String, String> = HashMap::new();
    let mut builtin: HashSet<String> = HashSet::new();
    {
        let f = std::fs::File::open(&linux_pkg)?;
        let dz = zstd::Decoder::new(f)?;
        let mut tar = tar::Archive::new(dz);
        for entry in tar.entries()? {
            let entry = entry?;
            let path = entry.path()?.to_path_buf().to_string_lossy().to_string();
            if path.ends_with("/vmlinuz") {
                // vmlinuz is read in the second pass below
                continue;
            }
            if path.ends_with("/modules.builtin") || path.ends_with("/modules.builtin.zst") {
                // read the list
                let mut e2 = entry;
                let mut buf = Vec::new();
                e2.read_to_end(&mut buf)?;
                let text = if path.ends_with(".zst") {
                    String::from_utf8_lossy(&zstd::decode_all(&buf[..])?).to_string()
                } else {
                    String::from_utf8_lossy(&buf).to_string()
                };
                for line in text.lines() {
                    let stem = Path::new(line.trim())
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let stem = stem.trim_end_matches(".ko").to_string();
                    if !stem.is_empty() {
                        builtin.insert(stem);
                    }
                }
                continue;
            }
            if path.ends_with(".ko") || path.ends_with(".ko.zst") {
                let stem = Path::new(&path)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let stem = stem.trim_end_matches(".ko").to_string();
                module_paths.insert(stem, path.clone());
            }
        }
    }
    // Second tiny pass just for vmlinuz (first pass borrowed entries).
    if vmlinuz.is_none() {
        let f = std::fs::File::open(&linux_pkg)?;
        let dz = zstd::Decoder::new(f)?;
        let mut tar = tar::Archive::new(dz);
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf().to_string_lossy().to_string();
            if path.ends_with("/vmlinuz") {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                vmlinuz = Some(buf);
                break;
            }
        }
    }
    let Some(vmlinuz) = vmlinuz else {
        bail!("vmlinuz not found in the linux package");
    };

    // DFS the dependency graph from the wanted modules; emit post-order
    // (dependencies load first). Reads `depends=` straight out of .modinfo.
    fn load_module(
        stem: &str,
        module_paths: &HashMap<String, String>,
        builtin: &HashSet<String>,
        linux_pkg: &Path,
        staging: &Path,
        done: &mut HashSet<String>,
        order: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 || done.contains(stem) {
            return Ok(());
        }
        done.insert(stem.to_string());
        if builtin.contains(stem) {
            println!("mkimage: module {stem} is builtin — skip");
            return Ok(());
        }
        let Some(path) = module_paths.get(stem) else {
            println!("mkimage: module {stem} not present — skip");
            return Ok(());
        };
        // stream just this entry out of the package
        let raw = {
            let f = std::fs::File::open(linux_pkg)?;
            let dz = zstd::Decoder::new(f)?;
            let mut tar = tar::Archive::new(dz);
            let mut out = None;
            for entry in tar.entries()? {
                let mut entry = entry?;
                let p = entry.path()?.to_path_buf().to_string_lossy().to_string();
                if p == *path {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf)?;
                    out = Some(buf);
                    break;
                }
            }
            out.ok_or_else(|| anyhow::anyhow!("module {stem} vanished from package"))?
        };
        let ko = if path.ends_with(".zst") {
            zstd::decode_all(&raw[..])?
        } else {
            raw
        };
        // parse `depends=` from the .modinfo section
        let deps: Vec<String> = {
            let mut out = Vec::new();
            let needle = b"depends=";
            let mut i = 0;
            while let Some(pos) = ko[i..]
                .windows(needle.len())
                .position(|w| w == *needle)
            {
                let start = i + pos + needle.len();
                let end = ko[start..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|p| start + p)
                    .unwrap_or(ko.len());
                let line = String::from_utf8_lossy(&ko[start..end]).to_string();
                for d in line.split(',').filter(|d| !d.is_empty()) {
                    out.push(d.trim().to_string());
                }
                i = end;
            }
            out
        };
        for d in &deps {
            load_module(d, module_paths, builtin, linux_pkg, staging, done, order, depth + 1)?;
        }
        let out_name = format!("/modules/{stem}.ko");
        std::fs::write(staging.join("modules").join(format!("{stem}.ko")), &ko)?;
        order.push(out_name);
        println!("mkimage: module {stem} ({} bytes)", ko.len());
        Ok(())
    }

    let mut done = HashSet::new();
    let mut order: Vec<String> = Vec::new();
    for m in WANTED_MODULES {
        load_module(
            m,
            &module_paths,
            &builtin,
            &linux_pkg,
            &staging,
            &mut done,
            &mut order,
            0,
        )?;
    }
    if order.is_empty() {
        bail!("no NIC modules could be staged");
    }
    std::fs::write(
        staging.join("modules").join("order.txt"),
        order.join("\n") + "\n",
    )?;

    // ---- 3. busybox + applets --------------------------------------------
    let busybox_bytes = {
        let f = std::fs::File::open(&busybox_pkg)?;
        let dz = zstd::Decoder::new(f)?;
        let mut tar = tar::Archive::new(dz);
        let mut found = None;
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf().to_string_lossy().to_string();
            if path == "usr/bin/busybox" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                found = Some(buf);
                break;
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("usr/bin/busybox not found in busybox package"))?
    };
    std::fs::write(staging.join("bin").join("busybox"), &busybox_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            staging.join("bin").join("busybox"),
            std::fs::Permissions::from_mode(0o755),
        )?;
    }

    // ---- 4. our init + /init entry ----------------------------------------
    let init_bytes = std::fs::read(&opts.init_bin)?;
    std::fs::write(staging.join("bin").join("sieve-os"), &init_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            staging.join("bin").join("sieve-os"),
            std::fs::Permissions::from_mode(0o755),
        )?;
    }

    // ---- 5. build cpio ------------------------------------------------------
    let mut entries: Vec<Entry> = Vec::new();
    for d in dirs {
        entries.push(Entry {
            name: format!("/{d}"),
            kind: EntryKind::Dir { mode: 0o755 },
        });
    }
    entries.push(Entry {
        name: "/bin/busybox".into(),
        kind: EntryKind::File {
            data: busybox_bytes,
            mode: 0o755,
        },
    });
    entries.push(Entry {
        name: "/bin/sieve-os".into(),
        kind: EntryKind::File {
            data: init_bytes,
            mode: 0o755,
        },
    });
    for a in APPLETS {
        entries.push(Entry {
            name: format!("/bin/{a}"),
            kind: EntryKind::Symlink {
                target: "/bin/busybox".into(),
            },
        });
    }
    entries.push(Entry {
        name: "/init".into(),
        kind: EntryKind::Symlink {
            target: "/bin/sieve-os".into(),
        },
    });
    entries.push(Entry {
        name: "/etc/resolv.conf".into(),
        kind: EntryKind::File {
            data: b"nameserver 10.0.2.3\n".to_vec(),
            mode: 0o644,
        },
    });
    entries.push(Entry {
        name: "/etc/hostname".into(),
        kind: EntryKind::File {
            data: b"sieveplate\n".to_vec(),
            mode: 0o644,
        },
    });
    entries.push(Entry {
        name: "/etc/motd".into(),
        kind: EntryKind::File {
            data: concat!(
                "  sieveplate OS — a living cell-grid operating system\n",
                "  kernel: real Linux | PID 1: real Rust | packages: real Arch\n"
            )
            .to_string()
            .into_bytes(),
            mode: 0o644,
        },
    });
    // modules from staging
    for f in std::fs::read_dir(staging.join("modules"))?.flatten() {
        let name = f.file_name().to_string_lossy().to_string();
        let data = std::fs::read(f.path())?;
        entries.push(Entry {
            name: format!("/modules/{name}"),
            kind: EntryKind::File {
                data,
                mode: 0o644,
            },
        });
    }

    let cpio_path = opts.out.join("initramfs.cpio");
    {
        let f = std::fs::File::create(&cpio_path)?;
        let mut w = CpioWriter::new(std::io::BufWriter::new(f));
        for e in &entries {
            w.write_entry(e)?;
        }
        w.finish()?;
    }

    // kernel + gzip'd initramfs for convenience
    std::fs::write(opts.out.join("vmlinuz"), &vmlinuz)?;
    println!(
        "mkimage: wrote {} ({}), {} ({})",
        cpio_path.display(),
        human(std::fs::metadata(&cpio_path)?.len()),
        opts.out.join("vmlinuz").display(),
        human(vmlinuz.len() as u64)
    );
    Ok(())
}

fn fetch_to_cache(
    pkg: &crate::pkg::PackageInfo,
    cache: &Path,
    force: bool,
) -> Result<PathBuf> {
    let local = cache.join(&pkg.filename);
    if force || !local.exists() || std::fs::metadata(&local).map(|m| m.len() == 0).unwrap_or(true) {
        let url = format!(
            "{MIRROR}/{}/os/x86_64/{}",
            pkg.repo,
            pkg.filename.replace(' ', "%20")
        );
        println!("mkimage: downloading {url}");
        let bytes = http_get(&url).with_context(|| format!("download {url}"))?;
        std::fs::write(&local, &bytes)?;
    }
    Ok(local)
}

fn human(n: u64) -> String {
    if n > 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n > 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

use std::collections::HashMap;
