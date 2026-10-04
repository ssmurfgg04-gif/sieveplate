//! sieveplate-os entrypoint. Dispatches on argv0 basename so one static
//! binary serves three roles inside the initramfs:
//!   /init            (symlink to /bin/sieve-os) → PID 1
//!   /bin/spore       (symlink to /bin/sieve-os) → package manager CLI
//!   /bin/sieve-os    → `mkimage` (image builder, host side) / help

use sieveplate_os as os;

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "sieve-os".into());
    let base = argv0
        .rsplit('/')
        .next()
        .unwrap_or("sieve-os")
        .to_string();

    let args: Vec<String> = std::env::args().skip(1).collect();

    match base.as_str() {
        "init" => os::init::main(),
        "spore" => spore_cli(&args),
        _ => top_cli(&args),
    }
}

fn top_cli(args: &[String]) -> anyhow::Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("init") => os::init::main(),
        Some("spore") => spore_cli(&args[1..]),
        Some("mkimage") => {
            let mut out = PathBuf::from("./os-image");
            let mut init_bin: Option<PathBuf> = None;
            let mut force = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--out" => {
                        out = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    "--init" => {
                        init_bin = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--refetch" => {
                        force = true;
                        i += 1;
                    }
                    other => anyhow::bail!("unknown flag {other}"),
                }
            }
            let init_bin = init_bin.unwrap_or_else(|| {
                // beside the binary (CI: target/<triple>/release/sieve-os)
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("init")))
                    .unwrap_or_else(|| PathBuf::from("./init"))
            });
            os::mkimage::mkimage(os::mkimage::MkimageOpts {
                out,
                init_bin,
                force_refetch: force,
            })
        }
        _ => {
            eprintln!("sieve-os — the sieveplate OS binary");
            eprintln!();
            eprintln!("  sieve-os init              (run as PID 1 — normally via the /init symlink)");
            eprintln!("  sieve-os mkimage --out DIR --init PATH [--refetch]");
            eprintln!("  spore install <pkgs...> --root / [--cache DIR] [--mirror URL]");
            eprintln!("  spore list --root /");
            eprintln!("  spore plan <pkgs...> --root /");
            Ok(())
        }
    }
}

fn spore_cli(args: &[String]) -> anyhow::Result<()> {
    let mut root = PathBuf::from("/");
    let mut cache = PathBuf::from("/var/cache/spore");
    let mut mirror = os::pkg::DEFAULT_MIRROR.to_string();
    let mut positional: Vec<String> = Vec::new();
    let mut cmd = "install".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--cache" => {
                cache = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--mirror" => {
                mirror = args[i + 1].clone();
                i += 2;
            }
            other => {
                if positional.is_empty() && matches!(other, "install" | "list" | "plan") {
                    cmd = other.to_string();
                } else {
                    positional.push(other.to_string());
                }
                i += 1;
            }
        }
    }
    match cmd.as_str() {
        "install" => {
            let installed = os::pkg::install(&positional, &root, &cache, &mirror)?;
            for name in installed {
                println!("installed {name}");
            }
            Ok(())
        }
        "list" => os::pkg::list(&root),
        "plan" => os::pkg::plan(&positional, &root, &cache, &mirror),
        _ => anyhow::bail!("unknown spore command '{cmd}'"),
    }
}
