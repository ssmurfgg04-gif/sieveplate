//! `sieve` — the Sieveplate control plane CLI.
//!
//! - `sieve demo`       : the Phase-1 vertical slice, end to end, live
//! - `sieve run -f ...` : apply + execute a declarative system until Ctrl-C
//! - `sieve apply`      : validate + record a plan (content-addressed)
//! - `sieve plan`       : dry-run — print the closure hash and the diff
//! - `sieve rollback`   : apply the previous plan (Nix-style)
//! - `sieve status`     : inspect plans
//! - `sieve bench`      : measure wake latency, turns, store, scale-to-zero
//! - `sieve store ...`  : put/get/gc/Datalog-query the content store

mod bench;
mod demo;
mod hearth_cmd;
mod run;
mod store_cmd;
mod top;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sieve",
    version,
    about = "Sieveplate: a living cell-grid runtime — capability-gated cells, transactional turns, scale-to-zero",
    after_help = "Start with: sieve demo"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// INTERNAL: jailed worker process (spawned by `sieve run` for
    /// process-isolated cells). Not for interactive use.
    #[command(hide = true, name = "__worker")]
    __Worker {
        /// JSON-encoded SandboxPolicy.
        #[arg(long)]
        sandbox: String,
    },
    /// Run the Phase-1 vertical slice: sleep → wake → transact → persist → restore
    Demo {
        /// Reduce output
        #[arg(long)]
        quiet: bool,
    },
    /// Execute a declarative system spec until Ctrl-C
    Run {
        #[arg(short, long)]
        file: String,
        /// Data root for the store/event log/plans
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Validate a spec and record its plan (content-addressed)
    Apply {
        #[arg(short, long)]
        file: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Dry-run: print closure hash and diff vs the applied plan
    Plan {
        #[arg(short, long)]
        file: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Roll back to the previously applied plan
    Rollback {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Show the applied plan (HEAD)
    Status {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Benchmark the cell grid
    Bench {
        /// Which suite: wake | turns | store | cells | all
        #[arg(long, default_value = "all")]
        suite: String,
    },
    /// Content-addressed versioning: snapshots, branches, diff/ddiff
    Hearth {
        #[command(subcommand)]
        cmd: HearthCmd,
    },
    /// Content store operations
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Live dashboard over a running/declared system (Catppuccin Mocha TUI)
    Top {
        #[arg(short, long)]
        file: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
        /// Headless: render one frame to this JSON file and exit
        #[arg(long)]
        screenshot: Option<String>,
        /// Screenshot geometry (WxH)
        #[arg(long, default_value = "100x31")]
        size: String,
        /// Screenshot: seed hearth demo branches when empty
        #[arg(long)]
        seed_hearth: bool,
    },
    /// Host identity operations (key format v1, ADR-0007)
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Show the host identity: fingerprint, key generation, pinned peers
    Show {
        /// Host alias (defaults to the system name in the spec)
        #[arg(long, default_value = "host")]
        host: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Rotate to a fresh key pair (generation + 1). Produces a
    /// RotationStatement signed by both generations with both algorithms;
    /// peers still pinning old keys re-pin automatically on the next
    /// handshake.
    Rotate {
        /// Host alias to rotate
        #[arg(long, default_value = "host")]
        host: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
}

#[derive(Subcommand)]
enum HearthCmd {
    /// Write a blob: `sieve hearth write KEY --text T`
    Write {
        key: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        file: Option<String>,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Commit a snapshot tree on a branch: entries are `key=blobhash`
    Snapshot {
        branch: String,
        /// key=blobhash entries
        entries: Vec<String>,
        #[arg(long, default_value = "")]
        message: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// List branches and their tips
    Branches {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// First-parent history of a branch
    Log {
        branch: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Logical diff between two branch tips
    Diff {
        branch_a: String,
        branch_b: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Byte-level delta between two snapshot trees (tree hashes)
    Ddiff {
        tree_a: String,
        tree_b: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Reconstruct a tree from a base tree + delta (hash-verified)
    ApplyDelta {
        base_tree: String,
        delta: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Materialize a commit's snapshot into a directory
    Checkout {
        commit: String,
        #[arg(long, default_value = "./checkout")]
        out: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Put bytes (from --text or file) and print the content hash
    Put {
        #[arg(long)]
        text: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Get an object by hash
    Get {
        hash: String,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Count objects
    Stats {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Garbage-collect unreachable objects
    Gc {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Verify the hash-chained event log
    Verify {
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
    /// Query the event log with Datalog: rules then a goal ending in '?'
    /// Example: sieve store query 'wake(C, U)?' --us-threshold 0
    Query {
        /// Datalog: facts are projected from the log; e.g. "wake(C, U)?"
        goal: String,
        /// Extra rules (repeatable), e.g. --rule 'slow(C) :- wake(C, U)...'
        /// (Datalog ints only; write constants inline)
        #[arg(long = "rule")]
        rules: Vec<String>,
        #[arg(long, default_value = "./runtime")]
        root: String,
    },
}

fn init_logging(quiet: bool) {
    let filter = if quiet { "warn" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::__Worker { sandbox } => {
            // NO logging on stdout (the protocol pipe owns it).
            init_logging(true);
            let policy: sieveplate_jail::SandboxPolicy = serde_json::from_str(&sandbox)
                .map_err(|e| anyhow::anyhow!("bad sandbox policy: {e}"))?;
            let registry = sieveplate_cells::builtin_registry();
            let mut stdin = std::io::stdin();
            sieveplate_jail::run_worker(&registry, &policy, &mut stdin)
                .map_err(|e| anyhow::anyhow!("worker exited: {e}"))
        }
        Cmd::Demo { quiet } => {
            init_logging(quiet);
            demo::run().await
        }
        Cmd::Run { file, root } => {
            init_logging(false);
            run::run_file(&file, &root).await
        }
        Cmd::Apply { file, root } => {
            init_logging(false);
            run::apply(&file, &root)
        }
        Cmd::Plan { file, root } => {
            init_logging(true);
            run::plan(&file, &root)
        }
        Cmd::Rollback { root } => {
            init_logging(false);
            run::rollback(&root)
        }
        Cmd::Status { root } => {
            init_logging(true);
            run::status(&root)
        }
        Cmd::Bench { suite } => {
            init_logging(true);
            bench::run(&suite).await
        }
        Cmd::Hearth { cmd } => {
            init_logging(true);
            match cmd {
                HearthCmd::Write {
                    key,
                    text,
                    file,
                    root,
                } => hearth_cmd::write(&root, &key, &text, &file),
                HearthCmd::Snapshot {
                    branch,
                    entries,
                    message,
                    root,
                } => hearth_cmd::snapshot(&root, &branch, &entries, &message),
                HearthCmd::Branches { root } => hearth_cmd::branches(&root),
                HearthCmd::Log { branch, root } => hearth_cmd::log(&root, &branch),
                HearthCmd::Diff {
                    branch_a,
                    branch_b,
                    root,
                } => hearth_cmd::diff(&root, &branch_a, &branch_b),
                HearthCmd::Ddiff {
                    tree_a,
                    tree_b,
                    root,
                } => hearth_cmd::ddiff(&root, &tree_a, &tree_b),
                HearthCmd::ApplyDelta {
                    base_tree,
                    delta,
                    root,
                } => hearth_cmd::apply_delta(&root, &base_tree, &delta),
                HearthCmd::Checkout { commit, out, root } => {
                    hearth_cmd::checkout(&root, &commit, &out)
                }
            }
        }
        Cmd::Store { cmd } => {
            init_logging(true);
            match cmd {
                StoreCmd::Put { text, root } => store_cmd::put(&text, &root),
                StoreCmd::Get { hash, root } => store_cmd::get(&hash, &root),
                StoreCmd::Stats { root } => store_cmd::stats(&root),
                StoreCmd::Gc { root } => store_cmd::gc(&root),
                StoreCmd::Verify { root } => store_cmd::verify(&root),
                StoreCmd::Query { goal, rules, root } => store_cmd::query(&goal, &rules, &root),
            }
        }
        Cmd::Top {
            file,
            root,
            screenshot,
            size,
            seed_hearth,
        } => {
            init_logging(true);
            match screenshot {
                Some(out) => top::screenshot(&file, &root, &out, &size, seed_hearth).await,
                None => top::interactive(&file, &root).await,
            }
        }
        Cmd::Identity { cmd } => {
            init_logging(true);
            match cmd {
                IdentityCmd::Show { host, root } => {
                    let dir = std::path::Path::new(&root).join("fabric");
                    if !dir.join("identity.json").exists() {
                        eprintln!("no identity at {}/fabric yet — run a system first", root);
                        std::process::exit(1);
                    }
                    let id = sieveplate_fabric::HostIdentity::load_or_create(&dir, &host)?;
                    let pubk = id.public();
                    let peers = sieveplate_fabric::KnownPeers::open(dir.join("known_peers.json"))?;
                    println!("host\t{}", id.host);
                    println!("format\t{} v{}", id.format, id.version);
                    println!("generation\t{}", id.generation);
                    println!("fingerprint\t{}", sieveplate_fabric::fingerprint(&pubk));
                    println!("algorithms\tEd25519 + ML-DSA-65 (hybrid, no downgrade)");
                    println!("pinned_peers\t{}", peers.list().len());
                    for (name, rec) in peers.list() {
                        println!(
                            "peer\t{}\t{}\tgen {}",
                            name, rec.fingerprint, rec.generation
                        );
                    }
                    Ok(())
                }
                IdentityCmd::Rotate { host, root } => {
                    let dir = std::path::Path::new(&root).join("fabric");
                    let id = sieveplate_fabric::HostIdentity::load_or_create(&dir, &host)?;
                    let old_fp = sieveplate_fabric::fingerprint(&id.public());
                    let (next, stmt) = id.rotate(&dir)?;
                    stmt.verify()?;
                    println!(
                        "rotated\t{}\tgen {} -> gen {}",
                        host, stmt.core.old_generation, stmt.core.new_generation
                    );
                    println!("old_fingerprint\t{}", old_fp);
                    println!(
                        "new_fingerprint\t{}",
                        sieveplate_fabric::fingerprint(&next.public())
                    );
                    println!(
                        "statement\tfabric/rotation-{}.json (4 signatures: Ed25519+ML-DSA-65 x old+new)",
                        stmt.core.new_generation
                    );
                    println!(
                        "next_handshake\tpeers still pinning the old keys re-pin automatically"
                    );
                    Ok(())
                }
            }
        }
    }
}
