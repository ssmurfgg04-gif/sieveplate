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
mod run;
mod store_cmd;

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
    /// Content store operations
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
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
    }
}
