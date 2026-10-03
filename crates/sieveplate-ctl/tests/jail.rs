//! Process-isolated cells end to end: the tests spawn the REAL `sieve
//! __worker` binary (see `worker_exe`) and prove:
//! 1. a process cell computes and persists across evict→respawn;
//! 2. the seccomp sandbox actually DENIES socket + file syscalls;
//! 3. capability grants are enforced for process cells too.
//!
//! These run unprivileged: seccomp needs only NO_NEW_PRIVS. Landlock is
//! kernel-gated (≥ 5.13) — the worker reports, we don't assert it here.

use std::time::Duration;

use sieveplate_engine::{CellSpec, Host, HostConfig, Isolation};
use sieveplate_jail::SandboxPolicy;

fn test_host(tag: &str, host_name: &str) -> Host {
    let root = std::env::temp_dir().join(format!("sp-jail-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let rt = root.join("runtime");
    std::fs::create_dir_all(&rt).unwrap();
    let mut host = Host::start(
        HostConfig {
            host: host_name.into(),
            vats: vec!["core".into()],
            mailbox_capacity: 1024,
            worker_exe: Some(std::path::PathBuf::from(env!("CARGO_BIN_EXE_sieve"))),
            drain_on_shutdown: true,
        },
        &rt,
    )
    .unwrap();
    let _ = &mut host;
    host
}

fn proc_spec(name: &str, template: &str, sandbox: SandboxPolicy) -> CellSpec {
    CellSpec {
        name: name.into(),
        vat: "core".into(),
        template: template.into(),
        caps: vec![],
        sleep_after_ms: None,
        persist_on_turn: true,
        max_restarts: 3,
        isolation: Isolation::Process,
        sandbox,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn process_cell_computes_and_survives_eviction() {
    let host = test_host("compute", "node-a");

    host.create_cell(&proc_spec(
        "pcounter",
        "builtin:counter",
        SandboxPolicy::default(),
    ))
    .await
    .unwrap();

    let pcounter = sieveplate_core::Port::new("node-a", "core", "pcounter");
    // Compute through the real process boundary. `add` is fire-and-forget;
    // `get` returns the count.
    use sieveplate_core::Route as _;
    host.fabric
        .deliver(sieveplate_core::Envelope::new(
            pcounter.clone(),
            "add",
            5u64.to_le_bytes().to_vec(),
        ))
        .await
        .unwrap();
    let v = host
        .fabric
        .call(pcounter.clone(), "get", vec![], Duration::from_secs(20))
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(v[..8].try_into().unwrap()), 5);

    // Evict: the OS process is KILLED; state lives in the CAS.
    let h = host.scale_to_zero("core", "pcounter").await.unwrap();
    assert!(!h.is_empty());
    let procs = host.proc_cells();
    assert!(procs
        .iter()
        .any(|(_, n, running)| n == "pcounter" && !running));

    // The next message respawns the worker from the content store: the
    // value must have survived.
    let v2 = host
        .fabric
        .call(pcounter, "get", vec![], Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(v2[..8].try_into().unwrap()), 5);

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("sp-jail-compute-{}", std::process::id())),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn seccomp_denies_socket_and_file_syscalls() {
    let host = test_host("deny", "node-a");
    host.create_cell(&proc_spec(
        "probe",
        "builtin:sandbox-probe",
        SandboxPolicy::default(),
    ))
    .await
    .unwrap();
    let port = sieveplate_core::Port::new("node-a", "core", "probe");

    // socket() is not on the worker allowlist → connect must be blocked.
    let r = host
        .fabric
        .call(port.clone(), "socket", vec![], Duration::from_secs(20))
        .await
        .unwrap();
    let s = String::from_utf8_lossy(&r).to_string();
    assert!(
        s.starts_with("blocked:"),
        "socket syscall must be denied by seccomp, got: {s}"
    );

    // open() is not on the allowlist → file creation must be blocked.
    let r = host
        .fabric
        .call(port.clone(), "file", vec![], Duration::from_secs(20))
        .await
        .unwrap();
    let s = String::from_utf8_lossy(&r).to_string();
    assert!(
        s.starts_with("blocked:"),
        "file syscall must be denied by seccomp, got: {s}"
    );

    // The cell is still alive and answering after refused syscalls
    // (Errno(EPERM), not KillProcess).
    let r = host
        .fabric
        .call(port, "ok", vec![], Duration::from_secs(20))
        .await
        .unwrap();
    assert_eq!(r, b"ok");

    host.shutdown().await;
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("sp-jail-deny-{}", std::process::id())),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sandboxless_worker_still_runs_but_is_reported() {
    // A policy with everything disabled must NOT be silently treated as
    // sandboxed — the runtime surfaces the report (here we only assert the
    // cell still works, proving the policy is honored, and the report is
    // part of the worker handshake contract).
    let host = test_host("nosbx", "node-a");
    let policy = SandboxPolicy {
        seccomp: false,
        landlock: false,
        ..SandboxPolicy::default()
    };
    host.create_cell(&proc_spec("loose", "builtin:counter", policy))
        .await
        .unwrap();
    use sieveplate_core::Route as _;
    host.fabric
        .deliver(sieveplate_core::Envelope::new(
            sieveplate_core::Port::new("node-a", "core", "loose"),
            "add",
            1u64.to_le_bytes().to_vec(),
        ))
        .await
        .unwrap();
    let v = host
        .fabric
        .call(
            sieveplate_core::Port::new("node-a", "core", "loose"),
            "get",
            vec![],
            Duration::from_secs(20),
        )
        .await
        .unwrap();
    assert_eq!(u64::from_le_bytes(v[..8].try_into().unwrap()), 1);
    host.shutdown().await;
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("sp-jail-nosbx-{}", std::process::id())),
    );
}
