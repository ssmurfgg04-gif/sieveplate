//! Kernel-enforced sandboxing for process cells.
//!
//! Two complementary mechanisms, applied to the worker process *before any
//! cell code runs*:
//!
//! 1. **seccomp (default-deny syscall allowlist)** — the worker may only
//!    call the syscalls a stateless compute loop needs (read/write on its
//!    stdio pipes, memory management, clock, futex, exit). `socket`,
//!    `open`, `clone`, `execve`, `fork` are all denied with `EPERM`.
//!    This works on any Linux ≥ 3.17 unprivileged (via `NO_NEW_PRIVS`) —
//!    it is the enforced-in-this-process guarantee.
//! 2. **Landlock (filesystem restriction, best-effort)** — on kernels
//!    ≥ 5.13 the worker's filesystem view is narrowed to read-only access
//!    on explicitly granted paths. On older kernels the crate reports the
//!    restriction as *unsupported* rather than silently claiming it.
//!
//! The honest report returned by [`apply_self`] is what the runtime surfaces
//! in status output: `seccomp: enforced` always (or init failure), and
//! `landlock: enforced | unsupported (kernel < 5.13) | disabled`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Apply the default-deny seccomp allowlist (recommended; the only way
    /// to actually enforce on kernels < 5.13).
    #[serde(default = "default_true")]
    pub seccomp: bool,
    /// Apply Landlock filesystem confinement (kernel ≥ 5.13; best-effort
    /// otherwise — the report says which happened).
    #[serde(default = "default_true")]
    pub landlock: bool,
    /// Paths the worker may READ via Landlock (advisory on old kernels —
    /// seccomp denies `open` regardless, so file access is blocked twice).
    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,
    /// Address-space cap in MiB (rlimit). 0 = unlimited.
    #[serde(default = "default_mem")]
    pub max_mem_mib: u64,
}

fn default_true() -> bool {
    true
}
fn default_mem() -> u64 {
    512
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        SandboxPolicy {
            seccomp: true,
            landlock: true,
            readonly_paths: Vec::new(),
            max_mem_mib: 512,
        }
    }
}

/// What the kernel actually enforced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxReport {
    /// true = a default-deny seccomp filter is live in this process.
    pub seccomp_enforced: bool,
    pub landlock: LandlockStatus,
    /// Human note (e.g. why landlock is unsupported).
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LandlockStatus {
    /// FS confinement active.
    Enforced,
    /// Kernel lacks Landlock (ABI reported unsupported by the ruleset).
    Unsupported,
    /// Policy disabled it.
    Disabled,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("seccomp: {0}")]
    Seccomp(String),
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("rlimit: {0}")]
    Rlimit(String),
    #[error("prctl: {0}")]
    Prctl(String),
}

/// Syscalls the worker is allowed to call. Deliberately minimal: no
/// `open`/`openat` (file access denied outright), no socket family, no
/// process family (`clone`/`fork`/`execve`), no `prctl` (further filter
/// manipulation impossible once running).
const WORKER_ALLOWLIST: &[i64] = &[
    // I/O on inherited fds (stdin/stdout pipes)
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_readv,
    libc::SYS_lseek,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_flock,
    // memory management
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_mremap,
    libc::SYS_brk,
    // synchronization / time
    libc::SYS_futex,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    // process info (read-only)
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getppid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_sched_getaffinity,
    libc::SYS_getrandom,
    libc::SYS_getcwd,
    libc::SYS_uname,
    // thread-local / stack setup performed by std at startup
    libc::SYS_set_robust_list,
    libc::SYS_set_tid_address,
    libc::SYS_rseq,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigreturn,
    libc::SYS_fcntl,
    // exit
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// Apply the sandbox to the CURRENT process. Order matters:
/// rlimits → Landlock (may set NO_NEW_PRIVS itself) → explicit
/// `PR_SET_NO_NEW_PRIVS` → seccomp (last: cannot be undone).
pub fn apply_self(policy: &SandboxPolicy) -> Result<SandboxReport, SandboxError> {
    // 1. Address-space cap.
    if policy.max_mem_mib > 0 {
        let limit = policy.max_mem_mib * 1024 * 1024;
        let rl = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rl) };
        if rc != 0 {
            return Err(SandboxError::Rlimit(
                std::io::Error::last_os_error().to_string(),
            ));
        }
    }

    // 2. Landlock filesystem confinement (best-effort).
    let mut report = SandboxReport {
        seccomp_enforced: false,
        landlock: LandlockStatus::Disabled,
        note: String::new(),
    };
    if policy.landlock {
        match apply_landlock(&policy.readonly_paths) {
            Ok(true) => report.landlock = LandlockStatus::Enforced,
            Ok(false) => {
                report.landlock = LandlockStatus::Unsupported;
                report
                    .note
                    .push_str("landlock unsupported on this kernel (needs >= 5.13); ");
            }
            Err(e) => {
                report.landlock = LandlockStatus::Unsupported;
                report
                    .note
                    .push_str(&format!("landlock setup failed: {e}; "));
            }
        }
    }

    // 3. NO_NEW_PRIVS — required for unprivileged seccomp.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(SandboxError::Prctl(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    // 4. seccomp default-deny allowlist.
    if policy.seccomp {
        apply_seccomp()?;
        report.seccomp_enforced = true;
    }
    Ok(report)
}

fn apply_landlock(readonly_paths: &[PathBuf]) -> Result<bool, SandboxError> {
    use landlock::{
        Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };
    let abi = landlock::ABI::V1;
    let mut ruleset = Ruleset::default()
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::Landlock(e.to_string()))?
        .create()
        .map_err(|e| SandboxError::Landlock(e.to_string()))?;
    for p in readonly_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(p).map_err(|e| SandboxError::Landlock(e.to_string()))?,
                AccessFs::from_read(abi),
            ))
            .map_err(|e| SandboxError::Landlock(e.to_string()))?;
    }
    let status = ruleset
        .no_new_privs(true)
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(e.to_string()))?;
    // Best-effort mode degrades silently: inspect the status to know.
    Ok(!matches!(
        status.ruleset,
        landlock::RulesetStatus::NotEnforced
    ))
}

fn apply_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        other => {
            return Err(SandboxError::Seccomp(format!("unsupported arch {other}")));
        }
    };
    let rules: std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> = WORKER_ALLOWLIST
        .iter()
        .map(|&nr| (nr, Vec::new()))
        .collect();
    let filter: SeccompFilter = SeccompFilter::new(
        rules,
        // Denied syscalls fail observably with EPERM rather than killing
        // the worker (still default-deny: anything not listed is denied).
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))?;
    apply_filter(&program).map_err(|e: seccompiler::Error| SandboxError::Seccomp(e.to_string()))
}

/// Is the seccomp filter really live? A process can check itself: attempt a
/// forbidden syscall and expect EPERM.
pub fn self_check_seccomp() -> bool {
    // socket() is forbidden for workers: must fail with EPERM when the
    // filter is live.
    let rc = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if rc == -1 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    }
    unsafe { libc::close(rc) };
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_serde_roundtrip() {
        let p = SandboxPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&j).unwrap();
        assert!(back.seccomp);
        assert_eq!(back.max_mem_mib, 512);
    }

    // NOTE: apply_self() is exercised for real by the worker subprocess in
    // sieveplate-ctl integration tests (applying a filter inside the test
    // harness process would kill the harness).
}
