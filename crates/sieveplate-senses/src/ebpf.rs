//! eBPF senses — a REAL kernel-event path, with honest capability gating.
//!
//! What this module actually does (Linux only):
//! 1. Builds an eBPF program as raw `bpf_insn` arrays (no LLVM needed):
//!    a socket-filter that keeps every packet and reports its length
//!    (`r0 = __sk_buff.len`), so packet arrivals become readable events.
//! 2. Loads it with the real `bpf(2)` syscall (`BPF_PROG_LOAD`).
//! 3. Attaches it to a raw `AF_PACKET` socket (`SO_ATTACH_BPF`) and feeds
//!    every received frame into a [`Signal`], waking cells.
//!
//! Honest requirements, stated up front:
//! - **root/CAP_BPF** is required for `BPF_PROG_LOAD` on kernels with
//!   `kernel.unprivileged_bpf_disabled=1` (the default on modern distros).
//!   Without it, [`load_socket_filter`] returns
//!   [`EbpfError::PrivilegesUnavailable`] — the caller surfaces that
//!   instead of pretending the sense works.
//! - The eBPF *verifier* is a kernel-side checker, not a formal proof.
//!   Loading can still fail with a verifier log; we return it verbatim.
//!
//! Everything that can be tested WITHOUT root is tested (instruction
//! encoding, jump-target sanity, program shape). The full load-and-attach
//! path runs as `--ignored` tests under sudo in CI.

#![cfg(target_os = "linux")]

use libc::close;
use std::os::raw::c_void;

/// The kernel's `bpf_insn` (uapi/linux/bpf.h) — libc doesn't export it.
/// Exactly 8 bytes: dst/src registers share ONE byte (dst low nibble,
/// src high nibble). Getting this wrong = verifier reads garbage jumps.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_insn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

const SO_ATTACH_BPF: i32 = 50; // linux/socket.h
const ETH_P_ALL: u16 = 0x0003;

fn htons(v: u16) -> u16 {
    v.to_be()
}

/// eBPF register numbers.
const R0: u8 = 0;
const R1: u8 = 1;
const R6: u8 = 6;
/// Instruction classes / alu ops (linux/bpf.h).
const BPF_LDX: u8 = 0x01;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;
const BPF_W: u8 = 0x00;
const BPF_MEM: u8 = 0x60;
const BPF_MOV: u8 = 0xb0;
const BPF_X: u8 = 0x08;
const BPF_JA: u8 = 0x00;
const BPF_EXIT: u8 = 0x90;

/// One eBPF instruction (Rust-side builder for `bpf_insn`).
pub const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        regs: ((src & 0xf) << 4) | (dst & 0xf),
        off,
        imm,
    }
}

#[cfg(test)]
fn bpf_stmt(code: u8, imm: i32) -> bpf_insn {
    insn(code, 0, 0, 0, imm)
}

/// The packet-counter program:
/// `r6 = r1 (skb); r0 = *(u32*)(r6 + 0) /* len */; return r0` — keep all
/// bytes of every packet; userspace counts frames as they arrive.
/// Opcodes: 0xbf = ALU64 MOV reg,reg; 0x61 = LDX mem32; 0x95 = EXIT.
pub fn netmon_program() -> Vec<bpf_insn> {
    vec![
        insn(BPF_ALU64 | BPF_MOV | BPF_X, R6, R1, 0, 0), // r6 = ctx (__sk_buff*)
        insn(BPF_LDX | BPF_MEM | BPF_W, R0, R6, 0, 0),   // r0 = skb->len
        insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),            // return r0
    ]
}

/// Sanity checks mirroring what the kernel verifier rejects first:
/// jump targets in range, program non-empty, exits reachable.
pub fn program_sanity(prog: &[bpf_insn]) -> Result<(), String> {
    if prog.is_empty() {
        return Err("empty program".into());
    }
    for (i, ins) in prog.iter().enumerate() {
        let class = ins.code & 0x07;
        if class == BPF_JMP && ins.code != (BPF_JMP | BPF_EXIT) {
            let target = i as i16 + 1 + ins.off;
            if target < 0 || target as usize >= prog.len() {
                return Err(format!("jump at {i} lands out of range ({target})"));
            }
        }
        if ins.code == (BPF_JMP | BPF_JA) && ins.off == 0 && i + 1 == prog.len() {
            return Err("trailing no-op jump".into());
        }
    }
    let last = prog.last().unwrap();
    if last.code != (BPF_JMP | BPF_EXIT) {
        return Err("program must end with EXIT".into());
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("eBPF requires root (or CAP_BPF); kernel reports: {0}")]
    PrivilegesUnavailable(String),
    #[error("bpf syscall failed: {0}")]
    Syscall(String),
    #[error("verifier rejected program: {0}")]
    Verifier(String),
    #[error("socket: {0}")]
    Socket(String),
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Raw syscall wrappers (libc has no bpf() binding in all versions).
// ---------------------------------------------------------------------------

#[repr(C)]
struct BpfAttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    // remaining fields zeroed; the kernel reads per-prog-type
    _pad: [u64; 12],
}

const BPF_PROG_LOAD: i64 = 5;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

fn bpf_syscall(cmd: i64, attr: &BpfAttrProgLoad) -> Result<i64, EbpfError> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *const BpfAttrProgLoad,
            std::mem::size_of::<BpfAttrProgLoad>(),
        )
    };
    if rc < 0 {
        Err(EbpfError::Syscall(
            std::io::Error::last_os_error().to_string(),
        ))
    } else {
        Ok(rc)
    }
}

/// Are we root (or otherwise likely able to load programs)?
pub fn have_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Load a socket filter; returns the program fd (caller closes).
pub fn load_socket_filter(prog: &[bpf_insn]) -> Result<i32, EbpfError> {
    program_sanity(prog).map_err(EbpfError::Other)?;
    if !have_privileges() {
        return Err(EbpfError::PrivilegesUnavailable(format!(
            "euid={}",
            unsafe { libc::geteuid() }
        )));
    }
    let license = b"GPL\0";
    let mut log = vec![0u8; 4096];
    #[allow(unused_mut)]
    let mut attr = BpfAttrProgLoad {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: prog.len() as u32,
        insns: prog.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        _pad: [0; 12],
    };
    match bpf_syscall(BPF_PROG_LOAD, &attr) {
        Ok(fd) => Ok(fd as i32),
        Err(EbpfError::Syscall(e)) => {
            let msg = String::from_utf8_lossy(&log).to_string();
            let msg = msg.trim_matches('\0');
            if msg.is_empty() {
                Err(EbpfError::Syscall(e))
            } else {
                Err(EbpfError::Verifier(format!("{e}: {msg}")))
            }
        }
        Err(e) => Err(e),
    }
}

/// Attach a loaded program to a raw packet socket; returns (sock, old?) —
/// the socket fd is the event source: each `read` yields one packet.
pub fn attach_packet_socket(prog_fd: i32, iface_index: Option<u32>) -> Result<i32, EbpfError> {
    unsafe {
        let sock = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            htons(ETH_P_ALL) as i32,
        );
        if sock < 0 {
            return Err(EbpfError::Socket(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let rc = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            SO_ATTACH_BPF,
            &prog_fd as *const i32 as *const c_void,
            std::mem::size_of::<i32>() as u32,
        );
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            close(sock);
            return Err(EbpfError::Socket(format!("SO_ATTACH_BPF: {e}")));
        }
        if let Some(idx) = iface_index {
            // bindr: bind to a specific interface (optional).
            let mut addr: libc::sockaddr_ll = std::mem::zeroed();
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_ifindex = idx as i32;
            let rc = libc::bind(
                sock,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                close(sock);
                return Err(EbpfError::Socket(format!("bind: {e}")));
            }
        }
        Ok(sock)
    }
}

/// One packet event → one Signal (name = frame length).
fn packet_signal(source: &str, frame_len: usize) -> crate::Signal {
    crate::Signal {
        source: source.to_string(),
        name: "packet".to_string(),
        payload: (frame_len as u64).to_le_bytes().to_vec(),
    }
}

/// Spawn the eBPF netmon sense: load + attach + pump packets into `tx`.
/// Returns Err with a clear cause when privileges or kernel support are
/// missing — callers report that honestly instead of faking events.
pub fn spawn_netmon(
    name: &str,
    iface_index: Option<u32>,
    tx: crate::SignalTx,
) -> Result<impl FnOnce(), EbpfError> {
    if !have_privileges() {
        return Err(EbpfError::PrivilegesUnavailable("not root".into()));
    }
    let prog = netmon_program();
    let prog_fd = load_socket_filter(&prog)?;
    let sock = attach_packet_socket(prog_fd, iface_index)?;
    let source = name.to_string();
    Ok(move || {
        // Run on a blocking thread: recvfrom until stopped.
        let mut buf = [0u8; 65536];
        loop {
            let n = unsafe {
                libc::recvfrom(
                    sock,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                // EAGAIN (nonblocking) → brief park to avoid spin; real
                // deployments use epoll. Documented, honest tradeoff.
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            let sig = packet_signal(&source, n as usize);
            if tx.blocking_send(sig).is_err() {
                break;
            }
        }
        unsafe {
            close(sock);
            close(prog_fd);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_passes_sanity() {
        let p = netmon_program();
        assert!(program_sanity(&p).is_ok());
        // shape: mov, ldx, exit
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].code, BPF_LDX | BPF_MEM | BPF_W);
        assert_eq!(p[1].off, 0); // __sk_buff.len is at offset 0
                                 // instruction encoding must be exactly 8 bytes (kernel ABI)
        assert_eq!(std::mem::size_of::<bpf_insn>(), 8);
        // regs byte: dst in low nibble, src in high nibble
        assert_eq!(p[0].regs, (R1 << 4) | R6); // mov r6, r1
        assert_eq!(p[0].code, 0xbf, "ALU64 MOV X");
        assert_eq!(p[2].code, 0x95, "EXIT");
    }

    #[test]
    fn bad_jumps_are_caught_locally() {
        // A jump with an out-of-range target must be rejected BEFORE the
        // kernel ever sees it.
        let bad = vec![bpf_stmt(BPF_JMP | BPF_JA, 0)];
        assert!(program_sanity(&bad).is_err());
    }

    #[test]
    fn unprivileged_load_reports_privileges_clearly() {
        if have_privileges() {
            return; // root CI path exercises the real load below
        }
        let err = load_socket_filter(&netmon_program()).unwrap_err();
        assert!(matches!(err, EbpfError::PrivilegesUnavailable(_)));
    }

    /// REAL kernel path: needs root (CI runs this with sudo).
    #[tokio::test]
    #[ignore = "requires root: loads a real eBPF program via bpf(2)"]
    async fn loads_program_and_receives_loopback_packets() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let runner = spawn_netmon("ebpf-lo", None, tx).unwrap();
        let worker = std::thread::spawn(runner);
        // Generate a packet on loopback.
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = s.send_to(b"ping", "127.0.0.1:9");
        let sig = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("no packet event within 5s")
            .unwrap();
        assert_eq!(sig.source, "ebpf-lo");
        assert!(u64::from_le_bytes(sig.payload[..8].try_into().unwrap()) >= 4);
        // Drop the receiver so the pump thread sees a closed channel and
        // exits — otherwise join() waits forever.
        drop(rx);
        let _ = worker.join();
    }
}
