# ebpf — L1 kernel-event bridge

The spec's L1: hardware/kernel events become cell messages with zero
kernel modification and zero polling. There are now TWO real paths:

1. **In-process loader** (`sieveplate-senses::ebpf`) — the primary path.
   Builds raw `bpf_insn` (no LLVM), loads a socket filter via the
   `bpf(2)` syscall, attaches to `AF_PACKET` with `SO_ATTACH_BPF`, and
   feeds packet events straight into the signal pump. Requires
   root/CAP_BPF on modern kernels; **the privilege requirement is an
   explicit error, never faked**. CI runs the real load-and-receive test
   as root (`sudo cargo test -p sieveplate-senses -- --ignored`).
2. **Reference C bridge** (this directory) — a bpftool-based program +
   JSON-lines stream into the file sense. Kept as the documented
   reference for kernel-event shapes; see the table below.

```
kernel event ──▶ eBPF program ──▶ ring buffer ──▶ bpftool/cat ──▶ events.jsonl
                                                                      │ inotify (event-driven)
                                                                      ▼
                                                    sieve file-sense ─▶ pump ─▶ fabric ─▶ cell
```

## Contents

| file | program | hooks |
|---|---|---|
| `src/net_mon.bpf.c` | TCP connection monitor | tracepoint `tcp/inet_sock_set_state` |

## Build & run (requires root + clang + bpftool)

```bash
cd ebpf
make                      # clang -target bpf → build/net_mon.bpf.o
sudo ./run.sh             # attaches, streams events → /var/tmp/sieve-events.jsonl
```

Then point a `file` sense at the stream:

```toml
[[sense]]
name = "kernel"
kind = "file"
path = "/var/tmp/sieve-events.jsonl"

[[route]]
from = "sense:kernel"
to = "core/watcher"
```

Every TCP connection change in the kernel now wakes (and rolls) the
`watcher` cell. Disconnect `run.sh` and the stream simply goes quiet —
the cell scales to zero and the system returns to idle.

## Design notes

- **JSON lines, not libbpf-in-process.** Keeping the kernel-side loader as
  a separate process (`bpftool prog load` + pinned map/pipe) means the
  Rust runtime needs zero privileged dependencies, and a buggy loader can
  never take the runtime down. The inotify consumption path is identical
  to any other file sense, so cell code doesn't know or care whether the
  line came from eBPF, a script, or a test.
- **Verifier-safe by construction.** The programs use only bounded ring
  buffer submissions and CO-RE reads; `bpftool prog load` refuses anything
  the verifier rejects — a failed load is a *feature unavailable*, never a
  kernel crash (the spec's failure-modes table, row 6).
- **Production path.** For high event rates, replace the JSONL pipe with
  an mmap'd BPF ring buffer consumer inside `sieveplate-senses` (aya- or
  libbpf-rs-based, feature-gated). The cell-facing interface — `Signal`
  with a name and payload — does not change.
