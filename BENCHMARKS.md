# Benchmarks — what every number actually measures

> Rule for this document, learned the hard way: **a benchmark may claim
> only what it measures.** In-process message passing is not a VM boot.
> Evicting an actor is not a process exit. Nothing here is compared
> against a different kind of cost.

Environment: release build, Linux x86-64, one containerized cloud core.
Reproduce: `cargo run -p sieveplate-ctl --release -- bench --suite all`.

## Results

| benchmark | n | p50 | p95 | what it measures |
|---|---|---|---|---|
| turn: call round-trip (in-proc) | 2000 | 15 µs | 23 µs | one request/reply between two actor cells in the same host, same process |
| wake: scale-to-zero → wake cycle | 200 | 29 µs | 34 µs | actor eviction to CAS stub + restore-on-message **within the same process** |
| store: put 4 KiB | 1000 | 3 µs | 3 µs | SHA-256 + write + hash-file rename, local disk, warm cache |
| store: get + verify 4 KiB | 1000 | 5 µs | 6 µs | read + SHA-256 re-verify |
| cells: create | 200 | 20 µs | 27 µs | template instantiation + cap table wiring (in-proc) |
| cells: scale-to-zero (snapshot→CAS) | 200 | 23 µs | 35 µs | serialize + persist + drop from memory (in-proc) |
| **jail: process cell spawn** | 20 | **1.14 ms** | 1.36 ms | REAL `fork+exec`, environment wiped, seccomp filter applied, Landlock attempted, worker init handshake |
| **jail: first turn round-trip** | 20 | **71 µs** | 84 µs | envelope through length-prefixed pipe, handled in the jailed process, capability re-check at the parent, reply back |
| **handshake: SIEVE1 full** | 50 | **3.6 ms** | 5.3 ms | complete secure-link handshake: X25519 DH + ML-KEM-768 encapsulation, Ed25519 + ML-DSA-65 dual signature generation AND verification, HKDF key schedule |
| **wasm: turn (WASI cell)** | 2 ticks | **2.1 ms** | 2.1 ms | ONE message into a Wasmtime WASI cell: fresh instance per turn + state re-materialization + JSON stdin/stdout + CAS persist. Instance creation dominates; thread cells are the low-latency path (µs) |


## sieveplate vs standard Linux — same machine, same run (`--suite linux`)

The `linux` suite measures STANDARD Linux primitives in the same process
as the sieveplate rows, on the same core, in the same run. Nothing is
compared across machines, and no row claims to equal another row's cost
category — the point is calibration, not victory:

| benchmark | n | p50 | what it is |
|---|---|---|---|
| linux: UDS round-trip (64 B) | 2000 | ~22 µs | Unix domain socket, echo server task |
| linux: TCP loopback round-trip (64 B) | 2000 | ~29 µs | loopback TCP, same payload |
| linux: pipe round-trip (64 B, 2 pipes) | 2000 | ~13 µs | two OS pipes + a blocking thread — the cheapest kernel-mediated IPC |
| linux: fork+exec /bin/true (wait) | 50 | ~275 µs | the floor for ANY process-based isolation |
| linux: SIEVE1 sealed round-trip (64 B) | 2000 | ~277 µs | the SAME UDS path but each frame sealed: ChaCha20-Poly1305 seal + open, per-direction nonces, sequence replay check |

Reading these honestly:

- The in-proc cell turn (15 µs) is **not** OS-mediated; the pipe row is
  shown only to calibrate what the kernel's cheapest IPC costs.
- A process cell (`jail` rows, ~1.1 ms spawn / ~71 µs turn) sits close to
  the fork+exec floor (~275 µs on the runner) plus seccomp/Landlock setup
  and the mediated-pipe protocol — isolation is paid for where it is used.
- The SIEVE1 sealed round-trip (~277 µs) vs raw UDS (~22 µs) is what
  hybrid post-quantum confidentiality costs per message at 64 B — about
  12× on this machine. When a link does not need it, that is a real
  reason not to have it; sieveplate always has it (no plaintext mode).
- CI re-measures all of this on `ubuntu-latest` on every run of
  `bench-vs-linux.yml` — the numbers above are from a dev container, the
  workflow's step summary is the runner's own fresh measurement.

Reproduce locally: `cargo run -p sieveplate-ctl --release -- bench --suite linux --json out.json`.

Mesh note (measured in tests, not a benchmark suite): a 3-host line
converges in triggered announcements (link-up/down events only — no
periodic timer) and reroutes around a dead relay within a few
announcement rounds; delivery across 2 hops costs two additional
loopback forwards per direction. See `crates/sieveplate-ctl/tests/mesh.rs`.

The `jail` and `handshake` rows exist because the in-process rows say
nothing about them. A process spawn costs ~55× a cell create; a
cross-process turn costs ~5× an in-process turn; a hybrid-PQ handshake
costs ~240× an unencrypted connect. Those are the prices of the
guarantees, measured, not hidden.

## What these numbers do NOT measure

- **VM boot.** No Firecracker/Unikraft boot is benchmarked (no KVM in the
  measurement environment). MicroVM cell templates are config-tested, and
  launch refuses to run without KVM rather than faking it.
- **Network RTT.** `handshake` and `turn` rows run over in-memory duplex
  or loopback sockets; add real wire latency for cross-host numbers.
- **seL4/Microkit cells.** The seL4 port target has its own CI job
  (build + QEMU boot smoke); it publishes no latency numbers.
- **Throughput at saturation.** Rows are latency under light load.
- **eBPF sense path.** Loading and packet delivery are functional-tested
  (as root in CI), not benchmarked here.

## Against the original spec's targets

The spec set millisecond-class cell lifecycle and scale-to-zero < 10 ms.
The in-process rows meet those targets. That statement is now scoped
exactly: **in-process**. Process-isolated cells are ~1 ms to spawn (still
under the millisecond-class target on this hardware) and true VM cells
are gated on hardware we do not claim to have benchmarked.

## Historical note

An earlier revision of this document compared the 15 µs in-process turn
against a 176 ms Firecracker boot and printed "beats the spec by
30–550×". That comparison was invalid — an actor message-passing RTT and
a VM boot are different cost categories — and the claim was removed. The
correct comparison for isolation costs is now in the table above, measured
in this repo instead of imported from a different one.
