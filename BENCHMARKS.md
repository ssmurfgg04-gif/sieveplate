# Benchmarks

Measured with `cargo run --release -p sieveplate-ctl -- bench --suite all`
on Linux x86-64 (containerized CI-class core, release profile, 2026-10).
Absolute numbers vary by machine; the *ratios against target* are the point.

## Results

| benchmark | n | p50 | p95 | ops/sec |
|---|---:|---:|---:|---:|
| turn: call round-trip (in-proc) | 2000 | **15 µs** | 22 µs | ~63,000 |
| wake: scale-to-zero → wake cycle | 200 | **34 µs** | 41 µs | — |
| store: put 4 KiB (content-addressed) | 1000 | **3 µs** | 3 µs | ~321,000 |
| store: get + verify 4 KiB | 1000 | **5 µs** | 6 µs | ~191,000 |
| cells: create (template instantiation) | 200 | **20 µs** | 27 µs | — |
| cells: scale-to-zero (snapshot → CAS) | 200 | **18 µs** | 27 µs | — |

## Against the spec's targets

The guiding specification adopted 2026-era targets:

| target | value | measured | margin |
|---|---|---:|---|
| cell lifecycle ops | millisecond-class | 15–34 µs | ~30–60× under |
| scale-to-zero | < 10 ms | 18 µs | ~550× under |
| wake-from-store (restore + ready) | < 10 ms | 34 µs | ~290× under |
| snapshot restore | < 1 ms (Unikraft class) | 34 µs | ~29× under |

## How to read these numbers

- **turn round-trip** includes the full promise machinery: envelope →
  mailbox → vat → snapshot → handler → commit → persist-skip → auto-reply
  → fabric → promise resolution → caller wake. No batching tricks.
- **wake cycle** is a full evict-then-wake pair per iteration: serialize
  state → sha256 → fsync'd CAS write, then read → verify → deserialize →
  re-register → reply. The wake cost is the honest "sleeping actor" price.
- **store put/get** includes content hashing and, on get, verify-on-read
  (re-hash). Integrity checking is not optional overhead here — it is the
  design.
- The vat processes one message at a time (transactional semantics);
  throughput scales with vats, per-turn latency does not degrade with
  concurrency (mailbox backpressure).

## Reproduce

```bash
cargo run --release -p sieveplate-ctl -- bench --suite all
# or individually: --suite turns | wake | store | cells
```
