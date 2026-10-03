#!/usr/bin/env bash
# Sieveplate L1 reference bridge: load the eBPF program and stream kernel
# events as JSON lines into the file sense source. Requires root.
#
#   sudo ./run.sh [output.jsonl] [interface-index]
#
# The runtime consumes the stream with a `file` sense (inotify-driven) —
# see ebpf/README.md for the wiring.
set -euo pipefail

OBJ=${OBJ:-build/net_mon.bpf.o}
OUT=${1:-/var/tmp/sieve-events.jsonl}
IFINDEX=${2:-1}

command -v bpftool >/dev/null || { echo "bpftool required" >&2; exit 1; }
[ -f "$OBJ" ] || { echo "build first: make" >&2; exit 1; }

BPFFS=/sys/fs/bpf
PIN_PROG="$BPFFS/sieveplate_net_mon"
PIN_MAP="$BPFFS/sieveplate_events"

mkdir -p "$(dirname "$OUT")"
touch "$OUT"

cleanup() {
    bpftool map delete pinned "$PIN_MAP" 2>/dev/null || true
    bpftool prog unload pinned "$PIN_PROG" 2>/dev/null || true
    rm -f "$PIN_PROG" "$PIN_MAP"
}
trap cleanup EXIT

echo "loading $OBJ ..."
bpftool prog load "$OBJ" "$PIN_PROG" \
    map name events pinned "$PIN_MAP" 2>/dev/null \
|| bpftool prog loadall "$OBJ" "$BPFFS" 2>/dev/null

echo "attaching tracepoint tcp/inet_sock_set_state (ifindex $IFINDEX) ..."
ID=$(bpftool prog show pinned "$PIN_PROG" | awk '/^[0-9]+:/{print $1}' | cut -d: -f1)
bpftool prog attach "$ID" tracepoint inet_sock_set_state 2>/dev/null \
|| bpftool trace attach "$PIN_PROG" tracepoint inet_sock_set_state 2>/dev/null \
|| echo "NOTE: attach via bpftool failed; use a minimal libbpf loader for production." >&2

echo "streaming events -> $OUT (Ctrl-C to stop)"
# Consume the ring buffer and emit JSON lines. bpftool's ringbuf user-space
# consumer is deliberately minimal here; production should mmap the ring
# directly (see ebpf/README.md).
bpftool map dump pinned "$PIN_MAP" 2>/dev/null | while read -r line; do
    printf '{"name":"tcp_state","payload":"%s"}\n' "$line" >> "$OUT"
done
