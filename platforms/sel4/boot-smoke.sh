#!/bin/sh
# Boot seL4 under QEMU and require the sieveplate banner on the console.
# Usage: boot-smoke.sh
set -eu
cd "$(dirname "$0")"

if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
    echo "qemu-system-aarch64 not installed" >&2
    exit 2
fi
[ -f build/loader.img ] || { echo "build/loader.img missing — run build.sh first" >&2; exit 2; }

timeout 30 qemu-system-aarch64 \
    -machine virt,virtualization=on \
    -cpu cortex-a53 \
    -nographic \
    -m size=2G \
    -kernel build/loader.img \
    > qemu.log 2>&1 || true

if grep -q "sieveplate-seL4-cell boot OK" qemu.log; then
    echo "seL4 boot smoke: OK"
else
    echo "seL4 boot smoke FAILED — console output:" >&2
    cat qemu.log >&2
    exit 1
fi
