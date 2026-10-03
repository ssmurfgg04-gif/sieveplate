#!/bin/sh
# Build the sieveplate seL4 (Microkit) system.
# Usage: build.sh <path-to-microkit-sdk> <board>   (board: qemu_virt_aarch64)
# Output: build/loader.img (the seL4 + PDs boot image)
#
# Microkit 2.x layout: board/<board>/<config>/{include,lib,elf}; the tool
# is bin/microkit. Flags follow the SDK's example Makefiles.
set -eu

SDK="$1"
BOARD="$2"
CONFIG="${CONFIG:-release}"
ARCH="aarch64"
CC="${CC:-clang}"
LD="${LD:-ld.lld}"

TOOL="$SDK/bin/microkit"
[ -x "$TOOL" ] || { echo "Microkit tool not found at $TOOL" >&2; exit 2; }
BOARD_DIR="$SDK/board/$BOARD/$CONFIG"
[ -d "$BOARD_DIR" ] || { echo "Board dir not found: $BOARD_DIR" >&2; exit 2; }

echo "building sieveplate seL4 system for $BOARD ($CONFIG)"
mkdir -p build
$CC \
    --target=$ARCH-none-elf -mcpu=cortex-a53 -mstrict-align \
    -nostdlib -ffreestanding -fno-builtin \
    -O3 -Wall -Wextra \
    -I"$BOARD_DIR/include" \
    -c cell.c -o build/cell.o
$LD \
    -T"$BOARD_DIR/lib/microkit.ld" \
    -L"$BOARD_DIR/lib" \
    build/cell.o -lmicrokit \
    -o build/cell.elf
$TOOL \
    --board "$BOARD" \
    --config "$CONFIG" \
    --search-path build \
    -o build/loader.img \
    cell.system
echo "built build/loader.img"
