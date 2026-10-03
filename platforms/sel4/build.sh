#!/bin/sh
# Build the sieveplate seL4 (Microkit) system.
# Usage: build.sh <path-to-microkit-sdk> <board>   (board: qemu_virt_aarch64)
# Output: build/loader.img (the seL4 + PDs boot image)
set -eu

SDK="$1"
BOARD="$2"
ARCH="aarch64"
CC="${CC:-clang}"

if [ ! -x "$SDK/microkit" ]; then
    echo "Microkit tool not found at $SDK/microkit" >&2
    exit 2
fi

BOARD_DIR="$SDK/board/$BOARD"
LOADER_LD="$BOARD_DIR/loader.ld"
KERNEL="$BOARD_DIR/kernel"

echo "building sieveplate seL4 system for $BOARD"
echo "  sdk:      $SDK"
echo "  loader.ld: $LOADER_LD"
mkdir -p build
$CC \
    --target=$ARCH-none-elf -mcpu=cortex-a53 \
    -nostdlib -ffreestanding -fno-stack-protector \
    -O3 -Wall -Wextra \
    -I"$SDK/include" \
    -c cell.c -o build/cell.o
$CC \
    --target=$ARCH-none-elf -mcpu=cortex-a53 \
    -nostdlib -ffreestanding \
    -L"$SDK/lib" \
    -T"$LOADER_LD" \
    build/cell.o -o build/cell.elf -lmicrokit
"$SDK/microkit" build.py \
    --sdf cell.system \
    --board "$BOARD" \
    --kernel "$KERNEL" \
    --image build/loader.img
echo "built build/loader.img"
