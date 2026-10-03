# Sieveplate L1 reference bridge — build the eBPF object.
# Requires: clang (with BPF backend), bpftool (for vmlinux.h generation
# via `bpftool btf dump file /sys/kernel/btf/vmlinux format c`).

CLANG ?= clang
INC ?= ./include
SRC := src/net_mon.bpf.c
OBJ := build/net_mon.bpf.o

.PHONY: all clean vmlinux.h

all: $(OBJ)

build:
	mkdir -p build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

$(OBJ): $(SRC) | build
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 \
		-I$(INC) \
		-c $(SRC) -o $@

clean:
	rm -rf build
