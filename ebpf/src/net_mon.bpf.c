// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Sieveplate L1 reference program: monitor TCP connection state changes.
//
// Hooks the tcp/inet_sock_set_state tracepoint and submits one compact
// event per transition into a BPF ring buffer. Compiled with
//   clang -O2 -g -target bpf -c src/net_mon.bpf.c -o build/net_mon.bpf.o
// and loaded with `bpftool prog load` (see run.sh). The verifier rejects
// anything unsafe at load time — a rejected program is a feature that is
// unavailable, never a kernel crash.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct net_event {
    __u32 family;      // AF_INET=2, AF_INET6=10
    __u8  proto;       // IPPROTO_TCP (6)
    __u8  newstate;    // TCP_ESTABLISHED=1, TCP_CLOSE=7, ...
    __u16 port_be;     // local port, network order
    __u32 local_addr4; // IPv4, network order (0 for v6)
    __u8  local_addr6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

SEC("tracepoint/tcp/inet_sock_set_state")
int on_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct net_event *e;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0; /* ring full: drop the event, never block the kernel */

    e->family     = ctx->family;
    e->proto      = (__u8)ctx->protocol;
    e->newstate   = (__u8)ctx->newstate;
    e->port_be    = (__u16)ctx->sport;

    if (ctx->family == AF_INET) {
        e->local_addr4 = ctx->saddr;
        __builtin_memset(e->local_addr6, 0, sizeof(e->local_addr6));
    } else {
        e->local_addr4 = 0;
        __builtin_memcpy(e->local_addr6, ctx->saddr_v6, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
