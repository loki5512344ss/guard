#ifndef RAMPART_COMMON_H
#define RAMPART_COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP  0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_OFFSET 0x1FFF
#define IP_MF 0x2000

// ── Protocol-agnostic TCP state machine ──
enum connection_state {
    STATE_SYN_RECEIVED = 0, // SYN seen, waiting for ACK (handshake completing)
    STATE_ESTABLISHED  = 1, // handshake done; payload handed to proto_hook()
};

// ── Flow key (4-tuple for connection tracking) ──
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// ── Connection tracking entry ──
// LRU maps evict stale entries automatically when full; RST/FIN removes
// entries explicitly. last_seen supports future timer-based idle cleanup.
struct conntrack_entry {
    __u32 state;
    __u32 expected_seq;
    __u32 src_ip;
    __u64 last_seen;
    __u16 src_port;
    __u8 fails;
};

// ── SYN / UDP throttle entry ──
struct throttle_entry {
    __u64 window_start;
    __u32 hits;
};

// ── LPM key for blacklist/whitelist ──
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

// ── Ringbuf event (userspace receives these) ──
enum event_type {
    EVENT_BAN          = 0,
    EVENT_RATE_LIMIT   = 1,
    EVENT_POLICY_DROP  = 2,
    EVENT_CONN_DROP    = 3,
};

struct xdp_event {
    __u32 type;
    __u32 src_ip;
    __u32 metadata;
    __u64 timestamp;
};

// ── Bounds check macros (dual-bounds для verifier) ──
#define CHECK_BOUNDS_OR_RETURN(ptr, sz, pend, dend)     \
    do {                                                 \
        if ((void *)(ptr) + (sz) > (void *)(dend))       \
            goto error;                                  \
        barrier_var(ptr);                                \
        if ((void *)(ptr) + (sz) > (void *)(pend))       \
            goto error;                                  \
    } while (0)

#define barrier_var(var) asm volatile("" : "+r"(var))

// ── Ringbuf for events → userspace (declared here for push_event) ──
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_ringbuf SEC(".maps");

// ── Event push to ringbuf ──
static __always_inline void push_event(enum event_type type, __u32 src_ip, __u32 meta)
{
    struct xdp_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct xdp_event), 0);
    if (!e)
        return;
    e->type = type;
    e->src_ip = src_ip;
    e->metadata = meta;
    e->timestamp = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
}

#endif /* RAMPART_COMMON_H */
