#ifndef RAMPART_COMMON_H
#define RAMPART_COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP  0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_FRAGMENT 44
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60
/* Extension headers walked before giving up; a longer chain is treated as
 * "L4 not found" (source blacklist only), never as a free pass. */
#define RAMPART_V6_MAX_EXT 4
#define IP_OFFSET 0x1FFF
#define IP_MF 0x2000

/**
 * One 802.1Q / 802.1ad tag.
 *
 * The filter only needs the encapsulated EtherType to skip up to two tags
 * before L3; the TCI (PCP/DEI/VID) has no bearing on L3/L4 policy.
 */
struct rampart_vlan_hdr {
    __u16 tci;          // PCP/DEI/VID, unused
    __u16 encap_proto;  // EtherType of the next header
};

/**
 * First two bytes shared by every IPv6 extension header that carries a length
 * (hop-by-hop, routing, destination options, AH).
 */
struct rampart_ipv6_ext {
    __u8 nexthdr;
    __u8 hdrlen;  // 8-byte units minus 1 (AH: 4-byte units minus 2)
};

/**
 * Protocol-agnostic TCP connection states.
 *
 * A connection enters the map on the first bare SYN and advances only when
 * the handshake completes; payload inspection is reachable from ESTABLISHED
 * only, so no state can be skipped.
 */
enum connection_state {
    STATE_SYN_RECEIVED = 0, // SYN seen, waiting for ACK (handshake completing)
    STATE_ESTABLISHED  = 1, // handshake done; payload handed to proto_hook()
};

/**
 * Flow key identifying one connection: the classic 4-tuple.
 *
 * Addresses and ports stay in network byte order; this key is only ever
 * built and compared inside the BPF program.
 */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/**
 * Native IPv6 flow key: full 128-bit addresses plus ports, network order.
 */
struct flow_key6 {
    __u8  src[16];
    __u8  dst[16];
    __u16 src_port;
    __u16 dst_port;
};
_Static_assert(sizeof(struct flow_key6) == 36, "flow_key6 size");

/**
 * Connection tracking entry.
 *
 * LRU maps evict stale entries automatically when full; RST/FIN removes
 * entries explicitly. last_seen supports future timer-based idle cleanup.
 * expected_seq is the next in-order sequence number we accept on the
 * server-to-client direction.
 */
struct conntrack_entry {
    __u32 state;
    __u32 expected_seq;
    __u32 src_ip;
    __u64 last_seen;
    __u16 src_port;
    __u8 fails;
};

/**
 * Fixed-window throttle state for one source address.
 *
 * window_start is a bpf_ktime_get_ns() timestamp, so windows survive
 * wall-clock jumps; hits resets whenever the window rolls over.
 */
struct throttle_entry {
    __u64 window_start;
    __u32 hits;
    /* Explicit padding: the verifier rejects helper reads of uninitialised
     * stack bytes, and implicit padding is not zeroed by the compiler. The
     * struct size (16) is unchanged. */
    __u32 pad;
};

/**
 * LPM trie key for IPv4 blacklist and whitelist entries.
 *
 * prefixlen is in host byte order, the address in network byte order, which
 * is the layout the kernel expects for BPF_MAP_TYPE_LPM_TRIE.
 */
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

/**
 * LPM trie key for IPv6 blacklist entries.
 *
 * Same layout as bpf_lpm_trie_key: host-order prefix length followed by 16
 * address bytes, 20 bytes in total.
 */
struct lpm_key6 {
    __u32 prefixlen;
    __u8  addr[16];
};

/**
 * Event kinds that userspace can receive and react to.
 */
enum event_type {
    EVENT_BAN          = 0,
    EVENT_RATE_LIMIT   = 1,
    EVENT_POLICY_DROP  = 2,
    EVENT_CONN_DROP    = 3,
};

/**
 * Ring buffer event record handed to userspace.
 *
 * src_ip is always IPv4 (or the low 32 bits of an IPv4-mapped address)
 * because the record format is part of the userspace ABI; native IPv6
 * drops are therefore not reported.
 */
struct xdp_event {
    __u32 type;
    __u32 src_ip;
    __u32 metadata;
    __u64 timestamp;
};

/**
 * Dual bounds check for the verifier.
 *
 * A read of sz bytes at ptr is rejected unless it fits inside both the
 * provisional end pointer (pend) and the packet tail (dend). barrier_var()
 * keeps ptr in a register so the verifier does not lose the narrowed range
 * on the second comparison. The caller must provide an error: label.
 */
#define CHECK_BOUNDS_OR_RETURN(ptr, sz, pend, dend)     \
    do {                                                 \
        if ((void *)(ptr) + (sz) > (void *)(dend))       \
            goto error;                                  \
        barrier_var(ptr);                                \
        if ((void *)(ptr) + (sz) > (void *)(pend))       \
            goto error;                                  \
    } while (0)

/**
 * Pin a pointer in a register.
 *
 * The empty asm block gives the value a register home, which stops the
 * verifier from widening a range it already proved.
 */
#define barrier_var(var) asm volatile("" : "+r"(var))

/**
 * Ring buffer carrying events to userspace.
 *
 * Declared next to push_event() rather than in maps.h so every program that
 * includes this header gets the producer side without extra wiring.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_ringbuf SEC(".maps");

/**
 * Publish one event to userspace.
 *
 * Fire-and-forget: a full or missing ring buffer silently drops the record
 * because event reporting must never change the packet verdict.
 *
 * @param type    event kind stored in the record
 * @param src_ip  source address, network byte order
 * @param meta    event-specific value, e.g. the threshold that fired
 */
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
