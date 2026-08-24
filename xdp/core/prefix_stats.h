#ifndef RAMPART_PREFIX_STATS_H
#define RAMPART_PREFIX_STATS_H

#include "common.h"

// ── Per-prefix traffic statistics (shared ABI with Rust userspace) ──
// Layout is part of the userspace contract — do not reorder fields.

// family: 4 = IPv4 /24 префикс, 6 = IPv6 /64 префикс
struct prefix_key {
    __u8 family;
    __u8 pad[7];
    __u8 addr[16];   // network-order байты префикса, zero-padded
};

struct prefix_stats_val {
    __u64 syn_count;
    __u64 pkt_count;
    __u64 last_seen_ns;   // bpf_ktime_get_ns()
};

// 🔗 Prefix statistics (LRU) — читается и сбрасывается юзерспейсом
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct prefix_key);
    __type(value, struct prefix_stats_val);
} prefix_stats SEC(".maps");

#define PREFIX_FAMILY_V4 4
#define PREFIX_FAMILY_V6 6

// ── Build /24 IPv4 prefix key (network-order, low 8 bits masked out) ──
static __always_inline void prefix_key_from_v4(struct prefix_key *key,
                                               __u32 src_ip_net_order)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = PREFIX_FAMILY_V4;
    __builtin_memcpy(key->addr, &src_ip_net_order, 4);
    key->addr[3] = 0; // обнулить младшие 8 бит адреса
}

// ── Build /64 IPv6 prefix key (network-order, low 64 bits masked out) ──
static __always_inline void prefix_key_from_v6(struct prefix_key *key,
                                               const __u8 src_addr[16])
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = PREFIX_FAMILY_V6;
    __builtin_memcpy(key->addr, src_addr, 8);
}

// ── Increment per-prefix counters (sliding window handled in userspace) ──
// is_syn: 1 → syn_count++, 0 → pkt_count++; last_seen_ns updated всегда.
static __always_inline void update_prefix_stats(struct prefix_key *key,
                                                __u8 is_syn, __u64 now)
{
    struct prefix_stats_val *val = bpf_map_lookup_elem(&prefix_stats, key);

    if (!val) {
        struct prefix_stats_val init = {
            .syn_count   = is_syn ? 1 : 0,
            .pkt_count   = is_syn ? 0 : 1,
            .last_seen_ns = now,
        };
        bpf_map_update_elem(&prefix_stats, key, &init, BPF_ANY);
        return;
    }

    if (is_syn)
        __sync_fetch_and_add(&val->syn_count, 1);
    else
        __sync_fetch_and_add(&val->pkt_count, 1);
    val->last_seen_ns = now;
}

#endif /* RAMPART_PREFIX_STATS_H */
