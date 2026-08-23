#ifndef RAMPART_MAPS_H
#define RAMPART_MAPS_H

// 🔗 Blacklist (LPM_TRIE for CIDR support)
// Cleared by Rust userspace or per-entry expiry via ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct lpm_key);
    __type(value, __u64);       // ban expiry (ktime_ns)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_map SEC(".maps");

// 🔗 Whitelist (LPM_TRIE for CIDR) — checked before any filter
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_map SEC(".maps");

// 🔗 Connection tracking (SYN_RECEIVED → ESTABLISHED)
// LRU — автоматическое вытеснение старых записей
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct conntrack_entry);
} conntrack_map SEC(".maps");

// 🔗 SYN throttle per-source-IP (LRU)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // src_ip
    __type(value, struct throttle_entry);
} connection_throttle SEC(".maps");

// 🔗 UDP rate limit per-source-IP (LRU) — policy from config.h
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // src_ip
    __type(value, struct throttle_entry);
} udp_rate_limit SEC(".maps");

// 🔗 Statistics (per-CPU, атомарные инкременты)
#define STAT_TOTAL        0
#define STAT_TCP          1
#define STAT_WHITELIST    2
#define STAT_BLACKLIST    3
#define STAT_SYN_THROTTLE 4
#define STAT_PASS         5
#define STAT_DROP         6
#define STAT_UDP          7
#define STAT_RATE_LIMIT   8

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#endif /* RAMPART_MAPS_H */
