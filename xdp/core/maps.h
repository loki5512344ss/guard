#ifndef RAMPART_MAPS_H
#define RAMPART_MAPS_H

/**
 * IPv4 blacklist.
 *
 * An LPM trie so operators can ban a CIDR range rather than single hosts.
 * The value is the ban expiry as a bpf_ktime_get_ns() timestamp; expired
 * entries are ignored by the packet path and reaped from userspace, which
 * knows the prefix length. BPF_F_NO_PREALLOC is required by the LPM trie
 * type.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct lpm_key);
    __type(value, __u64);       // ban expiry (ktime_ns)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_map SEC(".maps");

/**
 * IPv6 blacklist.
 *
 * LPM trie over 128-bit prefix keys, the exact analogue of blacklist_map:
 * same expiry semantics, same required map flags.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct lpm_key6);
    __type(value, __u64);       // ban expiry (ktime_ns)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist6_map SEC(".maps");

/**
 * Whitelist.
 *
 * LPM trie of trusted CIDRs; the filter consults it before the port gate,
 * conntrack and blacklists so allowlisted traffic can never be throttled or
 * banned away.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_map SEC(".maps");

/**
 * IPv6 whitelist.
 *
 * IPv6 twin of whitelist_map: a 20-byte LPM key (host-order prefixlen
 * followed by 16 address bytes) and the same early position in the packet
 * path. Lookups use prefixlen 128 for the exact source address.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, struct lpm_key6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist6_map SEC(".maps");

/**
 * Connection tracking table (SYN_RECEIVED to ESTABLISHED).
 *
 * LRU so a flood of half-open flows evicts old entries instead of failing
 * map updates; RST/FIN removes entries explicitly on the normal path. Only
 * new connections are policed: a non-SYN segment whose entry was evicted
 * passes, because this is a stateless filter, not a firewall.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct conntrack_entry);
} conntrack_map SEC(".maps");

/**
 * Per-source SYN throttle state.
 *
 * LRU keeps memory bounded under spoofed-source floods, where the number of
 * distinct keys is unbounded and an exact table would simply fill up.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // src_ip
    __type(value, struct throttle_entry);
} connection_throttle SEC(".maps");

/**
 * Per-source UDP rate-limit state.
 *
 * The window and threshold come from G_UDP_POLICY / G_UDP_HIT_COUNT, so the
 * same map serves pass, drop and rate-limit modes without reloading.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // src_ip
    __type(value, struct throttle_entry);
} udp_rate_limit SEC(".maps");

/**
 * IPv6 twin of udp_rate_limit.
 *
 * Native IPv6 has no 32-bit source address to key on, so the key is the full
 * 128-bit address; the value and window contract are identical.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct in6_addr);   // src6
    __type(value, struct throttle_entry);
} udp_rate_limit6 SEC(".maps");

/**
 * RST-challenge pending state, one record per challenged flow.
 *
 * marker is our chosen ISN and bad_ack is the deliberately unacceptable
 * acknowledgement we sent; either one echoed back proves the source saw the
 * challenge, so both are kept until the proof arrives or the TTL expires.
 */
struct challenge_pending {
    __u64 sent_at;   // ktime_ns of the reflected SYN-ACK
    __u32 marker;    // our ISN (client may echo it as ack)
    __u32 bad_ack;   // bogus ack sent (live client echoes it as RST seq)
};

/**
 * Sources that already passed the RST challenge.
 *
 * The value is the last time the source proved liveness: the TTL is slid
 * forward on each verified SYN, and LRU eviction is the hard cap when more
 * sources are active than the table holds.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);             // src_ip
    __type(value, __u64);           // last_seen (ktime_ns)
} challenge_verified SEC(".maps");

/**
 * Outstanding challenges, keyed by the flow 4-tuple.
 *
 * Keyed per flow rather than per source so two concurrent connections from
 * the same host cannot overwrite each other's expected proof.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct challenge_pending);
} challenge_pending SEC(".maps");

/**
 * Statistics counters, indexed by the STAT_* constants below.
 *
 * Per-CPU array: increments need no atomics between CPUs, userspace sums the
 * per-CPU values when it reads the map.
 */
#define STAT_TOTAL        0
#define STAT_TCP          1
#define STAT_WHITELIST    2
#define STAT_BLACKLIST    3
#define STAT_SYN_THROTTLE 4
#define STAT_PASS         5
#define STAT_DROP         6
#define STAT_UDP          7
#define STAT_RATE_LIMIT   8
#define STAT_CHALLENGE_SENT     9
#define STAT_CHALLENGE_VERIFIED 10
#define STAT_CHALLENGE_FAILED   11
#define STAT_FRAGMENT_BYPASS    12

/**
 * Per-CPU counter storage.
 *
 * max_entries is rounded up past the highest STAT_* index so slots can be
 * added without touching the map definition.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#endif /* RAMPART_MAPS_H */
