#ifndef RAMPART_STATS_H
#define RAMPART_STATS_H

#include "common.h"
#include "maps.h"

// ── Per-CPU stat increment ──
static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// ── Convenience wrappers ──
static __always_inline void inc_total(void)   { inc_stat(STAT_TOTAL); }
static __always_inline void inc_tcp_mc(void)  { inc_stat(STAT_TCP_MC); }
static __always_inline void inc_whitelist(void)  { inc_stat(STAT_WHITELIST); }
static __always_inline void inc_blacklist(void)  { inc_stat(STAT_BLACKLIST); }
static __always_inline void inc_syn_throttle(void) { inc_stat(STAT_SYN_THROTTLE); }
static __always_inline void inc_pass(void)    { inc_stat(STAT_PASS); }
static __always_inline void inc_drop(void)    { inc_stat(STAT_DROP); }
static __always_inline void inc_verified(void){ inc_stat(STAT_VERIFIED); }

#endif /* RAMPART_STATS_H */
