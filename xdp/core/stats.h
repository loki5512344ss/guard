#ifndef RAMPART_STATS_H
#define RAMPART_STATS_H

#include "common.h"
#include "maps.h"

/**
 * Increment one per-CPU counter.
 *
 * A missing slot (never updated, or an index past max_entries) is ignored so
 * accounting can never change a packet verdict.
 *
 * @param idx  STAT_* index into stats_map
 */
static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/**
 * Named wrappers over inc_stat().
 *
 * They keep call sites readable and make the counter a decision of the call
 * site rather than a magic index, so new counters need no edits here.
 */
static __always_inline void inc_total(void)        { inc_stat(STAT_TOTAL); }
static __always_inline void inc_tcp(void)          { inc_stat(STAT_TCP); }
static __always_inline void inc_udp(void)          { inc_stat(STAT_UDP); }
static __always_inline void inc_whitelist(void)    { inc_stat(STAT_WHITELIST); }
static __always_inline void inc_blacklist(void)    { inc_stat(STAT_BLACKLIST); }
static __always_inline void inc_syn_throttle(void) { inc_stat(STAT_SYN_THROTTLE); }
static __always_inline void inc_rate_limit(void)   { inc_stat(STAT_RATE_LIMIT); }
static __always_inline void inc_chal_sent(void)     { inc_stat(STAT_CHALLENGE_SENT); }
static __always_inline void inc_chal_verified(void) { inc_stat(STAT_CHALLENGE_VERIFIED); }
static __always_inline void inc_chal_failed(void)   { inc_stat(STAT_CHALLENGE_FAILED); }
static __always_inline void inc_pass(void)         { inc_stat(STAT_PASS); }
static __always_inline void inc_drop(void)         { inc_stat(STAT_DROP); }

#endif /* RAMPART_STATS_H */
