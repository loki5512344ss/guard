#ifndef RAMPART_HOOK_API_H
#define RAMPART_HOOK_API_H

/*
 * ── Rampart protocol-hook contract ──
 *
 * The universal XDP filter is protocol-agnostic: it validates L2/L3/L4,
 * tracks the TCP handshake (SYN_RECEIVED → ESTABLISHED), applies
 * blacklist/whitelist/throttle policy — and then delegates deep payload
 * inspection to an optional protocol hook.
 *
 * ── WHAT THE HOOK SEES ──
 *
 *   proto_hook() is called ONLY when:
 *     - packet is TCP, destination port is inside the protected range;
 *     - connection passed SYN throttle and completed the 3-way handshake
 *       (state == STATE_ESTABLISHED);
 *     - the segment carries a non-zero payload.
 *
 *   Pure SYN / SYN-ACK / ACK (handshake segments) NEVER reach the hook:
 *   the hook physically cannot block a clean TCP handshake.
 *   Empty ACKs also never reach the hook (keep-alives pass untouched).
 *
 *   struct cursor  — bounds-checked window over the TCP payload:
 *                     pos = first payload byte, end = one past the last
 *                     byte of the packet (validated against data_end).
 *   struct pkt_meta — read-only metadata: 4-tuple (ports in HOST byte
 *                     order), payload length, full TCP flags byte,
 *                     L3 family.
 *
 * ── VERDICTS ──
 *
 *   XDP_PASS   — accept the segment; filter advances expected_seq by
 *                the consumed payload length and keeps conntrack entry.
 *   XDP_DROP   — drop the segment AND tear down the conntrack entry.
 *   Anything else (XDP_ABORTED etc.) is treated as XDP_PASS; do not
 *   return it.
 *
 * ── RULES FOR HOOK IMPLEMENTATIONS ──
 *
 *   1. Never block handshake traffic — guaranteed by design (see above),
 *      do not try to work around it either.
 *   2. Bounded loops only: every loop must have a compile-time-constant
 *      trip count (or be provably bounded for the verifier), keep total
 *      complexity low — the program must still load with unrolled loops.
 *   3. Every cursor advance MUST be bounds-checked against c->end
 *      (use cursor_take()); reading past c->end is forbidden even if it
 *      seems in-bounds in the packet.
 *   4. Do not update conntrack/throttle/blacklist maps from the hook;
 *      emit events via push_event() if needed (ringbuf, may fail silently).
 *   5. Keep the hook stateless per-call: all per-connection state lives
 *      in conntrack_map, which belongs to the core filter.
 *
 * ── HOW TO ATTACH A HOOK ──
 *
 *   1. Create hooks/<proto>_hook.h containing ONLY your own includes
 *      (common.h etc.) and a definition of proto_hook(). Do NOT include
 *      hook_api.h from the hook header — the core includes it for you:
 *
 *          // hooks/myproto_hook.h
 *          #include "../core/common.h"
 *          static __always_inline enum xdp_action
 *          proto_hook(struct cursor *c, struct pkt_meta *m)
 *          {
 *              ... parse m, advance c ...
 *              return XDP_PASS;   // or XDP_DROP
 *          }
 *
 *   2. Build the object with the macro pointing at your header:
 *
 *      clang -O2 -g -target bpf \
 *            -DRAMPART_PROTO_HOOK='"../hooks/myproto_hook.h"' \
 *            -c xdp/core/universal_filter.c -o universal_filter.o
 *
 *   Without RAMPART_PROTO_HOOK the default no-op stub below is used
 *   and every established connection passes.
 */

#include <linux/bpf.h>
#include "../core/common.h"

// ── Bounds-checked cursor over the payload window ──
struct cursor {
    __u8 *pos; // next unparsed byte
    __u8 *end; // one past last valid byte (== data_end)
};

// Take n bytes from the cursor; returns pointer or NULL on overrun.
static __always_inline __u8 *cursor_take(struct cursor *c, __u32 n)
{
    if (c->pos + n > c->end)
        return NULL;
    barrier_var(c->pos);
    __u8 *p = c->pos;
    c->pos += n;
    return p;
}

// ── Read-only packet metadata handed to the hook ──
struct pkt_meta {
    __u32 src_ip;      // IPv4 addr, or low 32 bits of IPv4-mapped IPv6
    __u32 dst_ip;      // same convention as src_ip
    __u16 src_port;    // host byte order
    __u16 dst_port;    // host byte order
    __u16 payload_len; // TCP payload bytes in this segment
    __u8  tcp_flags;   // full 13th-byte flags field
    __u8  is_ipv6;     // 1 if L3 is IPv4-mapped IPv6
};

#ifdef RAMPART_PROTO_HOOK
#include RAMPART_PROTO_HOOK
#else
/* Default stub: no deep inspection, everything established passes. */
static __always_inline enum xdp_action
proto_hook(struct cursor *c, struct pkt_meta *m)
{
    return XDP_PASS;
}
#endif /* RAMPART_PROTO_HOOK */

#endif /* RAMPART_HOOK_API_H */
