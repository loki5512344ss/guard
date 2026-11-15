#ifndef RAMPART_HOOK_API_H
#define RAMPART_HOOK_API_H

/**
 * Rampart protocol-hook contract.
 *
 * The universal XDP filter is protocol-agnostic: it validates L2/L3/L4,
 * tracks the TCP handshake (SYN_RECEIVED to ESTABLISHED) and applies the
 * blacklist, whitelist and throttle policy. Only then does it delegate deep
 * payload inspection to an optional protocol hook.
 *
 * What the hook sees
 * ------------------
 *
 * proto_hook() is called only when all of the following hold:
 *
 *   - the packet is TCP and its destination port is inside the protected
 *     range;
 *   - the connection passed the SYN throttle and completed the 3-way
 *     handshake (state == STATE_ESTABLISHED);
 *   - the segment carries a non-zero payload.
 *
 * Pure SYN, SYN-ACK and ACK segments never reach the hook, so a hook
 * physically cannot block a clean TCP handshake. Empty ACKs never reach it
 * either: keep-alives pass untouched.
 *
 * Arguments:
 *
 *   struct cursor   bounds-checked window over the TCP payload, where pos is
 *                   the first payload byte and end is one past the last byte
 *                   of the packet (validated against data_end).
 *   struct pkt_meta read-only metadata: the 4-tuple (ports in host byte
 *                   order), payload length, the full TCP flags byte and the
 *                   L3 family.
 *
 * Verdicts
 * --------
 *
 *   XDP_PASS  accept the segment; the filter advances expected_seq by the
 *             consumed payload length and keeps the conntrack entry.
 *   XDP_DROP  drop the segment and tear down the conntrack entry.
 *
 * Any other verdict (XDP_ABORTED and friends) is treated as XDP_PASS, so
 * returning it is never useful.
 *
 * Rules for hook implementations
 * ------------------------------
 *
 *   1. Never block handshake traffic. That is guaranteed by the design
 *      above; do not work around it either.
 *   2. Bounded loops only. Every loop needs a compile-time-constant trip
 *      count, or must be provably bounded for the verifier, and total
 *      complexity must stay low so the program still loads when unrolled.
 *   3. Every cursor advance must be bounds-checked against c->end via
 *      cursor_take(). Reading past c->end is forbidden even when it looks
 *      in-bounds in the packet.
 *   4. Do not update the conntrack, throttle or blacklist maps from the
 *      hook. Emit events through push_event() instead (ring buffer, may
 *      fail silently).
 *   5. Keep the hook stateless per call. All per-connection state lives in
 *      conntrack_map, which belongs to the core filter.
 *
 * How to attach a hook
 * --------------------
 *
 *   1. Create hooks/<proto>_hook.h containing only your own includes
 *      (common.h etc.) and a definition of proto_hook(). Never include
 *      hook_api.h from the hook header, because the core includes it for
 *      you:
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
 *   Without RAMPART_PROTO_HOOK the default no-op stub defined below is used,
 *   and every established connection passes.
 */

#include <linux/bpf.h>
#include "../core/common.h"

/**
 * Bounds-checked cursor over the payload window.
 *
 * A plain pointer pair, so the hook can hand it to cursor_take() without
 * extra state to keep in sync.
 */
struct cursor {
    __u8 *pos; // next unparsed byte
    __u8 *end; // one past last valid byte (== data_end)
};

/**
 * Take n bytes from the cursor.
 *
 * @param c  cursor to advance
 * @param n  number of bytes the caller intends to read
 * @return   pointer to the claimed bytes, or NULL when they would overrun
 *           c->end
 */
static __always_inline __u8 *cursor_take(struct cursor *c, __u32 n)
{
    if (c->pos + n > c->end)
        return NULL;
    barrier_var(c->pos);
    __u8 *p = c->pos;
    c->pos += n;
    return p;
}

/**
 * Read-only packet metadata handed to the hook.
 *
 * Addresses stay in network byte order and ports are converted to host order,
 * so a hook can compare ports directly but must byte-swap addresses before
 * printing them.
 */
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
/**
 * Default hook stub.
 *
 * Performs no deep inspection, so every established connection passes.
 *
 * @param c  payload cursor (unused)
 * @param m  packet metadata (unused)
 * @return   always XDP_PASS
 */
static __always_inline enum xdp_action
proto_hook(struct cursor *c, struct pkt_meta *m)
{
    return XDP_PASS;
}
#endif /* RAMPART_PROTO_HOOK */

#endif /* RAMPART_HOOK_API_H */
