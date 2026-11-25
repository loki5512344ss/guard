#ifndef RAMPART_SYN_CHALLENGE_H
#define RAMPART_SYN_CHALLENGE_H

/**
 * Rampart RST challenge (Oubliette-style liveness proof).
 *
 * Protocol-agnostic source verification that any TCP client can pass:
 *
 *   1. A SYN from a source that is neither whitelisted nor verified makes
 *      the filter reflect a SYN-ACK with a deliberately wrong ack number
 *      (derived deterministically from the 4-tuple and the secret) and drop
 *      the original SYN.
 *   2. A spoofed source never reacts, because it does not own the address.
 *   3. A live client's TCP stack rejects the unacceptable SYN-ACK
 *      (RFC 9293 SYN-SENT: a SEG.ACK outside [ISS+1, SND.NXT] triggers a
 *      RST with SEQ=SEG.ACK) and so echoes the secret-derived ack. Seeing
 *      the RST marks the source verified; the client's SYN retransmit (or
 *      the application's reconnect) then reaches the backend.
 *
 * The bogus ack sits just BELOW the client's ISS+1 (ISS+1-k, 1 <= k <= 2^15)
 * instead of anywhere in the 32-bit space. Linux conntrack on the client
 * side (ufw, NAT routers, any stateful firewall) marks a SYN-ACK whose ack is
 * outside its ~64 KiB window as INVALID, and "ct state invalid drop" or a
 * failed NAT reverse lookup then eats the challenge before the client stack
 * sees it. An ack within the window passes conntrack, yet is still
 * unacceptable to the TCP state machine (SEG.ACK <= ISS), so the RST is
 * still generated, and the RST seq lands inside the window as well.
 *
 * Pending challenges expire after G_CHALLENGE_TIMEOUT_MS, so a silent
 * spoofed source is forgotten instead of accumulating state.
 */

#include "common.h"
#include "config.h"
#include "maps.h"
#include "stats.h"

#define CHAL_CONTINUE (-1) // fall through to the normal filter path

// Range of the bogus-ack offset below the client's ISS+1. Must stay a power
// of two and well under the 65535-byte window the challenge SYN-ACK
// advertises, or client-side conntrack drops the challenge or the RST.
#define CHAL_ACK_SPAN 0x8000U

/**
 * Secret-dependent 64-bit mixing step (splitmix-style finalizer).
 *
 * @param h  running hash
 * @param v  value to fold in
 * @return   mixed hash
 */
static __always_inline __u64 chal_mix64(__u64 h, __u64 v)
{
    h ^= v;
    h *= 0x9E3779B97F4A7C15ULL;
    h ^= h >> 29;
    return h;
}

/**
 * Derive the per-flow challenge values.
 *
 * Both our ISN and the bogus-ack offset come from this hash, so forging a
 * passing RST requires G_CHALLENGE_SECRET. The client ISN is folded in, so a
 * SYN retransmit gets the same challenge while a new connection attempt on
 * the same 4-tuple gets a fresh one (a spoofer cannot enumerate the offset
 * across attempts).
 *
 * @param k    flow key of the connection being challenged
 * @param isn  client ISN from the SYN (host order)
 * @return     64-bit secret-derived value (high half ISN, low half offset)
 */
static __always_inline __u64 chal_derive(const struct flow_key *k, __u32 isn)
{
    __u64 h = (__u64)G_CHALLENGE_SECRET ^ 0x5253544348414C53ULL;
    h = chal_mix64(h, ((__u64)k->src_ip << 32) | k->dst_ip);
    h = chal_mix64(h, ((__u64)k->src_port << 48) | ((__u64)k->dst_port << 32) | isn);
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= h >> 32;
    return h;
}

/**
 * Sum the ten 16-bit words of a 20-byte header.
 *
 * Both the IPv4 and the TCP headers are exactly 20 bytes, so one helper
 * serves each of them.
 *
 * @param w  header viewed as ten 16-bit words
 * @return   unfolded ones-complement sum
 */
static __always_inline __u32 chal_sum10(const __u16 *w)
{
    __u32 s = 0;
    s += w[0]; s += w[1]; s += w[2]; s += w[3]; s += w[4];
    s += w[5]; s += w[6]; s += w[7]; s += w[8]; s += w[9];
    return s;
}

/**
 * Fold an accumulated sum into a ones-complement checksum.
 *
 * @param sum  unfolded 32-bit sum of 16-bit words
 * @return     checksum, already complemented and ready for the header
 */
static __always_inline __u16 chal_csum_fold(__u32 sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    return (__u16)~sum;
}

/**
 * Rewrite the packet in place into a SYN-ACK carrying the challenge.
 *
 * MAC addresses and IP addresses are swapped, ports are swapped, seq is set
 * to marker and ack to bad_ack; a guaranteed-unacceptable ack is what forces
 * the live client into an RST. The TCP header is rebuilt clean (options
 * gone), the IPv4 checksum recomputed and the TCP checksum rebuilt over the
 * pseudo-header. The frame is trimmed so the peer sees no leftover option
 * bytes from the original SYN.
 *
 * @param ctx      XDP context, used to trim the tail
 * @param eth      Ethernet header of the packet
 * @param l3       start of the IPv4 or IPv6 header
 * @param is_ipv6  1 when l3 is an IPv6 header
 * @param tcp      TCP header of the packet
 * @param marker   ISN to advertise (our seq)
 * @param bad_ack  unacceptable ack number to advertise
 */
static __always_inline void chal_build_synack(struct xdp_md *ctx,
                                              struct ethhdr *eth, void *l3,
                                              __u8 is_ipv6, struct tcphdr *tcp,
                                              __u32 marker, __u32 bad_ack)
{
    // Snapshot phase: every read happens before any write, because a write
    // invalidates the verifier's bounds knowledge for later reads.
    __u16 ipw[10];
    __u16 tcpw[10];
    __u8 ms[ETH_ALEN], md[ETH_ALEN];
    __u32 saddr[4] = {0}, daddr[4] = {0};

    __builtin_memcpy(ms, eth->h_source, ETH_ALEN);
    __builtin_memcpy(md, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(ipw, l3, 20);
    __builtin_memcpy(tcpw, tcp, 20);

    if (is_ipv6) {
        // saddr/daddr hold the addresses of the reply: the new source is the
        // original destination and the new destination is the original
        // source. The checksum below is computed over exactly these values.
        __builtin_memcpy(saddr, &((struct ipv6hdr *)l3)->daddr, 16);
        __builtin_memcpy(daddr, &((struct ipv6hdr *)l3)->saddr, 16);
    } else {
        saddr[0] = ((struct iphdr *)l3)->daddr;
        daddr[0] = ((struct iphdr *)l3)->saddr;
    }

    // Compute phase: build both header images in registers.
    // IPv4: swap addresses, fresh TTL, recompute the checksum.
    if (!is_ipv6) {
        __u16 s0 = ipw[6], s1 = ipw[7];
        ipw[6] = ipw[8];
        ipw[7] = ipw[9];
        ipw[8] = s0;
        ipw[9] = s1;
        ((__u8 *)ipw)[8] = 64; // TTL
        // tot_len must match the trimmed frame: 20 (IP) + 20 (TCP).
        // Without this the peer sees "truncated IP" and drops the challenge.
        ipw[1] = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ipw[5] = 0;            // checksum placeholder
        ipw[5] = chal_csum_fold(chal_sum10(ipw));
    } else {
        ((struct ipv6hdr *)l3)->payload_len =
            bpf_htons(sizeof(struct tcphdr));
    }

    // TCP: swap ports, inject the secret-derived seq/ack and SYN|ACK.
    __u16 nsport = tcpw[1];               // new source = old dest
    __u16 ndport = tcpw[0];               // new dest = old source
    tcpw[0] = nsport;
    tcpw[1] = ndport;
    // seq/ack are written per-halfword with htons: tcpw is a view over
    // network-order memory, raw host-order stores would swap halfword bytes.
    tcpw[2] = bpf_htons((__u16)(marker >> 16));
    tcpw[3] = bpf_htons((__u16)(marker & 0xFFFF));
    tcpw[4] = bpf_htons((__u16)(bad_ack >> 16));
    tcpw[5] = bpf_htons((__u16)(bad_ack & 0xFFFF));
    tcpw[6] = bpf_htons(0x5012);          // doff=5, flags SYN|ACK
    tcpw[7] = bpf_htons(0xFFFF);          // window
    tcpw[8] = 0;                          // checksum placeholder
    tcpw[9] = 0;                          // urg_ptr

    // TCP checksum over pseudo-header plus the 20-byte header.
    __u32 sum = 0;
    if (is_ipv6) {
        __u16 *w = (__u16 *)saddr;
        sum += w[0] + w[1] + w[2] + w[3] + w[4] + w[5] + w[6] + w[7];
        w = (__u16 *)daddr;
        sum += w[0] + w[1] + w[2] + w[3] + w[4] + w[5] + w[6] + w[7];
    } else {
        sum += ipw[6] + ipw[7] + ipw[8] + ipw[9]; // new IPv4 saddr/daddr
    }
    sum += bpf_htons(IPPROTO_TCP);
    sum += bpf_htons((__u16)sizeof(struct tcphdr));
    sum += chal_sum10(tcpw);
    tcpw[8] = chal_csum_fold(sum);

    // Write phase: commit the images built above.
    __builtin_memcpy(eth->h_dest, ms, ETH_ALEN);
    __builtin_memcpy(eth->h_source, md, ETH_ALEN);
    if (is_ipv6) {
        struct ipv6hdr *ip6 = l3;
        // Write the header with the same orientation the checksum was built
        // from: saddr is the new source (original destination), daddr the
        // new destination (original source).
        __builtin_memcpy(&ip6->saddr, saddr, 16);
        __builtin_memcpy(&ip6->daddr, daddr, 16);
        ip6->hop_limit = 64;
    } else {
        __builtin_memcpy(l3, ipw, 20);
    }
    __builtin_memcpy(tcp, tcpw, 20);

    // Trim to the bare header so SYN options and payload remnants are gone.
    long trim = (long)((void *)(long)ctx->data_end -
                       ((void *)tcp + sizeof(struct tcphdr)));
    if (trim > 0)
        bpf_xdp_adjust_tail(ctx, -trim);
}

/**
 * Derive the challenge values for a native IPv6 flow.
 *
 * Same contract as chal_derive(), over the full 128-bit addresses.
 *
 * @param k    IPv6 flow key of the connection being challenged
 * @param isn  client ISN from the SYN (host order)
 * @return     64-bit secret-derived value (high half ISN, low half offset)
 */
static __always_inline __u64 chal_derive6(const struct flow_key6 *k, __u32 isn)
{
    __u64 w[4];
    __builtin_memcpy(w, k->src, 16);
    __builtin_memcpy(&w[2], k->dst, 16);
    __u64 h = (__u64)G_CHALLENGE_SECRET ^ 0x5253544348414C36ULL;
    h = chal_mix64(h, w[0]);
    h = chal_mix64(h, w[1]);
    h = chal_mix64(h, w[2]);
    h = chal_mix64(h, w[3]);
    h = chal_mix64(h, ((__u64)k->src_port << 48) | ((__u64)k->dst_port << 32) | isn);
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= h >> 32;
    return h;
}

/**
 * Shared SYN handling for both address families.
 *
 * A verified source refreshes its TTL and continues down the normal filter
 * path. Anything else receives the reflected challenge. The maps are passed
 * in so the IPv4 and IPv6 tables share one implementation; the function is
 * always inlined, so the verifier still sees constant map pointers.
 *
 * @param ctx       XDP context
 * @param eth       Ethernet header
 * @param l3        start of the IPv4 or IPv6 header
 * @param is_ipv6   1 when l3 is an IPv6 header
 * @param tcp       TCP header
 * @param verified  challenge_verified or challenge_verified6
 * @param vkey      source address key for @verified
 * @param pending   challenge_pending or challenge_pending6
 * @param pkey      flow key for @pending
 * @param h         chal_derive()/chal_derive6() value for this SYN
 * @param now       current bpf_ktime_get_ns() timestamp
 * @return          CHAL_CONTINUE to process normally, XDP_TX when a challenge
 *                  was sent, or XDP_DROP on failure
 */
static __always_inline int chal_syn_common(struct xdp_md *ctx, struct ethhdr *eth,
                                           void *l3, __u8 is_ipv6,
                                           struct tcphdr *tcp,
                                           void *verified, const void *vkey,
                                           void *pending, const void *pkey,
                                           __u64 h, __u64 now)
{
    __u64 *v = bpf_map_lookup_elem(verified, vkey);
    if (v) {
        if (now - *v <= G_CHALLENGE_VERIFIED_TTL_NS) {
            *v = now; // sliding TTL refresh
            return CHAL_CONTINUE;
        }
        bpf_map_delete_elem(verified, vkey); // expired
    }

    __u32 isn = bpf_ntohl(tcp->seq);
    __u32 marker = (__u32)(h >> 32);  // our ISN
    // Bogus ack ISS+1-k with k in [1, CHAL_ACK_SPAN]: never acceptable
    // (SEG.ACK <= ISS) yet inside the conntrack window (see file header).
    __u32 bad_ack = isn + 1 - (1 + ((__u32)h & (CHAL_ACK_SPAN - 1)));

    struct challenge_pending p = {
        .sent_at = now,
        .marker = marker,
        .bad_ack = bad_ack,
    };
    if (bpf_map_update_elem(pending, pkey, &p, BPF_ANY)) {
        inc_drop(); // cannot track the challenge — fail closed
        return XDP_DROP;
    }

    inc_chal_sent();
    chal_build_synack(ctx, eth, l3, is_ipv6, tcp, marker, bad_ack);
    return XDP_TX;
}

/**
 * Shared RST handling for both address families.
 *
 * Only a RST echoing a secret-derived value counts as proof of life: our bad
 * ack as its seq, or our marker+1 as its ack. Everything else, including a
 * reply that arrives after the timeout, fails the challenge and is dropped.
 *
 * @param tcp       TCP header of the RST
 * @param verified  challenge_verified or challenge_verified6
 * @param vkey      source address key for @verified
 * @param pending   challenge_pending or challenge_pending6
 * @param pkey      flow key for @pending
 * @param now       current bpf_ktime_get_ns() timestamp
 * @return          CHAL_CONTINUE when no challenge was pending, otherwise XDP_DROP
 */
static __always_inline int chal_rst_common(struct tcphdr *tcp,
                                           void *verified, const void *vkey,
                                           void *pending, const void *pkey,
                                           __u64 now)
{
    struct challenge_pending *p = bpf_map_lookup_elem(pending, pkey);
    if (!p)
        return CHAL_CONTINUE;

    __u64 timeout_ns = (__u64)G_CHALLENGE_TIMEOUT_MS * 1000000ULL;
    __u32 seq = bpf_ntohl(tcp->seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);
    __u8 ok = (seq == p->bad_ack) ||
              (tcp->ack && ack == p->marker + 1);
    __u64 sent_at = p->sent_at;

    // Copy every field needed before deleting: an LRU element may be freed
    // as soon as it is removed, so p must never be dereferenced afterwards.
    bpf_map_delete_elem(pending, pkey);

    if (!ok || now - sent_at > timeout_ns) {
        inc_chal_failed();
        return XDP_DROP;
    }

    __u64 seen = now;
    bpf_map_update_elem(verified, vkey, &seen, BPF_ANY);
    inc_chal_verified();
    return XDP_DROP; // the client's SYN retransmit passes next
}

/**
 * IPv4 (and IPv4-mapped IPv6) SYN: see chal_syn_common().
 *
 * @param flow  32-bit flow key of this connection
 */
static __always_inline int chal_on_syn(struct xdp_md *ctx, struct ethhdr *eth,
                                       void *l3, __u8 is_ipv6,
                                       struct tcphdr *tcp,
                                       const struct flow_key *flow, __u64 now)
{
    __u64 h = chal_derive(flow, bpf_ntohl(tcp->seq));
    return chal_syn_common(ctx, eth, l3, is_ipv6, tcp,
                           &challenge_verified, &flow->src_ip,
                           &challenge_pending, flow, h, now);
}

/**
 * IPv4 (and IPv4-mapped IPv6) RST: see chal_rst_common().
 */
static __always_inline int chal_on_rst(struct tcphdr *tcp,
                                       const struct flow_key *flow, __u64 now)
{
    return chal_rst_common(tcp, &challenge_verified, &flow->src_ip,
                           &challenge_pending, flow, now);
}

/**
 * Native IPv6 SYN: see chal_syn_common(). The caller guarantees that the
 * TCP header directly follows the fixed IPv6 header (no extension headers),
 * because the reply is rebuilt as a bare 40+20-byte packet.
 *
 * @param flow6  128-bit flow key of this connection
 */
static __always_inline int chal6_on_syn(struct xdp_md *ctx, struct ethhdr *eth,
                                        struct ipv6hdr *ip6, struct tcphdr *tcp,
                                        const struct flow_key6 *flow6, __u64 now)
{
    __u64 h = chal_derive6(flow6, bpf_ntohl(tcp->seq));
    return chal_syn_common(ctx, eth, ip6, 1, tcp,
                           &challenge_verified6, flow6->src,
                           &challenge_pending6, flow6, h, now);
}

/**
 * Native IPv6 RST: see chal_rst_common().
 */
static __always_inline int chal6_on_rst(struct tcphdr *tcp,
                                        const struct flow_key6 *flow6, __u64 now)
{
    return chal_rst_common(tcp, &challenge_verified6, flow6->src,
                           &challenge_pending6, flow6, now);
}

#endif /* RAMPART_SYN_CHALLENGE_H */
