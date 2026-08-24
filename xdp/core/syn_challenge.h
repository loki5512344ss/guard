#ifndef RAMPART_SYN_CHALLENGE_H
#define RAMPART_SYN_CHALLENGE_H

// ── Rampart RST-challenge (Oubliette-style liveness proof) ──
//
// Protocol-agnostic source verification, compatible with any TCP client:
//   1. SYN from a source that is neither whitelisted nor verified:
//      kernel reflects a SYN-ACK with a DELIBERATELY WRONG ack number
//      (deterministic from the 4-tuple + secret) and drops the original SYN.
//   2. Spoofed source never reacts — it does not own the address.
//   3. Live client's TCP stack rejects the unacceptable SYN-ACK
//      (RFC 9293 SYN-SENT: SEG.ACK outside [ISS+1, SND.NXT] → RST)
//      echoing secret-derived values. Seeing that RST marks the source
//      verified; the app reconnects and its next SYN reaches the backend.
//
// Pending challenges expire after G_CHALLENGE_TIMEOUT_MS (spoof = silence).

#include "common.h"
#include "config.h"
#include "maps.h"
#include "stats.h"

#define CHAL_CONTINUE (-1) // fall through to the normal filter path

// ── Secret-dependent 64-bit mixing (splitmix-style finalizer) ──
static __always_inline __u64 chal_mix64(__u64 h, __u64 v)
{
    h ^= v;
    h *= 0x9E3779B97F4A7C15ULL;
    h ^= h >> 29;
    return h;
}

// Per-flow challenge values; infeasible to forge without G_CHALLENGE_SECRET
static __always_inline __u64 chal_derive(const struct flow_key *k)
{
    __u64 h = (__u64)G_CHALLENGE_SECRET ^ 0x5253544348414C53ULL;
    h = chal_mix64(h, ((__u64)k->src_ip << 32) | k->dst_ip);
    h = chal_mix64(h, ((__u64)k->src_port << 48) | ((__u64)k->dst_port << 32));
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= h >> 32;
    return h;
}

// ── Ones-complement helpers (both IPv4/TCP headers are 20 bytes = 10 words) ──
static __always_inline __u32 chal_sum10(const __u16 *w)
{
    __u32 s = 0;
    s += w[0]; s += w[1]; s += w[2]; s += w[3]; s += w[4];
    s += w[5]; s += w[6]; s += w[7]; s += w[8]; s += w[9];
    return s;
}

static __always_inline __u16 chal_csum_fold(__u32 sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    return (__u16)~sum;
}

// Rewrite the packet in place into a SYN-ACK: MAC/IP/ports swapped,
// seq = marker, ack = bad_ack (guaranteed unacceptable for the client),
// clean 20-byte TCP header, IP checksum recomputed, TCP checksum rebuilt.
// All reads happen BEFORE any packet write (writes invalidate verifier
// bounds), the tail is trimmed so the peer sees no leftover option bytes.
static __always_inline void chal_build_synack(struct xdp_md *ctx,
                                              struct ethhdr *eth, void *l3,
                                              __u8 is_ipv6, struct tcphdr *tcp,
                                              __u32 marker, __u32 bad_ack)
{
    // ── Snapshot phase (packet reads) ──
    __u16 ipw[10];
    __u16 tcpw[10];
    __u8 ms[ETH_ALEN], md[ETH_ALEN];
    __u32 saddr[4] = {0}, daddr[4] = {0};

    __builtin_memcpy(ms, eth->h_source, ETH_ALEN);
    __builtin_memcpy(md, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(ipw, l3, 20);
    __builtin_memcpy(tcpw, tcp, 20);

    if (is_ipv6) {
        __builtin_memcpy(saddr, &((struct ipv6hdr *)l3)->daddr, 16); // swapped
        __builtin_memcpy(daddr, &((struct ipv6hdr *)l3)->saddr, 16);
    } else {
        saddr[0] = ((struct iphdr *)l3)->daddr;
        daddr[0] = ((struct iphdr *)l3)->saddr;
    }

    // ── Compute images in registers ──
    // IPv4 header: swap addresses, fresh TTL, recompute checksum
    if (!is_ipv6) {
        __u16 s0 = ipw[6], s1 = ipw[7];
        ipw[6] = ipw[8];
        ipw[7] = ipw[9];
        ipw[8] = s0;
        ipw[9] = s1;
        ((__u8 *)ipw)[8] = 64; // TTL
        ipw[5] = 0;            // checksum placeholder
        ipw[5] = chal_csum_fold(chal_sum10(ipw));
    }

    // TCP header: swap ports, inject secret-derived seq/ack, SYN|ACK
    __u16 nsport = tcpw[1];               // new source = old dest
    __u16 ndport = tcpw[0];               // new dest = old source
    tcpw[0] = nsport;
    tcpw[1] = ndport;
    tcpw[2] = (__u16)(marker >> 16);
    tcpw[3] = (__u16)marker;
    tcpw[4] = (__u16)(bad_ack >> 16);
    tcpw[5] = (__u16)bad_ack;
    tcpw[6] = bpf_htons(0x5012);          // doff=5, flags SYN|ACK
    tcpw[7] = bpf_htons(0xFFFF);          // window
    tcpw[8] = 0;                          // checksum placeholder
    tcpw[9] = 0;                          // urg_ptr

    // TCP checksum over pseudo-header + 20-byte header
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

    // ── Write phase ──
    __builtin_memcpy(eth->h_dest, ms, ETH_ALEN);
    __builtin_memcpy(eth->h_source, md, ETH_ALEN);
    if (is_ipv6) {
        struct ipv6hdr *ip6 = l3;
        __builtin_memcpy(&ip6->saddr, daddr, 16);
        __builtin_memcpy(&ip6->daddr, saddr, 16);
        ip6->hop_limit = 64;
    } else {
        __builtin_memcpy(l3, ipw, 20);
    }
    __builtin_memcpy(tcp, tcpw, 20);

    // Trim to the bare header (drop SYN options/payload remnants)
    long trim = (long)((void *)(long)ctx->data_end -
                       ((void *)tcp + sizeof(struct tcphdr)));
    if (trim > 0)
        bpf_xdp_adjust_tail(ctx, -trim);
}

// ── Pure SYN from an unknown source: reflect the wrong SYN-ACK challenge ──
// Returns CHAL_CONTINUE (verified source — process normally), XDP_TX
// (challenge sent) or XDP_DROP.
static __always_inline int chal_on_syn(struct xdp_md *ctx, struct ethhdr *eth,
                                       void *l3, __u8 is_ipv6,
                                       struct tcphdr *tcp,
                                       const struct flow_key *flow, __u64 now)
{
    __u64 *v = bpf_map_lookup_elem(&challenge_verified, &flow->src_ip);
    if (v) {
        if (now - *v <= G_CHALLENGE_VERIFIED_TTL_NS) {
            *v = now; // sliding TTL refresh
            return CHAL_CONTINUE;
        }
        bpf_map_delete_elem(&challenge_verified, &flow->src_ip); // expired
    }

    __u64 h = chal_derive(flow);
    __u32 marker = (__u32)(h >> 32);  // our ISN
    __u32 bad_ack = (__u32)h;         // bogus ack the client must reject

    __u32 expect = bpf_ntohl(tcp->seq) + 1;
    if (bad_ack == expect) // ~2^-32 collision with a valid handshake — kill it
        bad_ack = ~bad_ack;

    struct challenge_pending p = {
        .sent_at = now,
        .marker = marker,
        .bad_ack = bad_ack,
    };
    if (bpf_map_update_elem(&challenge_pending, flow, &p, BPF_ANY)) {
        inc_drop(); // cannot track the challenge — fail closed
        return XDP_DROP;
    }

    inc_chal_sent();
    chal_build_synack(ctx, eth, l3, is_ipv6, tcp, marker, bad_ack);
    return XDP_TX;
}

// ── RST answering a pending challenge: proof of life ──
// Accept only if the RST echoes a secret-derived value (our bad ack as its
// seq, or our marker+1 as its ack). Anything else fails the challenge.
static __always_inline int chal_on_rst(struct tcphdr *tcp,
                                       const struct flow_key *flow, __u64 now)
{
    struct challenge_pending *p = bpf_map_lookup_elem(&challenge_pending, flow);
    if (!p)
        return CHAL_CONTINUE;

    __u64 timeout_ns = (__u64)G_CHALLENGE_TIMEOUT_MS * 1000000ULL;
    __u32 seq = bpf_ntohl(tcp->seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);
    __u8 ok = (seq == p->bad_ack) ||
              (tcp->ack && ack == p->marker + 1);

    bpf_map_delete_elem(&challenge_pending, flow);

    if (!ok || now - p->sent_at > timeout_ns) {
        inc_chal_failed();
        return XDP_DROP;
    }

    __u64 seen = now;
    bpf_map_update_elem(&challenge_verified, &flow->src_ip, &seen, BPF_ANY);
    inc_chal_verified();
    return XDP_DROP; // client app will retry connect; next SYN passes
}

#endif /* RAMPART_SYN_CHALLENGE_H */
