// ── Rampart Universal XDP Filter ──
// Protocol-agnostic L3/L4 filter with an L7 extension point.
//
// Responsibilities (L3/L4):
//   1. No pure ACK drop (prevents TCP handshake deadlock)
//   2. LRU conntrack: SYN_RECEIVED → ESTABLISHED, seq tracking
//   3. RST/FIN removes conntrack entry (no stale state)
//   4. IPv6 support alongside IPv4
//   5. IP/CIDR blacklist + whitelist (LPM_TRIE)
//   6. SYN throttle per-IP, invalid TCP flag combos dropped
//   7. UDP policy from config.h: pass / drop / rate-limit
//
// Deep payload inspection is delegated to an optional protocol hook:
//   see ../hooks/hook_api.h. Without a hook, established connections pass.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "maps.h"
#include "config.h"
#include "stats.h"
#include "../hooks/hook_api.h"

char __license[] SEC("license") = "GPL";

// ── TCP flag check (drop malicious combos) ──
// Returns 1 if packet should be dropped
static __always_inline __u8 detect_tcp_bypass(struct tcphdr *tcp)
{
    __u8 flags = *((__u8 *)tcp + 13);

    // No flags at all — bogus packet
    if ((flags & 0x3F) == 0)
        return 1;

    // SYN+FIN or SYN+RST — always forged
    if (tcp->syn) {
        if (tcp->fin || tcp->rst)
            return 1;
    }

    // SYN+ACK from client side — only servers send this
    if (tcp->syn && tcp->ack)
        return 1;

    // URG flag — not used by any mainstream protocol on protected ports
    if (tcp->urg)
        return 1;

    return 0;
}

// ── Blacklist lookup with expiry; removes expired entries ──
static __always_inline __u8 is_blacklisted(__u32 src_ip, __u64 now)
{
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    __u64 *ban_until = bpf_map_lookup_elem(&blacklist_map, &key);
    if (!ban_until)
        return 0;
    if (*ban_until > now)
        return 1;
    bpf_map_delete_elem(&blacklist_map, &key); // expired — clean up
    return 0;
}

static __always_inline void ban_ip(__u32 src_ip, __u64 until)
{
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    bpf_map_update_elem(&blacklist_map, &key, &until, BPF_ANY);
}

// ── Generic per-IP window throttle (shared by SYN throttle and UDP RL) ──
// map: LRU_HASH keyed by src_ip; returns 1 if limit exceeded (caller bans/drops)
static __always_inline __u8 throttle_hit(void *map, __u32 src_ip,
                                         __u32 max_hits, __u64 window_ns,
                                         __u64 now)
{
    struct throttle_entry *th = bpf_map_lookup_elem(map, &src_ip);

    if (th) {
        if (now - th->window_start < window_ns) {
            if (th->hits >= max_hits)
                return 1;
            __sync_fetch_and_add(&th->hits, 1);
        } else {
            th->window_start = now;
            th->hits = 1;
        }
    } else {
        struct throttle_entry new_th = { .window_start = now, .hits = 1 };
        bpf_map_update_elem(map, &src_ip, &new_th, BPF_ANY);
    }
    return 0;
}

// ══════════════════════════════════════════
// Main XDP entry point
// ══════════════════════════════════════════
SEC("xdp")
int rampart_universal_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    inc_total();

    // ── Parse Ethernet header ──
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Non-IP traffic: pass (ARP, etc.)
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    // ── Parse IP header ──
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u8 l4_proto = 0;
    __u8 is_ipv6 = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->ihl < 5)
            return XDP_DROP;

        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
            return XDP_PASS;

        // Non-sequential fragment: pass (can't inspect ports safely)
        if (ip->frag_off & bpf_htons(IP_OFFSET))
            return XDP_PASS;

        // First fragment with MF: drop (can't reassemble)
        if (ip->frag_off & bpf_htons(IP_MF))
            return XDP_DROP;

        src_ip   = ip->saddr;
        dst_ip   = ip->daddr;
        l4_proto = ip->protocol;
    } else {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS; // extension headers not walked

        // Use IPv4-mapped IPv6 address for flow key (::ffff:0:0/96)
        if (ip6->saddr.in6_u.u6_addr32[0] != 0 ||
            ip6->saddr.in6_u.u6_addr32[1] != 0 ||
            ip6->saddr.in6_u.u6_addr32[2] != bpf_htonl(0xFFFF) ||
            ip6->daddr.in6_u.u6_addr32[0] != 0 ||
            ip6->daddr.in6_u.u6_addr32[1] != 0 ||
            ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(0xFFFF)) {
            // Non-mapped IPv6 — pass for now (not supported)
            return XDP_PASS;
        }

        // FIX: source address must come from saddr, never daddr
        src_ip   = ip6->saddr.in6_u.u6_addr32[3];
        dst_ip   = ip6->daddr.in6_u.u6_addr32[3];
        l4_proto = ip6->nexthdr;
        is_ipv6  = 1;
    }

    // ── Parse L4 header ──
    __u8 ip_hdr_len;
    void *l4;

    if (is_ipv6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        l4 = (void *)(ip6 + 1);
        ip_hdr_len = sizeof(struct ipv6hdr);
    } else {
        struct iphdr *ip = (void *)(eth + 1);
        l4 = (void *)ip + (ip->ihl * 4);
        ip_hdr_len = ip->ihl * 4;
    }

    if ((void *)l4 + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    // ── Port range check (protected services) ──
    __u16 dst_port;
    if (l4_proto == IPPROTO_TCP)
        dst_port = bpf_ntohs(((struct tcphdr *)l4)->dest);
    else
        dst_port = bpf_ntohs(((struct udphdr *)l4)->dest);

    if (dst_port < G_START_PORT || dst_port > G_END_PORT)
        return XDP_PASS;

    if (l4_proto == IPPROTO_TCP)
        inc_tcp();
    else
        inc_udp();

    __u64 now = bpf_ktime_get_ns();

    // ── Whitelist check (CIDR) — before any filtering ──
    struct lpm_key wl_key = { .prefixlen = 32, .ip = src_ip };
    if (bpf_map_lookup_elem(&whitelist_map, &wl_key)) {
        inc_whitelist();
        return XDP_PASS;
    }

    // ── Blacklist check (CIDR with expiry) ──
    if (is_blacklisted(src_ip, now)) {
        inc_blacklist();
        inc_drop();
        if (G_FEATURE_EVENTS)
            push_event(EVENT_BAN, src_ip, 0);
        return XDP_DROP;
    }

    // ═══════════ UDP path ═══════════
    if (l4_proto == IPPROTO_UDP) {
        switch (G_UDP_POLICY) {
        case 1: // drop
            inc_drop();
            if (G_FEATURE_EVENTS)
                push_event(EVENT_POLICY_DROP, src_ip, 0);
            return XDP_DROP;
        case 2: // rate-limit
            if (throttle_hit(&udp_rate_limit, src_ip,
                             G_UDP_HIT_COUNT, G_UDP_WINDOW_NS, now)) {
                inc_rate_limit();
                inc_drop();
                if (G_FEATURE_EVENTS)
                    push_event(EVENT_RATE_LIMIT, src_ip, G_UDP_HIT_COUNT);
                return XDP_DROP;
            }
            /* fallthrough: within limits — pass */
        default: // pass
            inc_pass();
            return XDP_PASS;
        }
    }

    // ═══════════ TCP path ═══════════
    struct tcphdr *tcp = l4;

    // Malicious TCP flags
    if (detect_tcp_bypass(tcp)) {
        inc_drop();
        if (G_FEATURE_EVENTS)
            push_event(EVENT_POLICY_DROP, src_ip, 0);
        return XDP_DROP;
    }

    // TCP header length check
    if (tcp->doff < 5)
        return XDP_DROP;
    __u8 tcp_hdr_len = tcp->doff * 4;
    if ((void *)data + sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len > data_end)
        return XDP_DROP;

    // Compute payload pointers
    __u8 *tcp_payload = (__u8 *)tcp + tcp_hdr_len;
    __u8 *tcp_payload_end = (__u8 *)data_end;
    __s32 tcp_payload_len = (__s32)(tcp_payload_end - tcp_payload);
    if (tcp_payload_len < 0)
        tcp_payload_len = 0;

    // ── Build flow key ──
    struct flow_key flow = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    // ── SYN handling (new connection) ──
    if (tcp->syn && !tcp->ack) {
        // SYN throttle per-IP
        if (G_FEATURE_SYN_THROTTLE &&
            throttle_hit(&connection_throttle, src_ip,
                         G_SYN_HIT_COUNT, G_SYN_WINDOW_NS, now)) {
            ban_ip(src_ip, now + G_SYN_BAN_DURATION_NS);
            inc_syn_throttle();
            inc_drop();
            if (G_FEATURE_EVENTS)
                push_event(EVENT_RATE_LIMIT, src_ip, G_SYN_HIT_COUNT);
            return XDP_DROP;
        }

        // Create conntrack entry for new connection
        struct conntrack_entry ce = {};
        ce.state = STATE_SYN_RECEIVED;
        ce.expected_seq = bpf_ntohl(tcp->seq) + 1; // expect ACK seq
        ce.src_ip = src_ip;
        ce.src_port = tcp->source;
        ce.last_seen = now;

        if (bpf_map_update_elem(&conntrack_map, &flow, &ce, BPF_ANY)) {
            // Map full — should not happen with LRU
            inc_drop();
            return XDP_DROP;
        }

        inc_pass();
        return XDP_PASS; // Let SYN through
    }

    // ── Connection tracking lookup ──
    struct conntrack_entry *conn = bpf_map_lookup_elem(&conntrack_map, &flow);
    if (!conn) {
        // Unknown connection — drop
        inc_drop();
        return XDP_DROP;
    }
    conn->last_seen = now;

    // Handle RST/FIN — clean up conntrack entry
    if (tcp->rst || tcp->fin) {
        bpf_map_delete_elem(&conntrack_map, &flow);
        inc_pass();
        return XDP_PASS;
    }

    // ── Sequence number tracking (established connections only) ──
    __u32 seq = bpf_ntohl(tcp->seq);
    if (conn->state == STATE_ESTABLISHED && tcp_payload_len > 0 &&
        seq != conn->expected_seq) {
        conn->fails++;
        if (conn->fails >= G_MAX_OUT_OF_ORDER) {
            bpf_map_delete_elem(&conntrack_map, &flow);
            inc_drop();
            if (G_FEATURE_EVENTS)
                push_event(EVENT_CONN_DROP, src_ip, conn->fails);
            return XDP_DROP;
        }
        // Allow retransmission (don't update expected_seq)
        inc_pass();
        return XDP_PASS;
    }

    // ── State machine ──
    if (conn->state == STATE_SYN_RECEIVED) {
        // Expecting the ACK that completes the 3-way handshake
        if (!tcp->ack || seq != conn->expected_seq) {
            inc_drop();
            return XDP_DROP;
        }

        // Do NOT drop pure ACK here. Other XDP filters drop the pure ACK
        // expecting the data packet to serve as ACK, which causes ~1-7s
        // TCP handshake deadlock. We pass the ACK through and promote
        // the connection to ESTABLISHED.
        conn->state = STATE_ESTABLISHED;
        conn->expected_seq = seq + tcp_payload_len;

        if (tcp_payload_len == 0) {
            inc_pass();
            return XDP_PASS;
        }
        // Client sent data together with the final ACK — fall through to hook
    }

    // STATE_ESTABLISHED: empty segments pass untouched (keep-alives),
    // payload segments go through the optional protocol hook.
    if (tcp_payload_len > 0) {
        struct cursor c = { .pos = tcp_payload, .end = tcp_payload_end };
        struct pkt_meta m = {
            .src_ip      = src_ip,
            .dst_ip      = dst_ip,
            .src_port    = bpf_ntohs(tcp->source),
            .dst_port    = dst_port,
            .payload_len = (__u16)tcp_payload_len,
            .tcp_flags   = *((__u8 *)tcp + 13),
            .is_ipv6     = is_ipv6,
        };

        enum xdp_action verdict = proto_hook(&c, &m);

        if (verdict == XDP_DROP) {
            bpf_map_delete_elem(&conntrack_map, &flow);
            inc_drop();
            if (G_FEATURE_EVENTS)
                push_event(EVENT_CONN_DROP, src_ip, 0);
            return XDP_DROP;
        }
        conn->expected_seq = seq + tcp_payload_len;
    }

    inc_pass();
    return XDP_PASS;
}
