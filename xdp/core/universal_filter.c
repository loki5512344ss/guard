/**
 * Rampart universal XDP filter.
 *
 * Protocol-agnostic L3/L4 filter with an optional L7 extension point. It
 * owns, in this order:
 *
 *   1. No pure-ACK drop (prevents TCP handshake deadlock).
 *   2. LRU conntrack, consulted only for new (SYN) connections. A non-SYN
 *      segment with no tracked state passes: this is a stateless filter, not
 *      a firewall, so spoofed SYNs cannot black-hole established flows and
 *      ordinary replies are never dropped for lack of state.
 *   3. RST/FIN removes the conntrack entry, so no stale state survives.
 *   4. IPv6 support alongside IPv4.
 *   5. IP/CIDR blacklist and whitelist (LPM trie, IPv4 and IPv6).
 *   6. Per-IP SYN throttle, with invalid TCP flag combinations dropped.
 *   7. UDP policy from config.h: pass, drop or rate-limit.
 *
 * L2 decapsulation peels up to two VLAN tags before L3. IP fragments carry
 * no inspectable ports, so they only get the source blacklist and then pass
 * (dropping first fragments would break legitimate large datagrams).
 *
 * Deep payload inspection is delegated to an optional protocol hook (see
 * ../hooks/hook_api.h). Without a hook, established connections pass.
 */

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
#include "prefix_stats.h"
#include "syn_challenge.h"
#include "../hooks/hook_api.h"

char __license[] SEC("license") = "GPL";

/**
 * Reject TCP flag combinations that no real stack emits.
 *
 * Every rule here is a signature of forged or scanner traffic, so a match
 * means the packet can be dropped before it reaches any stateful logic.
 *
 * @param tcp  TCP header of the packet
 * @return     1 when the packet must be dropped, 0 when it looks legitimate
 */
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

/**
 * Check the IPv4 blacklist.
 *
 * The /32 lookup cannot address a wider /24 (or any other prefix) stored in
 * the trie, so an expired entry is only ignored here; userspace reaps it
 * with the prefix length it was created with. Deleting by /32 from the
 * packet path used to leak every prefix ban until the trie filled up.
 *
 * @param src_ip  source address, network byte order
 * @param now     current bpf_ktime_get_ns() timestamp
 * @return        1 when the source is currently banned, 0 otherwise
 */
static __always_inline __u8 is_blacklisted(__u32 src_ip, __u64 now)
{
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    __u64 *ban_until = bpf_map_lookup_elem(&blacklist_map, &key);
    if (!ban_until)
        return 0;
    return *ban_until > now;
}

/**
 * Check the IPv6 blacklist.
 *
 * Key layout mirrors bpf_lpm_trie_key: prefixlen in host order followed by
 * 16 address bytes. Expired entries are ignored, never deleted here, for the
 * same reason as in is_blacklisted().
 *
 * @param addr  16-byte source address, network byte order
 * @param now   current bpf_ktime_get_ns() timestamp
 * @return      1 when the source is currently banned, 0 otherwise
 */
static __always_inline __u8 is_blacklisted6(const __u8 addr[16], __u64 now)
{
    struct lpm_key6 key = {};
    key.prefixlen = 128;
    __builtin_memcpy(key.addr, addr, 16);
    __u64 *ban_until = bpf_map_lookup_elem(&blacklist6_map, &key);
    if (!ban_until)
        return 0;
    return *ban_until > now;
}

/**
 * Add a /32 ban for one source address.
 *
 * @param src_ip  source address, network byte order
 * @param until   expiry as a bpf_ktime_get_ns() timestamp
 */
static __always_inline void ban_ip(__u32 src_ip, __u64 until)
{
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    bpf_map_update_elem(&blacklist_map, &key, &until, BPF_ANY);
}

/**
 * Fixed-window throttle for one IPv4 source address.
 *
 * Shared by the SYN throttle and the UDP rate limiter; only the map, the
 * threshold and the window length differ. The caller decides the verdict,
 * which is why an exceeded limit returns 1 instead of dropping.
 *
 * @param map        LRU hash map keyed by src_ip
 * @param src_ip     source address, network byte order
 * @param max_hits   packets allowed per window
 * @param window_ns  window length in nanoseconds
 * @param now        current bpf_ktime_get_ns() timestamp
 * @return           1 when the limit is exceeded, 0 when within it
 */
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

/**
 * IPv6 twin of throttle_hit().
 *
 * Identical window logic; only the key width differs, so the caller passes a
 * pointer to the 16-byte source address (the map key is struct in6_addr).
 *
 * @param map        LRU hash map keyed by the source address
 * @param key        pointer to the 16-byte source address
 * @param max_hits   packets allowed per window
 * @param window_ns  window length in nanoseconds
 * @param now        current bpf_ktime_get_ns() timestamp
 * @return           1 when the limit is exceeded, 0 when within it
 */
static __always_inline __u8 throttle_hit6(void *map, const void *key,
                                          __u32 max_hits, __u64 window_ns,
                                          __u64 now)
{
    struct throttle_entry *th = bpf_map_lookup_elem(map, key);

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
        bpf_map_update_elem(map, key, &new_th, BPF_ANY);
    }
    return 0;
}

/**
 * Main XDP entry point.
 *
 * Parses L2/L3/L4, applies whitelist and blacklist, then dispatches to the
 * UDP policy or the TCP state machine. A return of XDP_PASS means the packet
 * continues to the kernel stack; XDP_DROP means it is discarded here.
 *
 * @param ctx  XDP context for the received frame
 * @return     the XDP verdict for this packet
 */
SEC("xdp")
int rampart_universal_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    inc_total();

    // Parse the Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Strip up to two VLAN tags (802.1Q / 802.1ad). Tagged frames used to hit
    // the non-IP early return, which let a banned source bypass the blacklist
    // with VLAN/QinQ encapsulation.
    void *l3 = (void *)(eth + 1);
    __u16 eth_proto = eth->h_proto;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD))
            break;
        struct rampart_vlan_hdr *vh = l3;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        eth_proto = vh->encap_proto;
        l3 = (void *)(vh + 1);
    }

    // Non-IP traffic: pass (ARP, etc.)
    if (eth_proto != bpf_htons(ETH_P_IP) && eth_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    // Parse the IP header.
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u8 l4_proto = 0;
    __u8 is_ipv6 = 0;
    __u8 native_v6 = 0;
    __u8 is_fragment = 0;
    // Protocols the filter cannot inspect (ICMP, GRE, ESP, an IPv6 chain that
    // does not end in TCP/UDP): never a free pass, the source blacklist still
    // applies below. They used to return XDP_PASS before any list was read.
    __u8 l4_unfiltered = 0;
    __u16 v6_ext_len = 0;
    void *v6_l4 = NULL;
    __u8 src6[16];

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->version != 4 || ip->ihl < 5) {
            inc_drop();
            return XDP_DROP;
        }

        src_ip   = ip->saddr;
        dst_ip   = ip->daddr;
        l4_proto = ip->protocol;

        // MF or a non-zero offset: this packet has no reliable L4 header.
        // Both first and later fragments are handled by the source blacklist
        // below and then passed; dropping first fragments would break
        // legitimate large datagrams.
        if (ip->frag_off & bpf_htons(IP_OFFSET | IP_MF)) {
            is_fragment = 1;
        } else if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            l4_unfiltered = 1;
        }
    } else {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        // Keep the full address for the IPv6 whitelist and blacklist even
        // when it is IPv4-mapped; the low 32 bits are used for flow keys.
        __builtin_memcpy(src6, &ip6->saddr, 16);
        is_ipv6  = 1;
        // Walk hop-by-hop / routing / destination-options / AH headers to the
        // real L4 header. Returning XDP_PASS on the first extension header let
        // any IPv6 flood skip the blacklist, throttle and port gate by adding
        // one (kernel stacks process these headers normally).
        __u8 nh = ip6->nexthdr;
        void *ext = (void *)(ip6 + 1);
#pragma unroll
        for (int i = 0; i < RAMPART_V6_MAX_EXT; i++) {
            if (nh != IPPROTO_HOPOPTS && nh != IPPROTO_ROUTING &&
                nh != IPPROTO_DSTOPTS && nh != IPPROTO_AH)
                break;
            struct rampart_ipv6_ext *eh = ext;
            if ((void *)(eh + 1) > data_end)
                return XDP_PASS;
            __u16 elen = (nh == IPPROTO_AH) ? ((__u16)eh->hdrlen + 2) * 4
                                            : ((__u16)eh->hdrlen + 1) * 8;
            nh  = eh->nexthdr;
            ext = (void *)((__u8 *)ext + elen);
        }
        l4_proto  = nh;
        v6_l4     = ext;
        v6_ext_len = (__u16)((__u8 *)ext - (__u8 *)(ip6 + 1));

        // A fragment header hides the L4 header; same policy as IPv4.
        if (nh == IPPROTO_FRAGMENT) {
            is_fragment = 1;
        } else if (nh != IPPROTO_TCP && nh != IPPROTO_UDP) {
            l4_unfiltered = 1;
        }

        // Use IPv4-mapped IPv6 address for flow key (::ffff:0:0/96)
        if (ip6->saddr.in6_u.u6_addr32[0] != 0 ||
            ip6->saddr.in6_u.u6_addr32[1] != 0 ||
            ip6->saddr.in6_u.u6_addr32[2] != bpf_htonl(0xFFFF) ||
            ip6->daddr.in6_u.u6_addr32[0] != 0 ||
            ip6->daddr.in6_u.u6_addr32[1] != 0 ||
            ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(0xFFFF)) {
            // Native IPv6: no 32-bit representable address, handled
            // separately after the generic L4/port gates and must never
            // touch the IPv4 maps.
            native_v6 = 1;
        } else {
            // Source address must come from saddr, never daddr, or the
            // filter would track the server instead of the client.
            src_ip   = ip6->saddr.in6_u.u6_addr32[3];
            dst_ip   = ip6->daddr.in6_u.u6_addr32[3];
        }
    }

    __u64 now = bpf_ktime_get_ns();

    // Whitelist check (LPM trie), before the port gate, conntrack and both
    // blacklists: a whitelisted source must truly bypass the state machine.
    if (is_ipv6) {
        struct lpm_key6 wl6 = {};
        wl6.prefixlen = 128;
        __builtin_memcpy(wl6.addr, src6, 16);
        if (bpf_map_lookup_elem(&whitelist6_map, &wl6)) {
            inc_whitelist();
            return XDP_PASS;
        }
    } else {
        struct lpm_key wl = { .prefixlen = 32, .ip = src_ip };
        if (bpf_map_lookup_elem(&whitelist_map, &wl)) {
            inc_whitelist();
            return XDP_PASS;
        }
    }

    // Fragments: the L4 ports are missing or incomplete, so the stateful and
    // throttle logic cannot run. Apply the source blacklist and pass; the
    // dedicated counter keeps this deliberate bypass observable.
    if (is_fragment || l4_unfiltered) {
        __u8 banned = native_v6 ? is_blacklisted6(src6, now)
                                : is_blacklisted(src_ip, now);
        if (banned) {
            inc_blacklist();
            inc_drop();
            if (!native_v6 && G_FEATURE_EVENTS)
                push_event(EVENT_BAN, src_ip, 0);
            return XDP_DROP;
        }
        if (is_fragment)
            inc_fragment_bypass();
        inc_pass();
        return XDP_PASS;
    }

    // Parse the L4 header.
    __u8 ip_hdr_len;
    void *l4;

    if (is_ipv6) {
        l4 = v6_l4;
        ip_hdr_len = sizeof(struct ipv6hdr);
    } else {
        struct iphdr *ip = l3;
        l4 = (void *)ip + (ip->ihl * 4);
        ip_hdr_len = ip->ihl * 4;
    }

    // Minimum L4 header per protocol: a short UDP datagram used to fall through
    // to XDP_PASS because the check was sized for TCP, letting it bypass the
    // blacklist entirely. Fragments were already handled above (source
    // blacklist only), so a short UDP header here is a real datagram.
    __u32 min_l4 = (l4_proto == IPPROTO_TCP) ? sizeof(struct tcphdr)
                                             : sizeof(struct udphdr);
    if ((void *)l4 + min_l4 > data_end)
        return XDP_PASS;

    // Port range check: out-of-range destinations are not ours to defend.
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

    // Native IPv6: blacklist plus cheap L4 policy (no stateful v6 yet).
    if (native_v6) {
        if (is_blacklisted6(src6, now)) {
            inc_blacklist();
            inc_drop();
            return XDP_DROP;
        }
        if (l4_proto == IPPROTO_UDP) {
            switch (G_UDP_POLICY) {
            case 1: // drop
                inc_drop();
                return XDP_DROP;
            case 2: // rate-limit (per-source, 128-bit key)
                if (throttle_hit6(&udp_rate_limit6, src6,
                                  G_UDP_HIT_COUNT, G_UDP_WINDOW_NS, now)) {
                    inc_rate_limit();
                    inc_drop();
                    // No ringbuf event: xdp_event.src_ip is u32 (ABI).
                    return XDP_DROP;
                }
                /* fallthrough: within limits — pass */
            default: // pass
                inc_pass();
                return XDP_PASS;
            }
        }
        // TCP: forged-flag combos are L4-generic, no state needed. The full
        // TCP header must be in bounds: the earlier gate only proved the size
        // for the protocol class it saw, and the verifier cannot correlate the
        // two once l4_proto comes from the extension-header walk.
        if ((void *)l4 + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
        if (detect_tcp_bypass((struct tcphdr *)l4)) {
            inc_drop();
            return XDP_DROP;
        }
        // Per-prefix stats (/64) — feeds the subnet detector for IPv6
        struct prefix_key pkey6;
        prefix_key_from_v6(&pkey6, src6);
        struct tcphdr *tcp6 = (struct tcphdr *)l4;
        __u32 v6_id;
        __builtin_memcpy(&v6_id, src6 + 12, 4); // interface ID differs per host
        update_prefix_stats(&pkey6, (tcp6->syn && !tcp6->ack) ? 1 : 0, now, v6_id);
        inc_pass();
        return XDP_PASS;
    }

    // Blacklist check (CIDR with expiry).
    if (is_blacklisted(src_ip, now)) {
        inc_blacklist();
        inc_drop();
        if (G_FEATURE_EVENTS)
            push_event(EVENT_BAN, src_ip, 0);
        return XDP_DROP;
    }

    // UDP path.
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

    // TCP path.
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Malicious TCP flags
    if (detect_tcp_bypass(tcp)) {
        inc_drop();
        if (G_FEATURE_EVENTS)
            push_event(EVENT_POLICY_DROP, src_ip, 0);
        return XDP_DROP;
    }

    // TCP header length check.
    if (tcp->doff < 5) {
        inc_drop();
        return XDP_DROP;
    }
    __u8 tcp_hdr_len = tcp->doff * 4;
    if ((void *)l4 + tcp_hdr_len > data_end) {
        inc_drop();
        return XDP_DROP;
    }

    // Per-prefix stats key (/24), built once after blacklist and bypass drops.
    struct prefix_key pkey;
    prefix_key_from_v4(&pkey, src_ip);

    // The payload window is bounded by the IP header length field, not by
    // data_end: a real NIC pads the last frame to the 60-byte Ethernet
    // minimum, so counting to data_end would treat the padding as payload,
    // drift expected_seq and drop the connection after a few segments. The
    // frame can still be shorter than the IP header claims, so cap at
    // data_end as well.
    __u32 l4_len;
    if (is_ipv6) {
        struct ipv6hdr *ip6 = l3;
        __u16 payload_len = bpf_ntohs(ip6->payload_len);
        if (payload_len < v6_ext_len) {
            inc_drop();
            return XDP_DROP;
        }
        // payload_len counts the extension headers; l4 starts after them.
        l4_len = payload_len - v6_ext_len;
    } else {
        struct iphdr *ip = l3;
        __u16 tot_len = bpf_ntohs(ip->tot_len);
        if (tot_len < ip_hdr_len) {
            inc_drop();
            return XDP_DROP;
        }
        l4_len = (__u32)(tot_len - ip_hdr_len);
    }

    __u32 frame_l4 = (__u32)((__u8 *)data_end - (__u8 *)l4);
    if (l4_len > frame_l4)
        l4_len = frame_l4;
    if (l4_len < tcp_hdr_len) {
        inc_drop();
        return XDP_DROP;
    }

    __u32 tcp_payload_len = l4_len - tcp_hdr_len;
    __u8 *tcp_payload = (__u8 *)tcp + tcp_hdr_len;
    __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // Build the flow key.
    struct flow_key flow = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    // SYN handling: a bare SYN opens a new connection.
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

        // RST challenge: an unverified source must prove liveness first.
        // Placed after throttle and blacklist so abusive sources never get a
        // reply, mirroring the prefix_stats ordering.
        if (G_SYN_CHALLENGE_ENABLED) {
            // The challenge reply is rebuilt as a bare 20-byte IPv4 header,
            // so an IPv4 SYN with options cannot be answered without shipping
            // a malformed SYN-ACK. Drop it (counted) instead.
            if (!is_ipv6 && ((struct iphdr *)l3)->ihl != 5) {
                inc_drop();
                return XDP_DROP;
            }
            int cv = chal_on_syn(ctx, eth, l3, is_ipv6, tcp, &flow, now);
            if (cv != CHAL_CONTINUE)
                return cv;
        }

        // Count SYN only after throttle passed (don't count throttled SYNs)
        update_prefix_stats(&pkey, 1, now, src_ip);

        // Create conntrack entry for new connection. A SYN may carry data
        // (TCP Fast Open), which is acknowledged as part of the handshake;
        // expected_seq must advance past it or the completing ACK is dropped.
        struct conntrack_entry ce = {};
        ce.state = STATE_SYN_RECEIVED;
        ce.expected_seq = bpf_ntohl(tcp->seq) + 1 + tcp_payload_len;
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

    // Connection tracking lookup.
    // pkt_count: all non-SYN TCP that survived blacklist/bypass/throttle
    update_prefix_stats(&pkey, 0, now, src_ip);

    // RST challenge proof: match a pending challenge before conntrack,
    // because the RST answers a flow that was never tracked.
    if (G_SYN_CHALLENGE_ENABLED && tcp->rst) {
        int cv = chal_on_rst(tcp, &flow, now);
        if (cv != CHAL_CONTINUE)
            return cv;
    }

    struct conntrack_entry *conn = bpf_map_lookup_elem(&conntrack_map, &flow);
    if (!conn) {
        // Stateless filter, not a firewall: only new connections (SYN) are
        // policed. An untracked non-SYN segment — a flow evicted under SYN
        // pressure, a connection opened before attach, or the reply to the
        // daemon's own outbound connection — passes instead of being dropped.
        inc_pass();
        return XDP_PASS;
    }
    conn->last_seen = now;

    // Handle RST/FIN — clean up conntrack entry
    if (tcp->rst || tcp->fin) {
        bpf_map_delete_elem(&conntrack_map, &flow);
        inc_pass();
        return XDP_PASS;
    }

    // Sequence number tracking, established connections only.
    __u32 seq = bpf_ntohl(tcp->seq);
    if (conn->state == STATE_ESTABLISHED && tcp_payload_len > 0) {
        if (seq != conn->expected_seq) {
            conn->fails++;
            if (conn->fails >= G_MAX_OUT_OF_ORDER) {
                // Copy the counter before deleting: the LRU element may be
                // freed by bpf_map_delete_elem, so conn must not be read
                // afterwards.
                __u8 fails = conn->fails;
                bpf_map_delete_elem(&conntrack_map, &flow);
                inc_drop();
                if (G_FEATURE_EVENTS)
                    push_event(EVENT_CONN_DROP, src_ip, fails);
                return XDP_DROP;
            }
            // Allow retransmission (don't update expected_seq)
            inc_pass();
            return XDP_PASS;
        }
        // In-order segment: reset the reordering counter, so isolated
        // reordered/retransmitted segments over the connection lifetime can
        // never accumulate into a false positive.
        conn->fails = 0;
    }

    // State machine.
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
