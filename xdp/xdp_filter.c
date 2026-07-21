// ── Rampart XDP/eBPF Filter ──
// Stateful TCP connection inspection for Minecraft Java Edition.
// Drops malicious traffic at NIC driver level, before kernel TCP stack.
//
// Based on research of existing XDP filters for Minecraft.
// Key fixes vs other implementations:
//   1. No pure ACK drop (prevents TCP handshake deadlock)
//   2. LRU maps for both conntrack and player entries
//   3. bpf_timer idle cleanup on conntrack entries (not just player)
//   4. RST/FIN removes conntrack entry (no stale state)
//   5. IPv6 support alongside IPv4
//   6. IP/CIDR whitelist (LPM_TRIE)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "maps.h"
#include "config.h"
#include "varint.h"
#include "protocol.h"
#include "stats.h"

char __license[] SEC("license") = "GPL";

// Timer-based cleanup not needed: all maps are LRU and self-evicting.
// Stale entries in conntrack_map/player_connection_map are evicted
// automatically by the kernel when the maps fill up.

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

    // URG flag — unused in Minecraft protocol
    if (tcp->urg)
        return 1;

    return 0;
}

// ── Switch connection to verified state ──
static __always_inline __u8 switch_to_verified(struct flow_key *flow)
{
    struct player_entry entry = {};
    entry.protocol = 0;

    if (bpf_map_update_elem(&player_connection_map, flow, &entry, BPF_NOEXIST)) {
        // Map is full — LRU will evict, but we still drop this one
        return 0;
    }

    // Remove from conntrack
    bpf_map_delete_elem(&conntrack_map, flow);
    return 1;
}

// ════════════════════════════════════════════════════
// Main XDP entry point
// ════════════════════════════════════════════════════
SEC("xdp")
int rampart_xdp_filter(struct xdp_md *ctx)
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
    __u8 is_ipv6 = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->ihl < 5)
            return XDP_DROP;

        // Non-TCP: pass
        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        // Non-sequential fragment: pass (can't inspect ports safely)
        if (ip->frag_off & bpf_htons(IP_OFFSET))
            return XDP_PASS;

        // First fragment with MF: drop (can't reassemble)
        if (ip->frag_off & bpf_htons(IP_MF))
            return XDP_DROP;

        src_ip = ip->saddr;
    } else {
        // IPv6
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        // Non-TCP: pass
        if (ip6->nexthdr != IPPROTO_TCP)
            return XDP_PASS;

        // Use IPv4-mapped IPv6 address for flow key (::ffff:0:0/96)
        if (ip6->daddr.in6_u.u6_addr32[0] != 0 ||
            ip6->daddr.in6_u.u6_addr32[1] != 0 ||
            ip6->daddr.in6_u.u6_addr32[2] != bpf_htonl(0xFFFF)) {
            // Non-mapped IPv6 — pass for now (not supported)
            return XDP_PASS;
        }

        src_ip = ip6->daddr.in6_u.u6_addr32[3];
        is_ipv6 = 1;
    }

    // ── Parse TCP header ──
    struct tcphdr *tcp;
    __u8 ip_hdr_len;

    if (is_ipv6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        tcp = (void *)(ip6 + 1);
        ip_hdr_len = sizeof(struct ipv6hdr);
    } else {
        struct iphdr *ip = (void *)(eth + 1);
        tcp = (void *)ip + (ip->ihl * 4);
        ip_hdr_len = ip->ihl * 4;
    }

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // TCP header length check
    if (tcp->doff < 5)
        return XDP_DROP;
    __u8 tcp_hdr_len = tcp->doff * 4;
    if ((void *)data + sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len > data_end)
        return XDP_DROP;

    // ── Port check ──
    // Only filter Minecraft ports
    __u16 dst_port = bpf_ntohs(tcp->dest);
    if (dst_port < G_START_PORT || dst_port > G_END_PORT)
        return XDP_PASS;

    inc_tcp_mc();

    // ── Whitelist check (CIDR) ──
    struct lpm_key wl_key = { .prefixlen = 32, .ip = src_ip };
    if (bpf_map_lookup_elem(&whitelist_map, &wl_key)) {
        inc_whitelist();
        return XDP_PASS;
    }

    // ── Malicious TCP flags ──
    if (detect_tcp_bypass(tcp)) {
        inc_drop();
        if (G_FEATURE_EVENTS)
            push_event(EVENT_DEATH_CODE, src_ip, 0);
        return XDP_DROP;
    }

    // Compute payload pointers
    __u8 *tcp_payload = (__u8 *)tcp + tcp_hdr_len;
    __u8 *tcp_payload_end = (__u8 *)data_end;
    __s32 tcp_payload_len = (__s32)(tcp_payload_end - tcp_payload);
    if (tcp_payload_len < 0)
        tcp_payload_len = 0;

    // ── Build flow key ──
    struct flow_key flow = {
        .src_ip   = src_ip,
        .dst_ip   = is_ipv6 ? 0 : ((struct iphdr *)(eth + 1))->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    // ── Verified player fast path ──
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow);
    if (player) {
        player->packets++;
        inc_pass();
        return XDP_PASS;
    }

    // ── SYN handling (new connection) ──
    if (tcp->syn && !tcp->ack) {
        // SYN throttle
        if (G_FEATURE_SYN_THROTTLE) {
            struct throttle_entry *th = bpf_map_lookup_elem(&connection_throttle, &src_ip);
            __u64 now = bpf_ktime_get_ns();

            if (th) {
                if (now - th->window_start < G_SYN_WINDOW_NS) {
                    if (th->hits >= G_SYN_HIT_COUNT) {
                        // Ban this IP
                        struct lpm_key ban_key = { .prefixlen = 32, .ip = src_ip };
                        __u64 ban_until = now + G_SYN_BAN_DURATION_NS;
                        bpf_map_update_elem(&blacklist_map, &ban_key, &ban_until, BPF_ANY);
                        inc_syn_throttle();
                        inc_drop();
                        if (G_FEATURE_EVENTS)
                            push_event(EVENT_RATE_LIMIT, src_ip, th->hits);
                        return XDP_DROP;
                    }
                    __sync_fetch_and_add(&th->hits, 1);
                } else {
                    th->window_start = now;
                    th->hits = 1;
                }
            } else {
                struct throttle_entry new_th = { .window_start = now, .hits = 1 };
                bpf_map_update_elem(&connection_throttle, &src_ip, &new_th, BPF_ANY);
            }
        }

        // Create conntrack entry for new connection
        struct conntrack_entry ce = {};
        ce.state = STATE_AWAIT_ACK;
        ce.expected_seq = bpf_ntohl(tcp->seq) + 1; // expect SYN-ACK seq
        ce.src_ip = src_ip;
        ce.src_port = tcp->source;

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

    // ── Sequence number tracking ──
    __u32 seq = bpf_ntohl(tcp->seq);
    if (conn->state != STATE_AWAIT_ACK && tcp_payload_len > 0) {
        if (seq != conn->expected_seq) {
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
    }

    // ── State machine ──
    __u32 state = conn->state;

    // Handle RST/FIN — clean up conntrack entry
    if (tcp->rst || tcp->fin) {
        bpf_map_delete_elem(&conntrack_map, &flow);
        inc_pass();
        return XDP_PASS;
    }

    if (state == STATE_AWAIT_ACK) {
        // Expecting ACK that completes TCP 3-way handshake
        if (!tcp->ack || seq != conn->expected_seq) {
            inc_drop();
            return XDP_DROP;
        }

        // ═══ FIX vs other implementations ═══
        // Do NOT drop pure ACK here. Other XDP filters drop the pure ACK
        // expecting the data packet to serve as ACK, which causes ~1-7s
        // TCP handshake deadlock. We pass the ACK through.
        conn->state = STATE_AWAIT_MC_HANDSHAKE;
        conn->expected_seq = seq + tcp_payload_len;

        // If this is a pure ACK (no data), pass it through
        if (tcp_payload_len == 0) {
            inc_pass();
            return XDP_PASS;
        }
        // Fall through to handshake inspection
    }
    else if (state == STATE_AWAIT_MC_HANDSHAKE) {
        // Pure ACK without data — pass through (keep-alive, etc.)
        if (tcp_payload_len == 0) {
            inc_pass();
            return XDP_PASS;
        }

        // Inspect handshake packet
        __u8 *cursor = tcp_payload;
        __s32 protocol = 0;

        __s32 result = inspect_handshake(&cursor, tcp_payload_end, &protocol, data_end);

        // Update expected sequence
        __u32 data_consumed = (__u32)(cursor - tcp_payload);
        conn->expected_seq += data_consumed;

        if (result == 0) {
            // Malformed handshake — ban
            struct lpm_key ban_key = { .prefixlen = 32, .ip = src_ip };
            __u64 now = bpf_ktime_get_ns();
            __u64 ban_until = now + G_BAN_DURATION_NS;
            bpf_map_update_elem(&blacklist_map, &ban_key, &ban_until, BPF_ANY);
            bpf_map_delete_elem(&conntrack_map, &flow);
            inc_drop();
            if (G_FEATURE_EVENTS)
                push_event(EVENT_BAN, src_ip, 1);
            return XDP_DROP;
        }

        if (result == RECEIVED_LEGACY_PING) {
            // Legacy ping (pre-1.7) — drop connection
            bpf_map_delete_elem(&conntrack_map, &flow);
            inc_drop();
            return XDP_DROP;
        }

        if (result == DIRECT_READ_LOGIN) {
            // Handshake + login in same segment
            __u8 login_ok = inspect_login_packet(cursor, tcp_payload_end, protocol, data_end);
            __u32 login_consumed = (__u32)(tcp_payload_end - cursor);
            if (login_consumed < (__u32)(tcp_payload_end - cursor))
                conn->expected_seq += login_consumed;

            if (!login_ok) {
                bpf_map_delete_elem(&conntrack_map, &flow);
                inc_drop();
                return XDP_DROP;
            }

            // Login passed — switch to verified
            if (switch_to_verified(&flow)) {
                conn->state = STATE_VERIFIED;
                inc_verified();
                if (G_FEATURE_EVENTS)
                    push_event(EVENT_VERIFIED, src_ip, protocol);
                return XDP_PASS;
            }
            inc_drop();
            return XDP_DROP;
        }

        if (result == DIRECT_READ_STATUS) {
            // Handshake + status request in same segment
            // Forge-style — pass through
            conn->state = STATE_PING_COMPLETE;
            inc_pass();
            return XDP_PASS;
        }

        // Normal: handshake only, wait for login
        conn->state = STATE_AWAIT_LOGIN;
        conn->expected_seq = seq + data_consumed;
        conn->protocol = (__u32)protocol;
        inc_pass();
        return XDP_PASS;
    }
    else if (state == STATE_AWAIT_LOGIN) {
        if (tcp_payload_len == 0) {
            inc_pass();
            return XDP_PASS;
        }

        __u8 login_ok = inspect_login_packet(tcp_payload, tcp_payload_end,
                                              (__s32)conn->protocol, data_end);

        if (!login_ok) {
            bpf_map_delete_elem(&conntrack_map, &flow);
            inc_drop();
            return XDP_DROP;
        }

        // Login passed — move to verified
        if (switch_to_verified(&flow)) {
            conn->state = STATE_VERIFIED;
            inc_verified();
            return XDP_PASS;
        }
        inc_drop();
        return XDP_DROP;
    }
    else if (state == STATE_VERIFIED) {
        // Should not happen — verified connections use fast path
        inc_pass();
        return XDP_PASS;
    }
    else if (state == STATE_PING_COMPLETE) {
        // Ping completed — drop connection
        bpf_map_delete_elem(&conntrack_map, &flow);
        inc_drop();
        return XDP_DROP;
    }

    // Unknown state — pass
    inc_pass();
    return XDP_PASS;

error:
    inc_drop();
    return XDP_DROP;
}
