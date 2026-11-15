#ifndef RAMPART_CONFIG_H
#define RAMPART_CONFIG_H

/**
 * Runtime-tunable filter configuration.
 *
 * The whole configuration lives in one aggregate in .rodata so that its
 * layout is fixed by this C declaration and by the mirrored #[repr(C)]
 * XdpGlobals in Rust, not by the linker's choice of symbol order. Separate
 * globals used to be reordered by clang, which silently broke hardcoded
 * offsets; a single aggregated object is emitted whole and stays stable.
 *
 * The object is volatile const: the loader patches the .rodata map before
 * the program is loaded, so the compiler must not constant-fold reads.
 */
struct rampart_config {
    // Protected port range: packets to ports outside it bypass the filter
    // entirely (XDP_PASS before any counting). Default protects every
    // TCP/UDP port; narrow it via loader patching for dedicated-edge setups.
    __u16 start_port;                 // 1
    __u16 end_port;                   // 65535

    // SYN throttle window: hit count per source, window length, ban length.
    __u32 syn_hit_count;              // 10 max SYNs / window
    __u64 syn_window_ns;              // 3 sec
    __u64 syn_ban_duration_ns;        // 60 sec

    // Idle timeouts. The XDP path does not read them yet; they are part of
    // the loader ABI so userspace can drive timer-based cleanup.
    __u64 conntrack_idle_ns;          // 30 sec
    __u64 player_idle_ns;             // 120 sec

    // Default ban duration userspace applies to new blacklist entries.
    __u64 ban_duration_ns;            // 5 min

    // Out-of-order payload packets tolerated before the connection is cut.
    __u8  max_out_of_order;           // 4

    // UDP policy and its rate-limit window.
    __u8  udp_policy;                 // 0 = pass, 1 = drop, 2 = rate-limit
    __u32 udp_hit_count;              // 100 max packets / window
    __u64 udp_window_ns;              // 1 sec

    // Feature switches read on the hot path.
    __u8  feature_syn_throttle;       // 1
    __u8  feature_events;             // 1

    // RST-challenge (Oubliette-style liveness proof). 0 disables it, leaving
    // a single branch and zero cost for legitimate traffic. The secret is
    // patched by the loader at attach time; the value below is a placeholder.
    __u8  syn_challenge_enabled;      // 0
    __u64 challenge_secret;           // 0xA5A55A5A5A5AA5A5
    __u32 challenge_timeout_ms;       // 3000 pending TTL
    __u64 challenge_verified_ttl_ns;  // 5 min
};

/**
 * Default configuration image shipped inside the object file.
 *
 * volatile const keeps every read tied to the patched .rodata map instead of
 * being folded into a constant at compile time.
 */
static volatile const struct rampart_config G = {
    .start_port               = 1,
    .end_port                 = 65535,
    .syn_hit_count            = 10,
    .syn_window_ns            = 3000000000ULL,
    .syn_ban_duration_ns      = 60000000000ULL,
    .conntrack_idle_ns        = 30000000000ULL,
    .player_idle_ns           = 120000000000ULL,
    .ban_duration_ns          = 300000000000ULL,
    .max_out_of_order         = 4,
    .udp_policy               = 0,
    .udp_hit_count            = 100,
    .udp_window_ns            = 1000000000ULL,
    .feature_syn_throttle     = 1,
    .feature_events           = 1,
    .syn_challenge_enabled    = 0,
    .challenge_secret         = 0xA5A55A5A5A5AA5A5ULL,
    .challenge_timeout_ms     = 3000,
    .challenge_verified_ttl_ns = 300000000000ULL,
};

/**
 * ABI guard for the configuration struct.
 *
 * The byte layout is part of the loader contract: src/xdp/globals.rs writes
 * fields at offset_of!(XdpGlobals, ..), and the real-kernel smoke patches
 * udp_policy and udp_hit_count by raw offset. Reordering or resizing a field
 * must break the build instead of silently misconfiguring the filter.
 */
_Static_assert(sizeof(struct rampart_config) == 96,
               "sizeof(struct rampart_config) must match XdpGlobals");
_Static_assert(__builtin_offsetof(struct rampart_config, start_port) == 0, "start_port");
_Static_assert(__builtin_offsetof(struct rampart_config, end_port) == 2, "end_port");
_Static_assert(__builtin_offsetof(struct rampart_config, syn_hit_count) == 4, "syn_hit_count");
_Static_assert(__builtin_offsetof(struct rampart_config, syn_window_ns) == 8, "syn_window_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, syn_ban_duration_ns) == 16, "syn_ban_duration_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, conntrack_idle_ns) == 24, "conntrack_idle_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, player_idle_ns) == 32, "player_idle_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, ban_duration_ns) == 40, "ban_duration_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, max_out_of_order) == 48, "max_out_of_order");
_Static_assert(__builtin_offsetof(struct rampart_config, udp_policy) == 49, "udp_policy");
_Static_assert(__builtin_offsetof(struct rampart_config, udp_hit_count) == 52, "udp_hit_count");
_Static_assert(__builtin_offsetof(struct rampart_config, udp_window_ns) == 56, "udp_window_ns");
_Static_assert(__builtin_offsetof(struct rampart_config, feature_syn_throttle) == 64, "feature_syn_throttle");
_Static_assert(__builtin_offsetof(struct rampart_config, feature_events) == 65, "feature_events");
_Static_assert(__builtin_offsetof(struct rampart_config, syn_challenge_enabled) == 66, "syn_challenge_enabled");
_Static_assert(__builtin_offsetof(struct rampart_config, challenge_secret) == 72, "challenge_secret");
_Static_assert(__builtin_offsetof(struct rampart_config, challenge_timeout_ms) == 80, "challenge_timeout_ms");
_Static_assert(__builtin_offsetof(struct rampart_config, challenge_verified_ttl_ns) == 88, "challenge_verified_ttl_ns");

/**
 * Read-only aliases that keep the hot path short.
 *
 * They expand to field accesses on G, so they remain live reads of the
 * patched .rodata and cost nothing at runtime.
 */
#define G_START_PORT              G.start_port
#define G_END_PORT                G.end_port
#define G_SYN_HIT_COUNT           G.syn_hit_count
#define G_SYN_WINDOW_NS           G.syn_window_ns
#define G_SYN_BAN_DURATION_NS     G.syn_ban_duration_ns
#define G_CONNTRACK_IDLE_NS       G.conntrack_idle_ns
#define G_PLAYER_IDLE_NS          G.player_idle_ns
#define G_BAN_DURATION_NS         G.ban_duration_ns
#define G_MAX_OUT_OF_ORDER        G.max_out_of_order
#define G_UDP_POLICY              G.udp_policy
#define G_UDP_HIT_COUNT           G.udp_hit_count
#define G_UDP_WINDOW_NS           G.udp_window_ns
#define G_FEATURE_SYN_THROTTLE    G.feature_syn_throttle
#define G_FEATURE_EVENTS          G.feature_events
#define G_SYN_CHALLENGE_ENABLED   G.syn_challenge_enabled
#define G_CHALLENGE_SECRET        G.challenge_secret
#define G_CHALLENGE_TIMEOUT_MS    G.challenge_timeout_ms
#define G_CHALLENGE_VERIFIED_TTL_NS G.challenge_verified_ttl_ns

#endif /* RAMPART_CONFIG_H */
