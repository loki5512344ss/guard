#ifndef RAMPART_CONFIG_H
#define RAMPART_CONFIG_H

// ⚙️ Runtime configurable globals (patched by Rust loader)
// These are volatile const — compiler replaces reads with immediate values
// after loader writes to .rodata section

// ── Port range ──
// Protected port range: packets to ports OUTSIDE this range bypass the
// filter (XDP_PASS before any counting/filtering). Default protects all
// TCP/UDP ports; narrow it via loader patching for dedicated-edge setups.
static volatile const __u16 G_START_PORT = 1;
static volatile const __u16 G_END_PORT   = 65535;

// ── SYN throttle ──
static volatile const __u32 G_SYN_HIT_COUNT      = 10;    // max SYNs / window
static volatile const __u64 G_SYN_WINDOW_NS       = 3000000000ULL; // 3 sec
static volatile const __u64 G_SYN_BAN_DURATION_NS = 60000000000ULL; // 60 sec

// ── Idle timeouts ──
static volatile const __u64 G_CONNTRACK_IDLE_NS   = 30000000000ULL; // 30 sec
static volatile const __u64 G_PLAYER_IDLE_NS      = 120000000000ULL; // 120 sec

// ── Blacklist default ban duration ──
static volatile const __u64 G_BAN_DURATION_NS     = 300000000000ULL; // 5 min

// ── Max out-of-order packets before dropping connection ──
static volatile const __u8 G_MAX_OUT_OF_ORDER = 4;

// ── UDP policy ──
static volatile const __u8 G_UDP_POLICY = 0; // 0 = pass, 1 = drop, 2 = rate-limit
static volatile const __u32 G_UDP_HIT_COUNT = 100;                  // max packets / window
static volatile const __u64 G_UDP_WINDOW_NS = 1000000000ULL;        // 1 sec

// ── Feature flags ──
static volatile const __u8 G_FEATURE_SYN_THROTTLE  = 1;
static volatile const __u8 G_FEATURE_EVENTS        = 1;

// ── RST-challenge (Oubliette liveness proof) ──
// 0 = disabled: single branch, zero cost for legitimate traffic.
// Secret is patched by the loader at attach time (default is a placeholder).
static volatile const __u8  G_SYN_CHALLENGE_ENABLED = 0;
static volatile const __u64 G_CHALLENGE_SECRET      = 0xA5A55A5A5A5AA5A5ULL;
static volatile const __u32 G_CHALLENGE_TIMEOUT_MS  = 3000;           // pending TTL
static volatile const __u64 G_CHALLENGE_VERIFIED_TTL_NS = 300000000000ULL; // 5 min

#endif /* RAMPART_CONFIG_H */
