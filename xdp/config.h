#ifndef RAMPART_CONFIG_H
#define RAMPART_CONFIG_H

// ⚙️ Runtime configurable globals (patched by Rust loader)
// These are volatile const — compiler replaces reads with immediate values
// after loader writes to .rodata section

// ── Port range ──
static volatile const __u16 G_START_PORT = 25565;
static volatile const __u16 G_END_PORT   = 25570;

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

// ── Feature flags ──
static volatile const __u8 G_FEATURE_SYN_THROTTLE  = 1;
static volatile const __u8 G_FEATURE_EVENTS        = 1;

#endif /* RAMPART_CONFIG_H */
