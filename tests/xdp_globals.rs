#![cfg(feature = "xdp")]

use rampart::config::Config;
use rampart::xdp::XdpGlobals;

#[test]
fn rodata_image_size_is_stable() {
    let img = XdpGlobals::default().build_rodata_image();
    assert_eq!(img.len(), 96, ".rodata image size must match config.h layout");
}

#[test]
fn rodata_defaults_match_config_h() {
    let img = XdpGlobals::default().build_rodata_image();
    let rd = |off: usize| u64::from_le_bytes(img[off..off + 8].try_into().expect("8 bytes"));
    let rd32 = |off: usize| u32::from_le_bytes(img[off..off + 4].try_into().expect("4 bytes"));
    assert_eq!(&img[0..2], 1u16.to_le_bytes());
    assert_eq!(&img[2..4], 65535u16.to_le_bytes());
    assert_eq!(rd32(4), 10); // G_SYN_HIT_COUNT
    assert_eq!(rd(8), 3_000_000_000); // G_SYN_WINDOW_NS
    assert_eq!(rd(16), 60_000_000_000); // G_SYN_BAN_DURATION_NS
    assert_eq!(rd(24), 30_000_000_000); // G_CONNTRACK_IDLE_NS
    assert_eq!(rd(32), 120_000_000_000); // G_PLAYER_IDLE_NS
    assert_eq!(rd(40), 300_000_000_000); // G_BAN_DURATION_NS
    assert_eq!(img[48], 4); // G_MAX_OUT_OF_ORDER
    assert_eq!(img[49], 0); // G_UDP_POLICY
    assert_eq!(rd32(52), 100); // G_UDP_HIT_COUNT (padding 50..52)
    assert_eq!(rd(56), 1_000_000_000); // G_UDP_WINDOW_NS
    assert_eq!(img[64], 1); // G_FEATURE_SYN_THROTTLE
    assert_eq!(img[65], 1); // G_FEATURE_EVENTS
    assert_eq!(img[66], 0); // G_SYN_CHALLENGE_ENABLED
    assert_eq!(rd(72), 0xA5A5_A5A5_A5A5_A5A5); // G_CHALLENGE_SECRET (padding 67..72)
    assert_eq!(rd32(80), 3000); // G_CHALLENGE_TIMEOUT_MS
    assert_eq!(rd(88), 300_000_000_000); // G_CHALLENGE_VERIFIED_TTL_NS (padding 84..88)
}

#[test]
fn rodata_padding_bytes_stay_zero() {
    let g = XdpGlobals {
        max_out_of_order: u8::MAX,
        udp_policy: u8::MAX,
        feature_syn_throttle: true,
        feature_events: true,
        syn_challenge_enabled: true,
        ..XdpGlobals::default()
    };
    let img = g.build_rodata_image();
    for off in [50, 51, 67, 68, 69, 70, 71, 84, 85, 86, 87] {
        assert_eq!(img[off], 0, "alignment padding at {off} must stay zeroed");
    }
}

#[test]
fn from_config_maps_fields() {
    let cfg = Config::parse_str(
        r#"
[xdp]
protected_port_start = 25560
protected_port_end = 25600
udp_policy = "rate-limit"
udp_rate_hit_count = 500
udp_rate_window_ms = 2000
syn_challenge_enabled = true
challenge_secret_hex = "0011223344556677"
challenge_timeout_ms = 7000
throttle_enabled = false
events_enabled = false
"#,
    )
    .expect("[xdp] section must parse");
    let g = XdpGlobals::from_config(&cfg.xdp).expect("globals must build");
    assert_eq!(g.start_port, 25560);
    assert_eq!(g.end_port, 25600);
    assert_eq!(g.udp_policy, 2);
    assert_eq!(g.udp_hit_count, 500);
    assert_eq!(g.udp_window_ns, 2_000_000_000);
    assert!(!g.feature_syn_throttle);
    assert!(!g.feature_events);
    assert!(g.syn_challenge_enabled);
    assert_eq!(g.challenge_secret, 0x0011_2233_4455_6677);
    assert_eq!(g.challenge_timeout_ms, 7000);

    let img = g.build_rodata_image();
    assert_eq!(img[49], 2);
    assert_eq!(img[64], 0);
    assert_eq!(&img[0..2], 25560u16.to_le_bytes());
}

#[test]
fn from_config_rejects_bad_udp_policy() {
    let cfg = Config::parse_str("[xdp]\nudp_policy = \"flood\"\n").expect("config parses");
    assert!(XdpGlobals::from_config(&cfg.xdp).is_err());
}

#[test]
fn from_config_rejects_inverted_port_range() {
    let cfg = Config::parse_str("[xdp]\nprotected_port_start = 100\nprotected_port_end = 50\n").expect("config parses");
    assert!(XdpGlobals::from_config(&cfg.xdp).is_err());
}

#[test]
fn from_config_rejects_bad_secret_hex() {
    for secret in ["nothex", "0011", "001122334455667788"] {
        let toml = format!("[xdp]\nchallenge_secret_hex = \"{secret}\"\n");
        let cfg = Config::parse_str(&toml).expect("config parses");
        assert!(
            XdpGlobals::from_config(&cfg.xdp).is_err(),
            "secret '{secret}' must be rejected"
        );
    }
}

#[test]
fn xdp_section_defaults_match_config_h() {
    let cfg = Config::parse_str("").expect("empty config parses");
    let g = XdpGlobals::from_config(&cfg.xdp).expect("globals must build");
    assert_eq!(g, XdpGlobals::default());
}
