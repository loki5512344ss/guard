//! Патчинг volatile const глобалов XDP-программы (`xdp/core/config.h`) из TOML-конфига.
//!
//! Глобалы живут в секции `.rodata`, которая при загрузке превращается в карту
//! с именем `rampart_.rodata`. Образ патчится до `load()` через
//! `OpenMapMut::set_initial_value()` (см. [`crate::xdp::filter`]).
//!
//! # Схема маппинга `[xdp]` → G_* (единственный источник истины)
//!
//! | Конфиг                  | Глобал                       | Тип |
//! |-------------------------|------------------------------|-----|
//! | `protected_port_start`  | `G_START_PORT`               | u16 |
//! | `protected_port_end`    | `G_END_PORT`                 | u16 |
//! | `udp_policy`            | `G_UDP_POLICY`               | u8 ("pass"=0, "drop"=1, "rate-limit"=2) |
//! | `udp_rate_hit_count`    | `G_UDP_HIT_COUNT`            | u32 |
//! | `udp_rate_window_ms`    | `G_UDP_WINDOW_NS`            | u64 (мс → нс) |
//! | `throttle_enabled`      | `G_FEATURE_SYN_THROTTLE`     | u8 (bool → 0/1) |
//! | `events_enabled`        | `G_FEATURE_EVENTS`           | u8 (bool → 0/1) |
//! | `syn_challenge_enabled` | `G_SYN_CHALLENGE_ENABLED`    | u8 (bool → 0/1) |
//! | `challenge_secret_hex`  | `G_CHALLENGE_SECRET`         | u64 (hex, big-endian) |
//! | `challenge_timeout_ms`  | `G_CHALLENGE_TIMEOUT_MS`     | u32 |
//!
//! Остальные глобалы (`G_SYN_*`, `G_CONNTRACK_IDLE_NS`, `G_PLAYER_IDLE_NS`,
//! `G_BAN_DURATION_NS`, `G_MAX_OUT_OF_ORDER`, `G_CHALLENGE_VERIFIED_TTL_NS`)
//! конфигом пока не управляются и патчатся значениями по умолчанию из config.h.

use anyhow::{Context, Result, bail};

use crate::config::XdpConfig;

/// Имя карты с образом `.rodata` загруженного BPF-объекта.
pub(crate) const RODATA_MAP_NAME: &str = "rampart_.rodata";

/// Размер образа `.rodata` в байтах (см. `build_rodata_image`).
pub const RODATA_SIZE: usize = 96;

/// Значение `G_UDP_POLICY`: пропускать UDP.
pub const UDP_POLICY_PASS: u8 = 0;
/// Значение `G_UDP_POLICY`: дропать весь UDP.
pub const UDP_POLICY_DROP: u8 = 1;
/// Значение `G_UDP_POLICY`: rate-limit по окну/порогу.
pub const UDP_POLICY_RATE_LIMIT: u8 = 2;

/// Дефолт-плейсхолдер `G_CHALLENGE_SECRET` из config.h.
const DEFAULT_CHALLENGE_SECRET: u64 = 0xA5A5_A5A5_A5A5_A5A5;

/// Runtime-значения глобалов XDP-программы; `Default` совпадает с config.h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpGlobals {
    pub start_port: u16,
    pub end_port: u16,
    pub syn_hit_count: u32,
    pub syn_window_ns: u64,
    pub syn_ban_duration_ns: u64,
    pub conntrack_idle_ns: u64,
    pub player_idle_ns: u64,
    pub ban_duration_ns: u64,
    pub max_out_of_order: u8,
    pub udp_policy: u8,
    pub udp_hit_count: u32,
    pub udp_window_ns: u64,
    pub feature_syn_throttle: bool,
    pub feature_events: bool,
    pub syn_challenge_enabled: bool,
    pub challenge_secret: u64,
    pub challenge_timeout_ms: u32,
    pub challenge_verified_ttl_ns: u64,
}

impl Default for XdpGlobals {
    fn default() -> Self {
        Self {
            start_port: 1,
            end_port: 65535,
            syn_hit_count: 10,
            syn_window_ns: 3_000_000_000,
            syn_ban_duration_ns: 60_000_000_000,
            conntrack_idle_ns: 30_000_000_000,
            player_idle_ns: 120_000_000_000,
            ban_duration_ns: 300_000_000_000,
            max_out_of_order: 4,
            udp_policy: UDP_POLICY_PASS,
            udp_hit_count: 100,
            udp_window_ns: 1_000_000_000,
            feature_syn_throttle: true,
            feature_events: true,
            syn_challenge_enabled: false,
            challenge_secret: DEFAULT_CHALLENGE_SECRET,
            challenge_timeout_ms: 3000,
            challenge_verified_ttl_ns: 300_000_000_000,
        }
    }
}

impl XdpGlobals {
    /// Собирает байтовый образ `.rodata` в порядке объявления глобалов
    /// в `xdp/core/config.h` с естественным выравниванием каждого поля.
    ///
    /// RISK: раскладка предполагает, что линкер кладёт статические переменные
    /// в секцию `.rodata` в порядке объявления с natural alignment — на
    /// практике это так (каждая `static volatile const` получает своё
    /// выравнивание, padding виден в смещениях ниже), но стандарт C этого не
    /// гарантирует. TODO: верифицировать смещения на сервере через BTF-dump
    /// карты `rampart_.rodata` (`bpftool btf dump`) и зафиксировать их здесь.
    pub fn build_rodata_image(&self) -> Vec<u8> {
        let mut img = vec![0u8; RODATA_SIZE];
        // u16 ×2 без padding: смещения 0..4.
        img[0..2].copy_from_slice(&self.start_port.to_le_bytes());
        img[2..4].copy_from_slice(&self.end_port.to_le_bytes());
        // u32, align 4: 4..8.
        img[4..8].copy_from_slice(&self.syn_hit_count.to_le_bytes());
        // u64, align 8: 8..48 (SYN throttle + idle timeouts + ban duration).
        img[8..16].copy_from_slice(&self.syn_window_ns.to_le_bytes());
        img[16..24].copy_from_slice(&self.syn_ban_duration_ns.to_le_bytes());
        img[24..32].copy_from_slice(&self.conntrack_idle_ns.to_le_bytes());
        img[32..40].copy_from_slice(&self.player_idle_ns.to_le_bytes());
        img[40..48].copy_from_slice(&self.ban_duration_ns.to_le_bytes());
        // u8 ×3 подряд: 48, 49, 50 (max_out_of_order, udp_policy, —).
        img[48] = self.max_out_of_order;
        img[49] = self.udp_policy;
        // u32 после u8: padding 50..52, значение 52..56.
        img[52..56].copy_from_slice(&self.udp_hit_count.to_le_bytes());
        // u64, align 8: 56..64.
        img[56..64].copy_from_slice(&self.udp_window_ns.to_le_bytes());
        // u8 ×3 (feature flags + challenge flag): 64, 65, 66.
        img[64] = u8::from(self.feature_syn_throttle);
        img[65] = u8::from(self.feature_events);
        img[66] = u8::from(self.syn_challenge_enabled);
        // u64 после u8: padding 67..72, значение 72..80.
        img[72..80].copy_from_slice(&self.challenge_secret.to_le_bytes());
        // u32: 80..84.
        img[80..84].copy_from_slice(&self.challenge_timeout_ms.to_le_bytes());
        // u64 после u32: padding 84..88, значение 88..96.
        img[88..96].copy_from_slice(&self.challenge_verified_ttl_ns.to_le_bytes());
        img
    }

    /// Строит глобалы из секции `[xdp]` конфига.
    ///
    /// # Errors
    /// Неизвестное значение `udp_policy`; некорректный `challenge_secret_hex`
    /// (не hex или не 8 байт); `protected_port_end < protected_port_start`.
    pub fn from_config(cfg: &XdpConfig) -> Result<Self> {
        let mut g = Self {
            start_port: cfg.protected_port_start,
            end_port: cfg.protected_port_end,
            udp_hit_count: cfg.udp_rate_hit_count,
            udp_window_ns: cfg.udp_rate_window_ms.saturating_mul(1_000_000),
            feature_syn_throttle: cfg.throttle_enabled,
            feature_events: cfg.events_enabled,
            syn_challenge_enabled: cfg.syn_challenge_enabled,
            challenge_timeout_ms: cfg.challenge_timeout_ms,
            ..Self::default()
        };
        if g.end_port < g.start_port {
            bail!(
                "xdp.protected_port_end ({}) < xdp.protected_port_start ({})",
                g.end_port,
                g.start_port
            );
        }
        g.udp_policy = match cfg.udp_policy.as_str() {
            "pass" => UDP_POLICY_PASS,
            "drop" => UDP_POLICY_DROP,
            "rate-limit" => UDP_POLICY_RATE_LIMIT,
            other => bail!("invalid xdp.udp_policy '{other}' (expected pass|drop|rate-limit)"),
        };
        if let Some(secret) = cfg.challenge_secret_hex.as_deref() {
            g.challenge_secret = parse_secret_hex(secret)?;
        }
        Ok(g)
    }
}

/// Парсит 128-битный hex (16 символов, опциональный префикс `0x`) в u64 (big-endian).
fn parse_secret_hex(s: &str) -> Result<u64> {
    let cleaned = s.trim().trim_start_matches("0x").replace(['_', ':', '-'], "");
    let bytes = hex::decode(&cleaned).with_context(|| format!("invalid xdp.challenge_secret_hex '{s}'"))?;
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("xdp.challenge_secret_hex must be exactly 8 bytes, got {}", v.len()))?;
    Ok(u64::from_be_bytes(arr))
}
