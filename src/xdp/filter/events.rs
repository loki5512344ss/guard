//! Разбор и политика для событий XDP-ringbuf (`struct xdp_event`).
//!
//! Чистые (без I/O, без libbpf) функции, чтобы их можно было покрыть
//! юнит-тестами без ядра/Redis. Wiring колбэка — в [`super::attach`].

use std::net::Ipv4Addr;

use crate::config::XdpConfig;

/// Точный размер `struct xdp_event` (см. `xdp/core/common.h:61-66`):
/// `__u32 type` @0, `__u32 src_ip` @4, `__u32 metadata` @8,
/// 4 байта padding @12 (выравнивание `__u64`), `__u64 timestamp` @16 → 24.
pub const XDP_EVENT_LEN: usize = 24;

/// Тип события из `enum event_type` (`common.h:54-59`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpEventKind {
    /// `EVENT_BAN` — пакет уже был в blacklist_map и сброшен ядром.
    Ban,
    /// `EVENT_RATE_LIMIT` — превышен порог троттлинга (SYN/UDP).
    RateLimit,
    /// `EVENT_POLICY_DROP` — статичная политика (UDP drop / вредоносные TCP-флаги).
    PolicyDrop,
    /// `EVENT_CONN_DROP` — flow сброшен (несоответствие seq или verdict хука).
    ConnDrop,
}

impl XdpEventKind {
    /// Декодирует числовое значение из C-enum. Неизвестный тип → `None` + debug.
    fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ban),
            1 => Some(Self::RateLimit),
            2 => Some(Self::PolicyDrop),
            3 => Some(Self::ConnDrop),
            other => {
                tracing::debug!(event_type = other, "xdp event: unknown type, dropped");
                None
            },
        }
    }
}

/// Разобранное событие ringbuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpEvent {
    pub kind: XdpEventKind,
    /// IPv4 источника (для IPv4-mapped IPv6 ядро кладёт в `src_ip` младший u32).
    pub src_ip: Ipv4Addr,
    /// Поле `__u32 metadata`: для `RateLimit` — порог срабатывания троттлинга,
    /// для `ConnDrop` — счётчик `conn->fails`, иначе `0`.
    pub metadata: u32,
    /// `bpf_ktime_get_ns()` на момент генерации (monotonic, не wall-clock).
    pub timestamp_ns: u64,
}

/// Разбирает 24-байтовый кадр `struct xdp_event`.
///
/// # Byte order (проверено по C-источнику)
/// Скалярные поля (`type`, `metadata`, `timestamp`) пишутся ядром в ПОРЯДКЕ ХОСТА
/// без конверсии: `push_event` присваивает их как есть — `e->type = type`,
/// `e->metadata = meta`, `e->timestamp = bpf_ktime_get_ns()`
/// (`common.h:92-95`, `bpf_htonl`/`bpf_ntohl` к ним НЕ применяется). Userspace
/// читает те же байты на той же машине → `from_ne_bytes` корректно.
///
/// А вот `src_ip` — сетевой порядок (big-endian octets): он приходит прямо из
/// заголовка пакета `src_ip = ip->saddr` (`universal_filter.c:149`) и пишется в
/// событие без `bpf_htonl` (`common.h:93`). Значит байты `data[4..8]` — это октеты
/// адреса в точковом порядке, и читать их надо как `Ipv4Addr::new(octets...)`, а НЕ
/// как `from_ne_bytes(u32)` (прежний баг: на LE-хосте давал перевернутый IP).
///
/// Возвращает `None`, если кадр короче `XDP_EVENT_LEN` или тип неизвестен.
pub fn parse_xdp_event(bytes: &[u8]) -> Option<XdpEvent> {
    let raw: &[u8; XDP_EVENT_LEN] = bytes.get(..XDP_EVENT_LEN)?.try_into().ok()?;
    let kind = XdpEventKind::from_u32(u32::from_ne_bytes(raw[0..4].try_into().ok()?))?;
    let src_ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    let metadata = u32::from_ne_bytes(raw[8..12].try_into().ok()?);
    // raw[12..16] — выравнивающий padding под __u64, не читаем (он не инициализирован).
    let timestamp_ns = u64::from_ne_bytes(raw[16..24].try_into().ok()?);
    Some(XdpEvent {
        kind,
        src_ip,
        metadata,
        timestamp_ns,
    })
}

/// Параметры авто-бана, резолвинг из секции `[xdp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoBanConfig {
    pub enabled: bool,
    pub duration_secs: u64,
    pub conn_drop_fails: u8,
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration_secs: 60,
            conn_drop_fails: 3,
        }
    }
}

impl AutoBanConfig {
    /// Берёт значения из `[xdp]`-секции конфига (единственный источник истины).
    pub fn from_xdp(cfg: &XdpConfig) -> Self {
        Self {
            enabled: cfg.auto_ban_enabled,
            duration_secs: cfg.auto_ban_duration_secs,
            conn_drop_fails: cfg.auto_ban_conn_drop_fails,
        }
    }
}

/// Готовый бан для применения к userspace-`Blacklist`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanAction {
    pub ip: Ipv4Addr,
    pub duration_secs: u64,
    /// Статичная причина (без аллокаций в горячем пути).
    pub reason: &'static str,
}

/// Чистое решение: банить ли источник события и на сколько.
///
/// Возвращает `None`, если фича выключена или тип события не банится.
/// Разбор по типам обоснован C-кодом:
///
/// * [`XdpEventKind::Ban`] — НЕ баним. Событие эмитится уже ПОСЛЕ того, как
///   ядро нашло IP в `blacklist_map` и дропнуло пакет (`universal_filter.c:220-225`);
///   повторный userspace-бан бессмысленен и мог бы скрыть штатный expiry.
/// * [`XdpEventKind::PolicyDrop`] — НЕ баним по умолчанию. Это статичная
///   политика на каждый пакет: UDP-drop-политика (`:234`) и вредоносные TCP-флаги
///   (`:259`). Бан по одному malformed-пакету перебанит легитимных, но глючных
///   клиентов — порог аккумулирования здесь отсутствует по смыслу.
/// * [`XdpEventKind::RateLimit`] — банیم. Порог троттлинга уже фактически превышен;
///   при этом UDP-путь (`:237-243`) только дропает и НЕ заносит в blacklist (в
///   отличие от SYN-пути `:295`) — userspace-бан добавляет реальную защиту.
/// * [`XdpEventKind::ConnDrop`] — баним, только если `metadata` (=`conn->fails`)
///   достиг порога (`:364-368`). Дроп по протокольному хуку приходит с `fails = 0`
///   (`:418`) и ниже порога, т.е. не банится.
#[must_use]
pub fn auto_ban_decision(event: &XdpEvent, config: &AutoBanConfig) -> Option<BanAction> {
    if !config.enabled {
        return None;
    }
    match event.kind {
        XdpEventKind::Ban | XdpEventKind::PolicyDrop => None,
        XdpEventKind::RateLimit => Some(BanAction {
            ip: event.src_ip,
            duration_secs: config.duration_secs,
            reason: "xdp-rate-limit",
        }),
        XdpEventKind::ConnDrop if event.metadata >= u32::from(config.conn_drop_fails) => Some(BanAction {
            ip: event.src_ip,
            duration_secs: config.duration_secs,
            reason: "xdp-conn-drop",
        }),
        XdpEventKind::ConnDrop => None,
    }
}

// Покрытие парсера и политики — в `tests/xdp_events.rs` (держим модуль под
// лимитом 250 строк; `src/xdp/filter/` уже на пределе в 4 файла на каталог).
