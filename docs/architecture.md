# Architecture — Rampart

> Текущее устройство системы: процессы, путь пакета и соединения, слои фильтрации,
> хранилища и наблюдаемость. Планы — в [roadmap/](roadmap/README.md); правила
> разработки — в [development.md](development.md); исследования и обоснования —
> в [research/](research/architecture.md).

---

## 1. Назначение

Rampart отбрасывает атакующий трафик до того, как он дойдёт до сервиса. Одна
платформа защищает TCP-сервис любого типа: веб-приложение, API, игровой сервер.
Логика конкретного протокола вынесена в compile-time плагины, поэтому ядро не
знает о Minecraft или HTTP ничего.

Модель угроз: распределённый флуд соединениями (SYN/connection flood), мусорные
L7-handshake, медленные клиенты (slowloris), ботнет с ротацией адресов внутри
подсети, повторные попытки с уже забаненных адресов. Rampart — stateless-фильтр
и не заменяет firewall или WAF: он не хранит тело запроса и не анализирует
шифрованный трафик.

## 2. Процессы

| Бинарь | Роль | Порты |
|--------|------|-------|
| `rampart` | edge-нода: XDP → PoW → userspace → плагин → upstream | `bind.port` (25565), metrics `[metrics].port` (9090) |
| `rampart-manager` | REST API и инвентарь | `0.0.0.0:8080` |
| `rampart-cli` | клиент manager API (`status`, `doctor`, `blacklist`, …) | — |
| `rampart-tui` | live-дашборд по Prometheus | — |

Edge и manager — независимые процессы. Связь только через Redis (баны, инвентарь,
heartbeat); без Redis edge продолжает работать автономно.

## 3. Путь трафика edge

```
client → eth0 → [XDP/eBPF] → kernel TCP → accept → Gateway → plugin → upstream
                      │                                  │
                      └─ ringbuf events → autoban        └─ Redis/ClickHouse
```

### 3.1 XDP (C, `xdp/core/`)

Stateless-фильтр на входе интерфейса. Разбирает Ethernet (VLAN/QinQ), IPv4/IPv6,
L4; порт-гейт `[xdp] protected_port_start/end` отсекает нецелевой трафик до
фильтра.

| Механизм | IPv4 | IPv6 |
|----------|------|------|
| Blacklist LPM (`/32`, `/128`, префиксы) | да | да |
| Whitelist LPM | да | да |
| TCP conntrack, SYN-throttle | да | нет |
| RST-challenge (liveness proof) | да | нет |
| UDP policy: pass/drop/rate-limit | да | да |
| Prefix-статистика (`/24`, `/64`) | да | да |
| Ringbuf-события | да | нет (только счётчики) |

Карты (`xdp/core/maps.h`): `blacklist_map`, `blacklist6_map`, `whitelist_map`,
`whitelist6_map`, `connection_map`, `throttle_map`, `prefix_stats`, `stats_map`,
`events_ringbuf`, `syn_challenge`-карты. Значение бана — монотонное время
истечения (`bpf_ktime_get_ns`), просроченные записи чистит userspace-reaper.

### 3.2 Gateway (Rust, `src/engine/tunnel/gateway/`)

Порядок фильтров на одно соединение (важен для безопасности и стоимости):

1. Whitelist — доверенный адрес обходит все проверки и никогда не банится.
2. Blacklist (local + Redis).
3. Subnet tracker: запись источника для детектора подсетей.
4. Per-IP rate limit (token bucket) — до PoW, чтобы несолвенный клиент не занимал
   задачу.
5. Глобальный бюджет соединений — защита от перегрузки accept-loop.
6. Per-IP лимит одновременных соединений.
7. PoW-гейт (опционально; несовместим с Minecraft).
8. Handshake плагина с таймаутом.
9. Connect к upstream, отправка preamble (например, PROXY v2), relay с idle-таймаутом.

Соединения принимает `src/engine/listener.rs`: несколько воркеров с
`SO_REUSEPORT`, backoff на `accept()` при `EMFILE`/`ENOMEM`, graceful shutdown
через `watch`-канал. Ingress PROXY v2 (`[proxy_protocol]`) принимается только от
`trusted_cidrs`; адрес из заголовка валидируется и не может быть loopback/
link-local/multicast/broadcast или адресом самого прокси.

### 3.3 Протокол-плагины (`src/protocol/`)

`ProtocolHandler` — трейт: разобрать handshake, вернуть upstream и байты,
которые нужно отправить в backend до relay. Плагины включаются feature-флагами:

- `protocol-http` — HTTP/1.1 request-head: allow/reject, лимит заголовков,
  blocked paths, обязательный User-Agent.
- `protocol-minecraft` — Minecraft Java handshake/list/login, один upstream,
  опциональный PROXY v2 к Paper.

Реестр (`ProtocolRegistry`) выбирает активный плагин; пустой реестр — fail-fast
при старте с подсказкой про фичи.

### 3.4 Detection и реакция (`src/traffic/`, `src/engine/subnet/`)

- `AttackDetector` — EWMA baseline по pps/cps, состояния normal → suspicious →
  under_attack с гистерезисом.
- `IpReputation` — score источника; хорошие соединения повышают, плохие понижают.
- `SubnetDetector` — превышение порога префиксом при адресах под per-IP лимитом;
  лестница вердиктов: strict limit → challenge → block префикса (через `ban_cidr`,
  не слепой hard-ban).
- `TrafficHook` — единая точка авто-бана; сверяется с `trusted_cidrs` и
  подавляет бан доверенной сети.
- `AlertDispatcher` — алерт только на переход состояния, опционально webhook.

## 4. Manager API

`src/manager/` — axum-роутер, JWT (HS256, audience, `JWT_SECRET` ≥ 32 байт),
per-IP лимиты (5 login/мин, 30 мутаций/мин), тело ≤ 8 КиБ, таймаут 10 с,
CORS только по явному `CORS_ORIGIN`.

| Маршрут | Доступ | Источник |
|---------|--------|----------|
| `GET /api/v1/health` | публичный | процесс |
| `POST /api/v1/auth/login` | публичный | `API_PASSWORD` |
| `GET /api/v1/servers` | JWT | Redis `rampart:servers:*` |
| `GET/POST/DELETE /api/v1/blacklist` | JWT | Redis set + metadata hash + pub/sub |
| `GET /api/v1/nodes` | JWT | Redis `rampart:nodes:*` (heartbeat) |

Мутации публикуют событие в `rampart:blacklist:events`; edge подписывается до
загрузки снимка, поэтому события во время загрузки не теряются. Полный контракт —
[api.md](api.md).

## 5. Хранилища

| Хранилище | Что хранит | Без него |
|-----------|------------|----------|
| Redis | blacklist set + metadata, pub/sub событий, инвентарь нод и серверов | edge автономен, кросс-нодовые баны не работают |
| ClickHouse | события атак и соединений (`rampart_events`) | запись событий выключена |
| Prometheus | метрики edge | дашборд/TUI без данных |

Redis-клиент работает через `ConnectionManager` с таймаутами и реконнектом;
снимок банов восстанавливается после переподключения с оставшимся TTL.

## 6. Наблюдаемость

`GET /metrics` на edge (Prometheus text format).

| Метрика | Тип | Смысл |
|---------|-----|-------|
| `rampart_connections_total{result}` | counter | allowed / blocked / overloaded |
| `rampart_rate_limit_hits{action}` | counter | срабатывания лимитов |
| `rampart_pow_challenges_total{result}` | counter | выдан/решён/отклонён |
| `rampart_pow_current_difficulty` | gauge | текущая сложность |
| `rampart_attack_status` | gauge | 0 normal, 1 suspicious, 2 under attack |
| `rampart_subnet_verdicts_total{verdict}` | counter | вердикты детектора подсетей |
| `rampart_auto_bans_total{reason}` | counter | авто-баны userspace |
| `rampart_intel_cps` | gauge | новые соединения/с в окне |
| `rampart_intel_rate_limit_drops_total` | counter | дропы по репутации |
| `rampart_intel_alerts_total` | counter | алерты на переход состояния |
| `rampart_xdp_*` | gauge | счётчики `stats_map`: `total`, `tcp`, `udp`, `whitelist`, `blacklist`, `syn_throttle`, `rate_limit`, `passed`, `dropped`, `challenge_sent`, `challenge_verified`, `challenge_failed`, `fragment_bypass` |
| `rampart_xdp_autobans_total` | counter | авто-баны из ringbuf |
| `rampart_clickhouse_dropped_total` | counter | потерянные события ClickHouse |

TUI (`src/tui/`) читает те же метрики через Prometheus HTTP.

## 7. Конфигурация

Единый `config.toml` для edge; manager настраивается переменными окружения.
Все секции опциональны, значения по умолчанию — в `src/config/sections/`;
семантическая валидация выполняется до bind. Полная таблица полей, границ и
дефолтов — [configuration.md](configuration.md).

Ключевые инварианты:

- `proxy_protocol.ingress_enabled` требует непустой `trusted_cidrs` и
  `protocol.minecraft`.
- `xdp.syn_challenge_enabled` требует свой `challenge_secret_hex` (placeholder
  отклоняется).
- `backend.upstreams` не пуст и валиден; для Minecraft — ровно один upstream.
- `ban.ban_duration_secs` ∈ `1..=31_536_000`, `pow.difficulty` ∈ `1..=10`,
  `workers.count ≥ 1`.
- `limits.relay_idle_timeout_secs` ∈ `1..=86_400`.

## 8. Карта модулей

```
src/
├── app/         сборка рантайма, фоновые задачи, graceful shutdown
├── bin/         тонкие точки входа (логика в lib)
├── cli/         команды rampart-cli
├── config/      Config + sections/ + trusted CIDR
├── engine/      listener, tunnel/gateway|proxy, challenge, subnet
├── filter/      blacklist, rate_limit, connection_limit, geo
├── manager/     axum API, auth, sync/heartbeat
├── metrics.rs   Prometheus registry и scrape endpoint
├── protocol/    трейт ProtocolHandler, реестр, http, minecraft
├── store/       redis (+sync), clickhouse
├── traffic/     hook, prefix, intel (ewma/detector/reputation), profile
├── tui/         ratatui-дашборд
└── xdp/         загрузчик, globals, probe/diagnostics, noop
xdp/
├── core/        universal_filter.c + maps/stats/config/common/prefix/syn_challenge
└── hooks/       hook_api.h — контракт BPF-хуков
```

## 9. Ограничения и деградация

- XDP выключен или недоступен → защита работает в userspace; логируется честный
  режим (native/generic/none).
- Redis недоступен → edge автономен, manager отдаёт `503` на inventory/blacklist.
- ClickHouse недоступен → события теряются, защита работает; счётчик дропов растёт.
- Перегрузка → глобальный бюджет отклоняет соединения (`overloaded`), а не
  копит задачи в памяти.

---

*Версия: 1.0 | Ноябрь 2026*
