# Configuration - Rampart

> Единый конфиг edge-ноды (`config.toml`) и переменные окружения Manager.
> Схема конфига: `src/config/sections.rs` — единственный источник правды.

## 1. Edge (`config.toml`, путь задаётся `RAMPART_CONFIG`)

```toml
# Корневые поля должны стоять до первой TOML-секции.
whitelist = ["127.0.0.1", "::1"]

[bind]
address = "0.0.0.0"
port = 25565

[backend]
# Список TCP-бэкендов (addr:port). Для Minecraft нужен ровно один backend.
upstreams = ["127.0.0.1:25566"]

[protocol.minecraft]
enabled = true
max_frame_bytes = 8192
timeout_secs = 5
send_proxy_protocol = false

[workers]
count = 4

[limits]
handshake_timeout_secs = 5      # таймаут чтения (slowloris-защита)
max_connections_per_ip = 10     # одновременные соединения с одного IP
rate_limit_pps = 5.0            # лимит коннектов/сек с одного IP
rate_limit_burst = 10.0         # burst

[ban]
ban_duration_secs = 3600

[store]
redis_url = ""                  # пусто = синхронизация блэклиста выключена
blacklist_cache_ttl_secs = 300
clickhouse_url = ""             # пусто = запись событий выключена

[xdp]
enabled = false                 # требует сборки --features xdp, kernel 5.10+
interface = "eth0"
protected_port_start = 1        # пакеты вне диапазона уходят в XDP_PASS до фильтра
protected_port_end = 65535
udp_policy = "pass"             # pass | drop | rate-limit (для IPv4 и IPv6)
udp_rate_hit_count = 100        # порог пакетов в окне при rate-limit
udp_rate_window_ms = 1000       # окно rate-limit
throttle_enabled = true         # SYN-throttle (только IPv4)
events_enabled = true           # ringbuf-события в userspace (только IPv4)
auto_ban_enabled = false        # OPT-IN: баны по событиям ringbuf
auto_ban_duration_secs = 300
auto_ban_conn_drop_fails = 3
syn_challenge_enabled = false   # RST-challenge (только IPv4)
challenge_timeout_ms = 3000

[logging]
level = "info"                  # trace, debug, info, warn, error
format = "text"                 # text или json

[metrics]
enabled = true
port = 9090

[pow]
enabled = false                 # PoW challenge, OFF по умолчанию
difficulty = 4

# Входящий PROXY v2 от известного TCP DDoS-прокси; включай только если
# прокси действительно отправляет этот заголовок.
[proxy_protocol]
ingress_enabled = false
trusted_cidrs = []
ingress_timeout_ms = 750
max_header_bytes = 512

```

Этот пример выбирает Minecraft Java и требует сборки с `protocol-minecraft`.
Для HTTP используй сборку `protocol-http` и удали `[protocol.minecraft]`.

Все секции опциональны — при отсутствии используются дефолты из таблицы выше.
Для ingress PROXY v2 укажи сети именно прокси в `trusted_cidrs`; включение без
доверенной сети отклоняется при чтении конфига.
`send_proxy_protocol` отправляет заголовок на Paper backend; прежнее имя
`proxy_protocol` внутри `[protocol.minecraft]` остаётся допустимым alias.

## 2. Manager (переменные окружения)

| Переменная | Обязательна | По умолчанию | Описание |
|------------|-------------|--------------|----------|
| `REDIS_URL` | нет | `redis://127.0.0.1:6379/0` | Хранилище состояния |
| `JWT_SECRET` | да | — | Минимум 32 байта |
| `JWT_AUDIENCE` | нет | `rampart` | Audience JWT |
| `JWT_EXPIRATION_SECS` | нет | `86400` | Время жизни токена |
| `API_PASSWORD` | да | — | Пароль для `/api/v1/auth/login`; значение `changeme` запрещено |
| `CORS_ORIGIN` | нет | `http://localhost:5173` | CORS; `*` или пусто — разрешить все |

Manager всегда слушает `0.0.0.0:8080`.

## 3. Feature flags сборки (Cargo.toml)

| Feature | По умолчанию | Что включает |
|---------|--------------|--------------|
| `store-redis` | ✅ | Redis-клиент и синхронизация блэклиста |
| `geoip` | ❌ | GeoIP lookup (maxminddb) |
| `xdp` | ❌ | Загрузка XDP-программы через libbpf-rs |
| `io-uring` | ❌ | splice/io_uring I/O |
| `protocol-http` | ❌ | HTTP/1.1 handler; включай только для HTTP upstream |
| `protocol-minecraft` | ❌ | Minecraft Java TCP handshake и проксирование |

Пример: `cargo build --release --features xdp --bin rampart`.

## 4. BPF/XDP программа

Исходник: `xdp/core/universal_filter.c`. Smoke-check компиляции:

```bash
clang -O2 -g -target bpf -c xdp/core/universal_filter.c -o /tmp/universal_filter.o
```

Параметры `[xdp]` (значения по умолчанию — в `src/config/sections/platform.rs`):

| Поле | По умолчанию | Что делает |
|------|--------------|------------|
| `enabled` | `false` | Загрузить и приаттачить XDP-программу при старте |
| `interface` | `eth0` | Интерфейс; native XDP, при отказе драйвера — generic (skb) |
| `protected_port_start` / `_end` | `1` / `65535` | Порт-гейт: трафик вне диапазона не фильтруется |
| `udp_policy` | `pass` | `drop` — дропать весь UDP; `rate-limit` — окно на source-IP |
| `udp_rate_hit_count` / `udp_rate_window_ms` | `100` / `1000` | Порог и окно для `rate-limit` |
| `throttle_enabled` | `true` | SYN-throttle + авто-бан по `connection_throttle` |
| `events_enabled` | `true` | Ringbuf-события (rate-limit/conn-drop) в userspace |
| `auto_ban_enabled` | `false` | OPT-IN: баны по событиям ringbuf |
| `auto_ban_duration_secs` | `300` | Длительность авто-бана |
| `auto_ban_conn_drop_fails` | `3` | Порог `conn->fails` для бана по `EVENT_CONN_DROP` |
| `syn_challenge_enabled` | `false` | RST-challenge (Oubliette liveness proof) |
| `challenge_secret_hex` | плейсхолдер | 128-битный hex-секрет challenge |
| `challenge_timeout_ms` | `3000` | TTL pending-challenge |

Покрытие семейств адресов:

- **IPv4**: blacklist, SYN-throttle, conntrack, RST-challenge, ringbuf-события, `udp_policy`
  (включая `rate-limit`), prefix-статистика.
- **IPv6**: blacklist (`blacklist6_map`, LPM по `/128` и префиксам), `udp_policy`
  (включая `rate-limit` с 128-битным ключом), детект TCP-bypass, prefix-статистика.
  Пока нет: conntrack, SYN-throttle, RST-challenge, ringbuf-события и unban для v6 —
  для v6 события видны только в счётчиках `stats_map`.

---

*Версия: 2.1 | Октябрь 2026*
