# Configuration - Rampart

> Единый конфиг edge-ноды (`config.toml`) и переменные окружения Manager.
> Схема конфига: `src/config/sections.rs` — единственный источник правды.

## 1. Edge (`config.toml`, путь задаётся `RAMPART_CONFIG`)

```toml
[bind]
address = "0.0.0.0"
port = 25565

[backend]
# Список TCP-бэкендов (addr:port). Обязателен непустой, адреса валидируются.
upstreams = ["127.0.0.1:25566"]

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

[logging]
level = "info"                  # trace, debug, info, warn, error
format = "text"                 # text или json

[metrics]
enabled = true
port = 9090

[pow]
enabled = false                 # PoW challenge, OFF по умолчанию
difficulty = 4

whitelist = ["127.0.0.1", "::1"]   # только IP-адреса, валидируются при парсинге
```

Все секции опциональны — при отсутствии используются дефолты из таблицы выше.

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
| `protocol-http` | ❌ | Резерв под HTTP-плагин (пока пустой) |

Пример: `cargo build --release --features xdp --bin rampart`.

## 4. BPF/XDP программа

Исходник: `xdp/core/universal_filter.c`. Smoke-check компиляции:

```bash
clang -O2 -g -target bpf -c xdp/core/universal_filter.c -o /tmp/universal_filter.o
```

---

*Версия: 2.0 | Август 2026*
