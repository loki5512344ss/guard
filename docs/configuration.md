# Configuration — Rampart

> Единый конфиг edge-ноды (`config.toml`) и переменные окружения Manager.
> Источник правды: `src/config/mod.rs` и `src/config/sections/`. Меняешь поле —
> правь эту таблицу в том же PR.

---

## 1. Edge (`config.toml`)

Путь по умолчанию — `/etc/rampart/config.toml`, переопределяется переменной
`RAMPART_CONFIG`. Все секции опциональны; при отсутствии используются дефолты из
таблиц ниже. Валидация выполняется до bind сокета: неверное значение — отказ
старта с внятной ошибкой.

### 1.1 Корень и входящий трафик

```toml
# Корневые поля должны стоять до первой TOML-секции.
whitelist = ["127.0.0.1", "::1"]

[bind]
address = "0.0.0.0"
port = 25565

[backend]
upstreams = ["127.0.0.1:25566"]

[workers]
count = 4

[limits]
handshake_timeout_secs = 5
max_connections_per_ip = 10
rate_limit_pps = 5.0
rate_limit_burst = 10.0
relay_idle_timeout_secs = 300

[ban]
ban_duration_secs = 3600
```

| Поле | По умолчанию | Ограничения и смысл |
|------|--------------|---------------------|
| `whitelist` | `[]` | Только IP-адреса (без CIDR). Обходят все фильтры, throttle и баны; адрес из whitelist никогда не банится |
| `bind.address` | `0.0.0.0` | Адрес прослушивания (IPv4 или IPv6) |
| `bind.port` | `25565` | Защищаемый TCP-порт |
| `backend.upstreams` | `["127.0.0.1:25566"]` | `addr:port`; список не пуст, каждый адрес валиден; Minecraft требует ровно один |
| `workers.count` | `4` | Accept-loop'ы с `SO_REUSEPORT`; ≥ 1 |
| `limits.handshake_timeout_secs` | `5` | Таймаут handshake/connect (slowloris-защита) |
| `limits.max_connections_per_ip` | `10` | Одновременные соединения с одного IP; > 0 |
| `limits.rate_limit_pps` | `5.0` | Новые соединения/с с одного IP; конечно и > 0 |
| `limits.rate_limit_burst` | `10.0` | Burst token bucket; ≥ 1 |
| `limits.relay_idle_timeout_secs` | `300` | Простой relay до разрыва; `1..=86400` |
| `ban.ban_duration_secs` | `3600` | Длительность бана; `1..=31_536_000` (год) |

### 1.2 PROXY protocol и PoW

```toml
[proxy_protocol]
ingress_enabled = false
trusted_cidrs = []
ingress_timeout_ms = 750
max_header_bytes = 512

[pow]
enabled = false
difficulty = 4
```

| Поле | По умолчанию | Ограничения и смысл |
|------|--------------|---------------------|
| `proxy_protocol.ingress_enabled` | `false` | Принимать PROXY v2 от внешнего TCP-прокси; требует непустой `trusted_cidrs` и `protocol.minecraft.enabled` |
| `proxy_protocol.trusted_cidrs` | `[]` | Точные адреса/CIDR самих прокси, не «весь DC» |
| `proxy_protocol.ingress_timeout_ms` | `750` | `1..=5000` |
| `proxy_protocol.max_header_bytes` | `512` | `52..=4096` |
| `pow.enabled` | `false` | Hashcash-challenge поверх любого TCP; несовместим с `protocol.minecraft.enabled` |
| `pow.difficulty` | `4` | Стартовая и минимальная сложность; `1..=10`, растёт под нагрузкой |

`trusted_cidrs` — это адреса самих прокси, а не клиентов: IP из заголовка
используется для per-IP лимитов, репутации и банов, поэтому любой хост внутри
`trusted_cidrs` может назвать себя кем угодно. Заголовок с адресом из
`trusted_cidrs`, а также unspecified/loopback/link-local/multicast/broadcast
отклоняется: клиентом считается transport peer (событие пишется в debug один раз
на соединение). Адреса из `trusted_cidrs` не банятся локально, в Redis и XDP.

### 1.3 XDP

```toml
[xdp]
enabled = false
interface = "eth0"
protected_port_start = 1
protected_port_end = 65535
udp_policy = "pass"
udp_rate_hit_count = 100
udp_rate_window_ms = 1000
throttle_enabled = true
syn_ban_duration_secs = 60
events_enabled = true
auto_ban_enabled = false
auto_ban_duration_secs = 60
auto_ban_conn_drop_fails = 3
syn_challenge_enabled = false
challenge_secret_hex = ""        # обязателен при syn_challenge_enabled
challenge_timeout_ms = 3000
```

| Поле | По умолчанию | Что делает |
|------|--------------|------------|
| `enabled` | `false` | Загрузить и приаттачить программу; требует сборки `--features xdp` |
| `interface` | `eth0` | Интерфейс; сначала native XDP, при отказе драйвера — generic (skb) |
| `protected_port_start` / `_end` | `1` / `65535` | Порт-гейт: трафик вне диапазона не фильтруется |
| `udp_policy` | `pass` | `pass`, `drop` или `rate-limit` (окно по source-IP) |
| `udp_rate_hit_count` / `udp_rate_window_ms` | `100` / `1000` | Порог и окно для `rate-limit` |
| `throttle_enabled` | `true` | SYN-throttle и авто-бан по `connection_throttle` (IPv4) |
| `syn_ban_duration_secs` | `60` | Бан в ядре при срабатывании SYN-throttle, `1..=86400`; не путать с `auto_ban_duration_secs` (userspace) |
| `events_enabled` | `true` | Ringbuf-события в userspace (IPv4) |
| `auto_ban_enabled` | `false` | OPT-IN: баны по событиям ringbuf |
| `auto_ban_duration_secs` | `60` | Длительность авто-бана |
| `auto_ban_conn_drop_fails` | `3` | Порог `conn->fails` для бана по `EVENT_CONN_DROP` |
| `syn_challenge_enabled` | `false` | RST-challenge (Oubliette-style liveness proof), IPv4 и IPv6 |
| `challenge_secret_hex` | — | 64-битный секрет, 16 hex-символов (`openssl rand -hex 8`); placeholder запрещён |
| `challenge_timeout_ms` | `3000` | TTL pending-challenge |

Поведение фильтра:

- **Stateless-фильтр, не firewall.** Conntrack ведётся только для TCP-соединений,
  начатых с SYN; пакет без состояния (non-SYN) пропускается, чтобы фильтр не рвал
  ответы на исходящие соединения демона и keep-alive health-check'ов.
- **VLAN/QinQ** (802.1Q и 802.1ad, до двух тегов) разбираются; **фрагменты**
  проверяются по source-IP в blacklist и пропускаются, счётчик — `fragment_bypass`.
- **Whitelist** загружается в `whitelist_map`/`whitelist6_map` при attach и
  обходит state machine, throttle и баны.
- **CIDR-баны** матчатся LPM-трией; userspace — диапазонами, поэтому `/24` и `/64`
  покрывают всю подсеть.
- **Оценка числа источников** в префиксе: XDP ведёт 64-битный bitmap хешей
  source-адресов, userspace считает popcount (spoof-gate работает и на XDP-пути).
  Счётчики префиксов сбрасываются при чтении, окно = интервал опроса монитора.

Покрытие семейств:

- **IPv4**: blacklist, SYN-throttle, conntrack, RST-challenge, ringbuf-события,
  `udp_policy` (включая `rate-limit`), prefix-статистика.
- **IPv6**: blacklist, whitelist, `udp_policy` (включая `rate-limit` с 128-битным
  ключом), детект TCP-bypass, RST-challenge (128-битные ключи), prefix-статистика.
  Пока нет: conntrack, SYN-throttle, ringbuf-события и unban — для v6 только счётчики.

Какую проверку источника включать:

| Протокол | PoW (`[pow]`) | RST-challenge (`[xdp] syn_challenge_enabled`) |
|----------|---------------|-----------------------------------------------|
| HTTP | да | да; можно вместе с PoW |
| Minecraft Java | нет — конфиг отклоняется | да, единственный вариант |
| Любой другой TCP | нет (клиент не ответит на текстовый challenge) | да |

RST-challenge не трогает payload: живой TCP-стек проходит его сам, приложение видит лишь
задержку ~10–20 мс на первом connect с адреса (verified держится 5 минут скользящим окном).
SYN с IPv4-опциями или за IPv6 extension-заголовками при включённом challenge дропается:
ответ собирается как голый заголовок.

### 1.4 Детекция и алерты

```toml
[detect.prefix]
enabled = false
syn_threshold = 500
window_secs = 10
min_unique_sources = 16

[detect.autoban]
enabled = false
reputation_threshold = -50

[detect.alert]
webhook_url = ""
```

| Поле | По умолчанию | Смысл |
|------|--------------|-------|
| `detect.prefix.enabled` | `false` | Детектор атак на уровне подсети (`/24`, `/64`) |
| `detect.prefix.syn_threshold` | `500` | Порог соединений на префикс в окне; при `enabled` обязан быть > 0 |
| `detect.prefix.window_secs` | `10` | Окно детектора |
| `detect.prefix.min_unique_sources` | `16` | Минимум уникальных источников (spoof-gate) |
| `detect.autoban.enabled` | `false` | Авто-бан по score репутации |
| `detect.autoban.reputation_threshold` | `-50` | Порог score; TTL — `ban.ban_duration_secs` |
| `detect.alert.webhook_url` | — | Webhook на переход состояния атаки |

### 1.5 Протоколы, логи, метрики, хранилища

```toml
[protocol.http]
max_header_bytes = 8192
timeout_secs = 5
blocked_paths = ["/wp-login.php"]
require_user_agent = false

[protocol.minecraft]
enabled = true
max_frame_bytes = 8192
timeout_secs = 5
send_proxy_protocol = false
max_handshake_bytes = 2048
max_login_start_bytes = 5120
max_status_request_bytes = 64
# min_protocol_version = 47
# max_protocol_version = 772
deny_protocol_versions = []
username_max_len = 16
username_charset = "standard"

[logging]
level = "info"
format = "text"

[metrics]
enabled = true
port = 9090

[store]
redis_url = ""
blacklist_cache_ttl_secs = 300
clickhouse_url = ""
```

| Поле | По умолчанию | Смысл |
|------|--------------|-------|
| `protocol.http.max_header_bytes` | `8192` | Лимит request-head; > 0 |
| `protocol.http.timeout_secs` | `5` | Таймаут чтения заголовков; > 0 |
| `protocol.http.blocked_paths` | `[]` | Точные пути, которые отклоняются |
| `protocol.http.require_user_agent` | `false` | Отклонять запросы без `User-Agent` |
| `protocol.minecraft.enabled` | `true` при сборке без `protocol-http` | Активный MC-handler |
| `protocol.minecraft.max_frame_bytes` | `8192` | Лимит кадра; > 0 |
| `protocol.minecraft.timeout_secs` | `5` | Таймаут handshake; > 0 |
| `protocol.minecraft.send_proxy_protocol` | `false` | Отправлять PROXY v2 на Paper; alias — `proxy_protocol` |
| `protocol.minecraft.max_handshake_bytes` | `2048` | Лимит кадра handshake (длина проверяется до буферизации); `16..=8192`, дополнительно ограничен `max_frame_bytes` |
| `protocol.minecraft.max_login_start_bytes` | `5120` | Лимит кадра login-start; `16..=8192` |
| `protocol.minecraft.max_status_request_bytes` | `64` | Лимит кадра status request; `1..=1024` |
| `protocol.minecraft.min_protocol_version` | не задан | Нижняя граница protocol id; `>= 0`, не больше `max_protocol_version` |
| `protocol.minecraft.max_protocol_version` | не задан | Верхняя граница protocol id; `>= 0` |
| `protocol.minecraft.deny_protocol_versions` | `[]` | Запрещённые protocol id (например `340`); `>= 0` |
| `protocol.minecraft.username_max_len` | `16` | Максимум символов в нике; `1..=64` |
| `protocol.minecraft.username_charset` | `"standard"` | `standard` (`A-Za-z0-9_.-`), `ascii` (печатный ASCII без пробела) или `any` (UTF-8 без управляющих символов) |
| `logging.level` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `logging.format` | `text` | `text` или `json` |
| `metrics.enabled` | `true` | Prometheus endpoint |
| `metrics.port` | `9090` | Порт метрик |
| `store.redis_url` | — | Пусто = синхронизация банов выключена |
| `store.blacklist_cache_ttl_secs` | `300` | TTL локального кеша blacklist |
| `store.clickhouse_url` | — | Пусто = запись событий выключена |

`[protocol.http]` существует только при сборке с `protocol-http`,
`[protocol.minecraft]` — только с `protocol-minecraft`; секция без
соответствующей фичи игнорируется. Для HTTP удали `[protocol.minecraft]`.

## 2. Manager (переменные окружения)

| Переменная | Обязательна | По умолчанию | Описание |
|------------|-------------|--------------|----------|
| `REDIS_URL` | нет | `redis://127.0.0.1:6379/0` | Хранилище состояния |
| `JWT_SECRET` | да | — | Минимум 32 непробельных байта |
| `JWT_AUDIENCE` | нет | `rampart` | Audience JWT |
| `JWT_EXPIRATION_SECS` | нет | `86400` | Время жизни токена |
| `API_PASSWORD` | да | — | Пароль для `/api/v1/auth/login`, минимум 16 символов; `changeme` запрещён |
| `CORS_ORIGIN` | нет | — | `*` — разрешить всё; список origin'ов через запятую; пусто — cross-origin запрещён |
| `MANAGER_TRUSTED_PROXIES` | нет | — | Сети reverse-прокси через запятую. `X-Forwarded-For` учитывается только для запросов из этих сетей; опечатка/пустая запись → отказ старта |

Manager всегда слушает `0.0.0.0:8080`.

## 3. Feature flags сборки

| Feature | По умолчанию | Что включает |
|---------|--------------|--------------|
| `store-redis` | ✅ | Redis-клиент и синхронизация blacklist |
| `geoip` | ❌ | GeoIP lookup (maxminddb; реализация — roadmap v0.5) |
| `xdp` | ❌ | Загрузка XDP-программы через libbpf-rs |
| `io-uring` | ❌ | splice/io_uring I/O (реализация — roadmap v0.6) |
| `protocol-http` | ❌ | HTTP/1.1 handler |
| `protocol-minecraft` | ❌ | Minecraft Java handshake и проксирование |

```bash
cargo build --release --features xdp,protocol-http --bin rampart
```

## 4. BPF/XDP программа

Исходник — `xdp/core/universal_filter.c`. Smoke-check компиляции:

```bash
mkdir -p target/xdp
clang -O2 -g -target bpf -I"/usr/include/$(gcc -print-multiarch)" \
  -c xdp/core/universal_filter.c -o target/xdp/universal_filter.o
```

`-I` с multiarch нужен, потому что `-target bpf` не ищет
`/usr/include/<triple>` по умолчанию. Полный прогон на реальном ядре —
`scripts/xdp_ci.sh` (см. [testing.md](testing.md)).

---

*Версия: 3.0 | Ноябрь 2026*
