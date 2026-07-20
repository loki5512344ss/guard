# Configuration - Rampart

> Примеры конфигурационных файлов для всех компонентов.

## Как конфиги связывают компоненты

```
Edge config.toml               Manager (env)
  bind.address                    JWT_SECRET
  bind.port                       API_PASSWORD
  backend.address          ───→   REDIS_URL
  hmac.secret ←──────┐            CLICKHOUSE_URL
  store.redis_url ────┤
                     │
Velocity (env)       │     Paper (env)
  RAMPART_HMAC_SECRET┤       RAMPART_HMAC_SECRET
  RAMPART_ALLOWED_   │       RAMPART_REDIS_URL
  DOMAINS            │       RAMPART_SERVER_NAME
  RAMPART_REDIS_URL ─┘       RAMPART_SERVER_IP
```

HMAC secret должен быть ОДИНАКОВЫМ на Edge, Velocity и Paper.
Redis URL - одинаковым на всех компонентах.

---

## 1. Edge Node (`config.toml`)

```toml
[bind]
address = "0.0.0.0"
port = 25565

[backend]
# Velocity нода или HAProxy
address = "10.0.0.2"
port = 25565

[hmac]
# Минимум 32 байта. Сгенерировать: openssl rand -hex 32
secret = "CHANGE_ME_32_BYTES_LONG_HERE_ABCDEF123456"

[workers]
# Количество воркеров = количество vCPU
count = 4

[xdp]
# Опционально, требует kernel 5.10+
enabled = false
interface = "eth0"

[limits]
# Максимум времени на получение handshake (Slowloris защита)
handshake_timeout_secs = 5
# Максимум одновременных соединений с одного IP
max_connections_per_ip = 10
# Лимит коннектов в секунду с одного IP (Status ping)
rate_limit_status_pps = 2
# Лимит коннектов в секунду с одного IP (Login)
rate_limit_login_pps = 5
# Лимит burst
rate_limit_burst = 10

[store]
# v0.2+: Redis для синхронизации блэклиста
redis_url = "redis://:password@10.0.0.1:6379/0"
# TTL кэша блэклиста (локально)
blacklist_cache_ttl_secs = 300

[logging]
level = "info"        # trace, debug, info, warn, error
format = "json"       # json или text

[metrics]
enabled = true
port = 9090

[quic]
# v0.4+: QUIC канал к Manager (опционально)
enabled = false
connect = "10.0.0.1:7777"
```

---

## 2. Velocity Plugin

Плагин конфигурируется через переменные окружения (совпадают с edge node).

```bash
# Обязательно: HMAC секрет (должен совпадать с edge нодой)
RAMPART_HMAC_SECRET="CHANGE_ME_32_BYTES_LONG_HERE_ABCDEF123456"

# Опционально: список разрешённых доменов (через запятую)
RAMPART_ALLOWED_DOMAINS="play.example.com,mc.example.com,example.com"
```

Установка:
```
# Сборка
cd plugins && ./gradlew :velocity:build

# Копирование в Velocity
cp velocity/build/libs/rampart-velocity-*.jar /opt/velocity/plugins/

# Рестарт
systemctl restart velocity
```

Плагин делает:
- **DomainCheck**: блокирует direct IP-коннекты, пропускает только домены из whitelist
- **HmacCheck**: верифицирует HMAC-SHA256 подпись в hostname (`\0shield\0<sig>`)

---

## 3. Paper Plugin

Конфигурация - через переменные окружения:

```bash
# Обязательно: HMAC секрет (должен совпадать с edge нодой)
RAMPART_HMAC_SECRET="CHANGE_ME_32_BYTES_LONG_HERE_ABCDEF123456"
```

Установка:
```
cd plugins && ./gradlew :paper:build
cp paper/build/libs/rampart-paper-*.jar /opt/paper/plugins/
```

Плагин делает:
- **HmacCheck**: резервная верификация HMAC-подписи на случай прямого коннекта (в обход Velocity)

---

## 4. Manager (`manager.toml`)

```toml
[bind]
address = "0.0.0.0"
port = 8080

[tls]
cert = "/etc/rampart/tls/manager.crt"
key = "/etc/rampart/tls/manager.key"
ca = "/etc/rampart/tls/ca.crt"

[auth]
jwt_secret = "CHANGE_ME_JWT_SECRET_HERE"
jwt_expiry_hours = 24

[redis]
url = "redis://:password@127.0.0.1:6379/0"
pool_size = 10

[nats]
# v0.4+: NATS для критических событий
urls = ["nats://127.0.0.1:4222"]

[clickhouse]
url = "http://127.0.0.1:8123"
db = "rampart"
batch_size = 1000
flush_interval_secs = 1

[quic]
# v0.4+: QUIC сервер для edge нод
bind = "0.0.0.0:7777"

[limits]
api_rate_per_minute = 60
```

---

## 5. HAProxy (`haproxy.cfg`)

```haproxy
global
    maxconn 100000
    log /dev/log local0

defaults
    mode tcp
    timeout connect 3s
    timeout client  30s
    timeout server  30s
    option tcplog

frontend minecraft_in
    bind *:25565
    mode tcp

    # Только от edge нод
    acl is_edge src 10.0.100.0/24
    tcp-request connection reject if !is_edge

    default_backend velocity_pool

backend velocity_pool
    mode tcp
    balance leastconn
    option tcp-check

    server vel1 10.0.0.2:25565 check inter 3s rise 2 fall 3
    server vel2 10.0.0.3:25565 check inter 3s rise 2 fall 3
    server vel3 10.0.0.4:25565 check inter 3s rise 2 fall 3
```

---

## 6. Prometheus (`prometheus.yml`)

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'rampart-edge'
    static_configs:
      - targets:
        - '10.0.100.1:9090'
        - '10.0.100.2:9090'

  - job_name: 'rampart-manager'
    static_configs:
      - targets: ['10.0.0.1:9090']

  - job_name: 'rampart-velocity'
    static_configs:
      - targets:
        - '10.0.0.2:9091'
        - '10.0.0.3:9091'

  - job_name: 'paper-servers'
    file_sd_configs:
      - files: ['/etc/prometheus/game_servers.json']
        refresh_interval: 30s
```

---

## 7. WireGuard (`wg0.conf`)

```ini
[Interface]
Address = 10.0.0.1/16
PrivateKey = <MANAGER_PRIVATE_KEY>
ListenPort = 51820
MTU = 1420

[Peer]
# Edge EU
PublicKey = <EDGE_EU_PUBLIC_KEY>
AllowedIPs = 10.0.100.1/32

[Peer]
# Edge US
PublicKey = <EDGE_US_PUBLIC_KEY>
AllowedIPs = 10.0.100.2/32

[Peer]
# Velocity 1
PublicKey = <VEL1_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

---

*Версия: 1.0 | Июль 2026*
