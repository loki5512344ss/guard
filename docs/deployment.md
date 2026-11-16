# Deployment - Rampart

> Как поднять Rampart с нуля.

---

## 1. Компоненты

| Бинарь | Роль | Порт по умолчанию |
|--------|------|-------------------|
| `rampart` | Edge-нода: XDP + PoW + userspace-фильтр | 25565 (+ metrics 9090) |
| `rampart-manager` | REST API управления | 8080 |
| `rampart-cli` | Управление через Manager API | — |

## 2. Требования

### Edge
- Ubuntu 22.04+ / Debian 12, kernel 5.10+
- KVM или bare metal (OpenVZ/LXC — XDP не работает)
- Rust toolchain для сборки

Для XDP дополнительно: `libelf-dev libbpf-dev clang linux-libc-dev`.

### Manager
- Любая VDS с Docker (Redis обязателен)

## 3. Быстрый старт — Edge

```bash
# Сборка edge для Minecraft Java
git clone https://github.com/loki5512344ss/guard.git && cd guard
cargo build --release --features protocol-minecraft --bin rampart

# Установка
sudo cp target/release/rampart /usr/local/bin/

# Конфиг
sudo mkdir -p /etc/rampart
sudo cp deploy/config/edge.toml /etc/rampart/config.toml
# Отредактируй backend.upstreams под свои бэкенды

# systemd unit
cat > /etc/systemd/system/rampart.service << 'EOF'
[Unit]
Description=Rampart Edge Node
After=network.target

[Service]
Type=simple
Environment=RAMPART_CONFIG=/etc/rampart/config.toml
ExecStart=/usr/local/bin/rampart
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now rampart

# Проверка
journalctl -u rampart -f
```

Minecraft-конфиг рассчитан на один Paper backend. Если включён
`protocol.minecraft.send_proxy_protocol`, включи `proxies.proxy-protocol: true` в
Paper и закрой backend-порт firewall-ом от всех, кроме Rampart. Для подробной
схемы с домашним сервером и защищённым VDS см. [Minecraft Java guide](minecraft-java.md).

## 4. Быстрый старт — Manager

```bash
export REDIS_URL="redis://127.0.0.1:6379/0"
export JWT_SECRET="$(openssl rand -hex 32)"   # минимум 32 байта без пробелов
export API_PASSWORD="$(openssl rand -base64 24)"  # минимум 16 символов, дефолт запрещён
cargo run --release --bin rampart-manager
# API на 0.0.0.0:8080
```

Manager refuses to start with an empty `API_PASSWORD`, a password shorter than
16 characters, the default placeholder (which must not be `changeme`), or a
`JWT_SECRET` with fewer than 32 non-whitespace bytes.

Manager listens on all interfaces by default. Permit `8080` only from an admin
VPN or specific admin addresses; do not expose the API to the public Internet.
The same applies to Redis (`6379`) and monitoring endpoints such as Prometheus
(`9090`), ClickHouse (`8123`/`9000`) and Grafana (`3000`). The sample Compose
files bind published ClickHouse and Grafana ports to `127.0.0.1` only, so reach
them through an SSH tunnel or a local admin session, never through the public
interface. `deploy/docker-compose.yml` publishes no Redis port at all and the
root `docker-compose.yml` binds it to loopback; both refuse to start unless
`REDIS_PASSWORD` and `GRAFANA_PASSWORD` are set. Cross-origin access to the
manager API is disabled unless `CORS_ORIGIN` is set explicitly (`*` or a
comma-separated origin list).

Инфраструктура (Redis, ClickHouse, Grafana) требует пароли из окружения —
Compose не стартует без них:

```bash
export REDIS_PASSWORD="$(openssl rand -base64 24)"
export GRAFANA_PASSWORD="$(openssl rand -base64 24)"
docker compose up -d redis clickhouse grafana
```

Для нескольких edge и Manager укажи один и тот же защищённый Redis endpoint в
`store.redis_url` каждого edge и `REDIS_URL` Manager. Edge передаёт туда
локальные автобаны и восстанавливает общие bans после переподключения. Открой
Redis только через private network/VPN; при пустом `redis_url` edge остаётся
автономным, и автобаны между узлами не распространяются.

## 5. Docker

```bash
# Пароли обязательны: без REDIS_PASSWORD/GRAFANA_PASSWORD Compose падает
export REDIS_PASSWORD="$(openssl rand -base64 24)"
export GRAFANA_PASSWORD="$(openssl rand -base64 24)"

# Образ edge
docker build -f deploy/docker/Dockerfile.edge -t rampart-edge .

# Полный стек edge + инфраструктура
docker compose -f deploy/docker-compose.yml up -d
```

Edge подключается к Redis по имени сервиса. Поскольку Redis в Compose требует
пароль, впиши его в URL конфига edge (`deploy/config/edge-docker.toml`) — тот
же пароль, что в `REDIS_PASSWORD`:

```toml
[store]
redis_url = "redis://:PASSWORD@redis:6379/0"
```

## 6. Проверка после деплоя

```bash
☐ systemctl status rampart
☐ ss -tlnp | grep 25565
☐ curl http://localhost:9090/metrics | grep rampart_
☐ rampart-cli status        # через Manager API
☐ rampart-cli doctor        # диагностика
```

---

*Версия: 2.1 | Октябрь 2026*
