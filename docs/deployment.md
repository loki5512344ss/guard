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
git clone https://github.com/loki5512344/rampart.git && cd rampart
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
export JWT_SECRET="$(openssl rand -hex 32)"   # минимум 32 байта
export API_PASSWORD="не-changeme"             # дефолт запрещён
cargo run --release --bin rampart-manager
# API на 0.0.0.0:8080
```

Инфраструктура (Redis, ClickHouse, Grafana):

```bash
docker compose up -d redis clickhouse grafana
```

## 5. Docker

```bash
# Образ edge
docker build -f deploy/docker/Dockerfile.edge -t rampart-edge .

# Полный стек edge + инфраструктура
docker compose -f deploy/docker-compose.yml up -d
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
