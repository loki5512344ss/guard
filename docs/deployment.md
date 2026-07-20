# Deployment - Rampart

> Как поднять Rampart с нуля. v0.1-v0.7.

---

## 1. Требования

### Минимальные (v0.1)
- 2 × VDS (KVM): Edge нода + Manager/Redis
- Ubuntu 22.04+, kernel 5.10+
- Rust toolchain (rustup)
- Docker + docker compose (для Manager)

### Полный стек (v0.4+)
- Edge: Debian 12 / Ubuntu 22.04, kernel 5.10+ (6.0+ для полного XDP)
- Manager: любая VDS с Docker
- Java 21 (для Velocity плагинов)
- WireGuard (между нодами)

## Схема деплоя

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Edge нода   │────→│  Load        │────→│  Velocity    │
│  25565/TCP   │     │  Balancer    │     │  кластер     │
│  XDP + Rust  │     │  HAProxy     │     │  x20 нод     │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                    ┌────────────────────────────┤
                    ▼                            ▼
           ┌──────────────┐            ┌──────────────┐
           │  Hub x100    │            │  Game        │
           │  (лобби)     │            │  серверы     │
           │              │            │  x300+       │
           └──────────────┘            └──────────────┘
                    │                         │
                    └──────────┬──────────────┘
                               ▼
                     ┌──────────────────┐
                     │  Manager нода     │
                     │  API :8080        │
                     │  Redis            │
                     │  WireGuard Hub    │
                     └──────────────────┘
```

Все соединения через WireGuard (10.0.0.0/16).
Game серверы НЕ имеют публичных IP - только WG.
Edge - единственная точка входа из интернета.

---

## 2. Быстрый старт - v0.1 (локально)

### Шаг 1: Edge нода

```bash
# На свежей Ubuntu 22.04 VDS

# Установка Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable

# Установка зависимостей
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# Клонирование и сборка
git clone https://github.com/yourname/rampart.git
cd rampart

# Сборка edge ноды
cargo build --release --bin rampart-core

# Создание конфига
mkdir -p /etc/rampart
cat > /etc/rampart/config.toml << 'EOF'
[bind]
address = "0.0.0.0"
port = 25565

[backend]
address = "127.0.0.1"
port = 25566

[hmac]
secret = "CHANGE_ME_32_BYTES_LONG_HERE"

[workers]
count = 4

[limits]
handshake_timeout_secs = 5
max_connections_per_ip = 10
EOF

# systemd unit
cat > /etc/systemd/system/rampart-edge.service << 'EOF'
[Unit]
Description=Rampart Edge Node
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rampart-core --config /etc/rampart/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65535
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now rampart-edge

# Проверка
journalctl -u rampart-edge -f
```

### Шаг 2: Manager (docker compose)

```bash
# На отдельной VDS или той же

# Установка Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Клонирование
git clone https://github.com/yourname/rampart.git
cd rampart

# Запуск инфраструктуры
docker compose up -d

# Проверка
docker compose ps
curl http://localhost:9090/api/health
```

### Шаг 3: Velocity плагин

```bash
# На Velocity ноде
# Сборка плагина
cd plugins/velocity
mvn clean package
# Полученный JAR: target/rampart-velocity-*.jar

# Копируем в папку плагинов Velocity
cp target/rampart-velocity-*.jar /opt/velocity/plugins/

# Настройка
cat >> /opt/velocity/velocity.toml << 'EOF'

[rampart]
# Включаем HMAC проверку
hmac_secret = "CHANGE_ME_32_BYTES_LONG_HERE"
# Домены разрешённые для подключения
allowed_domains = ["play.example.com", "mc.example.com"]
# Redis (опционально, для v0.2+)
redis_url = "redis://:password@10.0.0.1:6379/0"
EOF

# Рестарт Velocity
systemctl restart velocity
```

### Шаг 4: Проверка

```bash
# Статус edge ноды
rampart status

# Диагностика
rampart doctor

# Проверка что порт слушается
ss -tlnp | grep 25565

# Тест подключения Minecraft клиента
# Открой MC → Multiplayer → play.example.com:25565
```

---

## 3. WireGuard сеть

### Hub-and-Spoke на Manager

```bash
# На Manager ноде (WireGuard Hub)
# Установка
sudo apt-get install -y wireguard

# Генерация ключей
wg genkey | tee /etc/wireguard/manager.key | wg pubkey > /etc/wireguard/manager.pub

# Конфиг Hub
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
Address = 10.0.0.1/16
PrivateKey = <MANAGER_PRIVATE_KEY>
ListenPort = 51820

# Edge нода будет добавлена позже
EOF

systemctl enable --now wg-quick@wg0
```

### Добавление spoke ноды (через CLI)

```bash
# На Manager: генерируем конфиг для edge ноды
rampart wg add-node --role edge --name edge-eu-1 --public-ip 45.200.10.1

# Полученный конфиг:
# /etc/rampart/wg-configs/edge-eu-1/wg0.conf

# Копируем на edge ноду
scp /etc/rampart/wg-configs/edge-eu-1/wg0.conf root@45.200.10.1:/etc/wireguard/

# На edge ноде: запускаем
ssh root@45.200.10.1 'systemctl enable --now wg-quick@wg0'

# Проверка
ping 10.0.0.1  # Manager должен ответить
```

---

## 4. Полный production deploy (v0.4+)

### Edge нода с XDP

```bash
# Проверка совместимости
systemd-detect-virt  # должно быть kvm или none
ethtool -i eth0      # драйвер: i40e, mlx5, virtio

# Установка XDP зависимостей
sudo apt-get install -y libbpf-dev clang llvm linux-headers-$(uname -r)

# Сборка с XDP
cargo build --release --features xdp

# Настройка sysctl для DDoS защиты
cat > /etc/sysctl.d/99-rampart.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.icmp_echo_ignore_all = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
EOF
sysctl -p /etc/sysctl.d/99-rampart.conf
```

### Monitoring стек

```yaml
# /opt/rampart/docker-compose.monitoring.yml
# Дополнение к основному compose
services:
  victoria-metrics:
    image: victoriametrics/victoria-metrics:latest
    ports:
      - "8428:8428"  # remote_write endpoint
    command:
      - '--storageDataPath=/storage'
      - '--retentionPeriod=3'
    volumes:
      - vm-data:/storage

  parca:
    image: ghcr.io/parca-dev/parca:latest
    ports:
      - "7070:7070"
```

---

## 5. CI/CD pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    tags:
      - 'v*'

jobs:
  build-edge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release --features xdp
      - uses: actions/upload-artifact@v4
        with:
          name: rampart-edge
          path: target/release/rampart-core

  deploy-edge:
    needs: build-edge
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: |
          scp rampart-core root@${EDGE_HOST}:/usr/local/bin/
          ssh root@${EDGE_HOST} 'systemctl restart rampart-edge'
```

---

## 6. Firewall (резюме)

```bash
# Быстрая настройка для edge ноды
sudo ./scripts/firewall.sh

# Проверка
sudo iptables -L -n -v
```

Полные правила в [networking.md](research/networking.md).

---

## 7. Checklist после деплоя

```
☐ Edge нода запущена: systemctl status rampart-edge
☐ Порты слушаются: ss -tlnp | grep 25565
☐ WireGuard работает: wg show
☐ Manager API отвечает: curl http://localhost:9090/api/health
☐ Redis доступен: redis-cli ping
☐ ClickHouse пишет: curl http://localhost:8123/ping
☐ Velocity плагин загружен: /plugins/rampart-velocity-*.jar
☐ Реальный MC клиент заходит
☐ Prometheus метрики: curl http://localhost:9090/metrics
```

---

## 8. Troubleshooting

| Симптом | Причина | Решение |
|---------|---------|---------|
| Edge не стартует | Порт занят | `ss -tlnp \| grep 25565`, смени порт |
| Velocity не подключается | Не совпадает HMAC secret | Проверь `config.toml` и `velocity.toml` |
| XDP не загружается | OpenVZ / old kernel | `systemd-detect-virt`, проверь `uname -r` |
| Redis connection refused | Не настроен firewall | `iptables -A INPUT -p tcp --dport 6379 -s 10.0.0.0/16 -j ACCEPT` |
| ClickHouse не пишет | Нет таблицы | Выполни CREATE TABLE из `observability.md` |

---

*Версия: 1.0 | Июль 2026*
