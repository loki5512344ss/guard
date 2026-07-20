# Migration - Rampart

> Как обновляться между версиями без даунтайма.

---

## Общие принципы

1. **Читай CHANGELOG** перед обновлением
2. **Бэкап** перед любой миграцией: Redis RDB, конфиги, сертификаты
3. **Одна нода** сначала - тестируй на одной edge, потом на всех
4. **Откат** - всегда сохраняй предыдущую версию бинарника

---

## v0.1 → v0.2 (Redis + Registry)

### Изменения
- Edge нода начинает использовать Redis для синхронизации блэклиста
- Paper плагин пишет в Redis вместо локального YAML
- Velocity получает server registry из Redis

### Шаги

```bash
# 1. Поднять Redis (если ещё нет)
docker compose up -d redis

# 2. Настроить Redis пароль
echo "requirepass НОВЫЙ_ПАРОЛЬ" >> /etc/redis/redis.conf
systemctl restart redis

# 3. Обновить конфиг edge ноды
cat >> /etc/rampart/config.toml << 'EOF'
[store]
redis_url = "redis://:НОВЫЙ_ПАРОЛЬ@10.0.0.1:6379/0"
blacklist_cache_ttl_secs = 300
EOF

# 4. Обновить Paper плагин (перейти с file → redis)
sed -i 's/registration_mode: "file"/registration_mode: "redis"/' paper-global.yml
sed -i 's|# redis_url:|redis_url: "redis://:НОВЫЙ_ПАРОЛЬ@10.0.0.1:6379/0"|' paper-global.yml

# 5. Обновить Velocity плагин
# Добавить redis_url в velocity.toml

# 6. Рестарт по очереди (no downtime)
systemctl restart rampart-edge     # по одной edge ноде
systemctl restart velocity          # по одной velocity
# Paper плагины - reload через /reload команду
```

### Откат

```bash
# Если что-то пошло не так:
# 1. Вернуть registration_mode: "file" в paper-global.yml
# 2. Убрать redis_url из всех конфигов
# 3. Рестартнуть всё в обратном порядке
```

---

## v0.2 → v0.3 (Observability)

### Изменения
- Добавляются Prometheus метрики на всех компонентах
- ClickHouse для хранения attack log
- Grafana дашборды

### Шаги

```bash
# 1. Поднять стек мониторинга
docker compose up -d clickhouse prometheus grafana

# 2. Создать таблицы ClickHouse
clickhouse-client --query "
CREATE DATABASE IF NOT EXISTS rampart;

CREATE TABLE IF NOT EXISTS rampart.blocked (
  ts          DateTime CODEC(Delta, ZSTD),
  edge        LowCardinality(String),
  src_ip      IPv4,
  src_asn     UInt32,
  src_country LowCardinality(FixedString(2)),
  reason      LowCardinality(String),
  proto_ver   Int32,
  hostname    String CODEC(ZSTD)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, edge, src_ip)
TTL ts + INTERVAL 90 DAY;
"

# 3. Настроить scrape targets в prometheus.yml
# 4. Импортировать Grafana dashboard
# 5. Ничего рестартить не нужно - метрики уже встроены
```

### Проверка

```bash
curl -s http://EDGE_IP:9090/metrics | grep rampart
```

---

## v0.3 → v0.4 (XDP)

### Изменения
- XDP программа на C
- libbpf-rs для загрузки в ядро
- Feature flag: `xdp`

### Шаги

```bash
# 1. Проверить совместимость
systemd-detect-virt  # нужно kvm или none
uname -r              # нужно 5.10+
ethtool -i eth0      # драйвер

# 2. Установить зависимости
sudo apt-get install -y libbpf-dev clang llvm linux-headers-$(uname -r)

# 3. Собрать с XDP
cargo build --release --features xdp

# 4. Обновить бинарник
cp /usr/local/bin/rampart-core /usr/local/bin/rampart-core.backup
cp target/release/rampart-core /usr/local/bin/

# 5. Включить XDP в конфиге
cat >> /etc/rampart/config.toml << 'EOF'
[xdp]
enabled = true
interface = "eth0"
EOF

# 6. Рестарт
systemctl restart rampart-edge

# 7. Проверить
journalctl -u rampart-edge | grep XDP
ip link show | grep xdp
```

### Откат

```bash
# Отключить XDP
rampart config set xdp_enabled false
systemctl restart rampart-edge
# Вернуть старый бинарник
cp /usr/local/bin/rampart-core.backup /usr/local/bin/rampart-core
```

---

## v0.4 → v0.5 (Anti-Bot)

### Изменения
- GeoIP (MaxMind GeoLite2)
- Sonar 3.0 интеграция
- Challenge API

### Шаги

```bash
# 1. Зарегистрироваться на maxmind.com, скачать GeoLite2-ASN
# 2. Разместить базу на Manager
mkdir -p /var/lib/rampart/geoip
cp GeoLite2-ASN.mmdb /var/lib/rampart/geoip/

# 3. Обновить конфиг edge
cat >> /etc/rampart/config.toml << 'EOF'
[geoip]
db_path = "/var/lib/rampart/geoip/GeoLite2-ASN.mmdb"
# ASN с повышенным скорингом
vpn_asns = [16276, 24940, 20473]
datacenter_asns = [16509, 14618, 8075]
EOF

# 4. Обновить Velocity плагин (с поддержкой Sonar)
cp plugins/velocity/target/rampart-velocity-*.jar /opt/velocity/plugins/
systemctl restart velocity

# 5. Проверить
rampart geoip lookup 1.2.3.4
```

---

## v0.5 → v0.6 (Scale + HA)

### Изменения
- Rust LB вместо HAProxy
- mTLS между всеми компонентами
- QUIC канал Edge ↔ Manager
- NATS JetStream

### Шаги

```bash
# 1. Развернуть NATS
docker compose up -d nats

# 2. Обновить конфиг Manager
cat >> /etc/rampart/manager.toml << 'EOF'
[nats]
urls = ["nats://127.0.0.1:4222"]

[quic]
bind = "0.0.0.0:7777"
EOF

# 3. Сгенерировать PKI
rampart pki init --root-ca rampart-ca
rampart pki issue --ca edge-ca --name edge-eu-1 --ip 10.0.100.1
rampart pki issue --ca infra-ca --name manager --ip 10.0.0.1

# 4. Развернуть сертификаты на все ноды
# 5. Включить mTLS в конфигах
# 6. Постепенно перевести трафик с HAProxy на Rust LB
```

### Миграция с HAProxy

```bash
# Фаза 1: Запустить Rust LB рядом с HAProxy
# (разные порты: HAProxy :25565, Rust LB :25566)

# Фаза 2: Переключить edge ноды на Rust LB
# (изменить backend.address в config.toml)

# Фаза 3: Остановить HAProxy
# (когда все edge переключены)
```

---

## v0.6 → v0.7 (Polish)

### Изменения
- io_uring runtime (feature flag)
- Zero-copy splice
- SLSA Level 3

### Шаги

```bash
# 1. Проверить io_uring доступность
cat /proc/sys/kernel/io_uring_disabled  # 0 = OK

# 2. Собрать с io_uring
cargo build --release --features io-uring

# 3. Заменить бинарник
cp /usr/local/bin/rampart-core /usr/local/bin/rampart-core.epoll.backup
cp target/release/rampart-core /usr/local/bin/
systemctl restart rampart-edge

# 4. Проверить
journalctl -u rampart-edge | grep "io_uring"

# 5. Бенчмарк: сравнить производительность
tcpkali --connections 1000 --connect-rate 5000 --duration 30s EDGE_IP:25565
```

---

## Чеклист перед любой миграцией

```
☐ Прочитал CHANGELOG
☐ Сделал бэкап Redis: redis-cli SAVE
☐ Сделал бэкап конфигов: tar czf /backup/rampart-configs-$(date +%Y%m%d).tar.gz /etc/rampart/
☐ Сохранил старые бинарники
☐ Есть доступ к серверу через OOB/IPMI (на случай если сеть отвалится)
☐ Есть откат-план
☐ Предупредил команду в Discord
```

---

*Версия: 1.0 | Июль 2026*
