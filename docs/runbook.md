# Runbook - Rampart

> Пошаговые инструкции для админа в критических ситуациях.

---

## 1. DDoS атака - пошагово (3 ночи, вы сонный)

```bash
# ── ШАГ 1: Подтвердить атаку ──

# Открыть Grafana → посмотреть алерты
# Или в CLI:
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.state=="firing")'

# Проверить метрики edge ноды
curl -s http://EDGE_IP:9090/metrics | grep -E "rampart_(connections|rate_limit|blocked)"

# ── ШАГ 2: Определить тип атаки ──

# Если CPU < 50% и много DROP → XDP работает, атака L3/L4
# Если CPU > 80% → атака L7 (handshake flood)

# Проверка XDP счётчиков
cat /sys/kernel/debug/tracing/trace_pipe | head -20

# ── ШАГ 3: Действия ──

# A) SYN flood (XDP справляется)
#   → просто наблюдаем, XDP дропает на уровне ядра
#   → проверить CPU: должен быть < 30%
echo "Наблюдаем, XDP работает"

# B) Handshake flood (L7)
#   → Ужесточить rate limit на лету
rampart config set rate_limit_login_pps 2
rampart config set rate_limit_burst 5

#   → Включить emergency mode (только whitelist)
rampart emergency --enable
#   Это блокирует все IP кроме whitelist (доверенные ASN, verified players)

# C) Атака с датацентров
#   → Заблокировать ASN
rampart blacklist add asn 16276  # OVH
rampart blacklist add asn 24940  # Hetzner

#   → Включить GeoIP фильтр (блокировать страну)
rampart geoip block CN RU

# D) Атака на конкретный протокол
#   → Временно заблокировать статус пинги
rampart config set rate_limit_status_pps 0.1

#   → Заблокировать старые версии протокола
rampart config set min_protocol_version 765

# ── ШАГ 4: Если не помогает ──

# Включить challenge для ВСЕХ новых подключений
rampart challenge --mode all --type timing

# В крайнем случае - отключить все не-WG порты на edge
systemctl stop rampart-edge
iptables -A INPUT -p tcp --dport 25565 -j DROP
# Игроки не заходят, но серверы в безопасности
# Проверить через провайдера: возможно у них есть tools для фильтрации

# ── ШАГ 5: После атаки ──

# Выключить emergency mode
rampart emergency --disable

# Проверить логи в ClickHouse
clickhouse-client --query "
  SELECT src_country, count() as attacks
  FROM rampart.blocked
  WHERE ts > now() - INTERVAL 1 HOUR
  GROUP BY src_country
  ORDER BY attacks DESC
  LIMIT 10
"

# Написать post-mortem
```

---

## 2. Edge нода не стартует

```bash
# 1. Проверить статус
systemctl status rampart-edge

# 2. Логи
journalctl -u rampart-edge -n 50 --no-pager

# 3. Типичные причины:

#   A) Порт занят
ss -tlnp | grep 25565
#   Решение: сменить порт в /etc/rampart/config.toml

#   B) Конфиг не валидный
rampart config validate /etc/rampart/config.toml

#   C) libbpf не найден (если собрано с XDP)
ldd /usr/local/bin/rampart-core | grep bpf
#   Решение: apt-get install libbpf-dev

#   D) Нет прав на BPF
#   Решение: sudo setcap cap_bpf+ep /usr/local/bin/rampart-core

# 4. Запуск вручную (для диагностики)
/usr/local/bin/rampart-core --config /etc/rampart/config.toml --verbose
```

---

## 3. XDP не загружается

```bash
# 1. Проверить виртуализацию
systemd-detect-virt
# openvz/lxc → XDP не работает. Сменить провайдера.

# 2. Проверить версию ядра
uname -r
# < 5.10 → обновить ядро

# 3. Проверить драйвер
ethtool -i eth0 | grep driver
# virtio → только generic mode
# i40e/mlx5 → native mode

# 4. Проверить XDP поддержку
sudo ip link set dev eth0 xdp off 2>&1
# "Operation not supported" → XDP не поддерживается

# 5. Решение: отключить XDP в config.toml
# [xdp]
# enabled = false
# И перезапустить edge
systemctl restart rampart-edge
```

---

## 4. Игроки не могут зайти

```bash
# 1. Проверить edge ноду
curl -s http://EDGE_IP:9090/metrics | grep rampart_connections
# Если 0 → edge не принимает соединения

# 2. Проверить что порт открыт
nc -zv EDGE_IP 25565

# 3. Проверить HMAC
# На velocity: /logs/rampart-hmac.log
# "HMAC mismatch" → не совпадает secret
# "Direct IP blocked" → игрок подключился не через edge

# 4. Проверить firewall
iptables -L INPUT -n -v | grep 25565

# 5. Проверить DNS
dig +short play.example.com
# Должен показывать IP edge ноды

# 6. Проверить rate limit
# Если игроков много с одного IP (NAT) - превышают лимит
rampart config set max_connections_per_ip 50  # увеличить
```

---

## 5. Высокая нагрузка на edge

```bash
# 1. Определить bottleneck

# CPU
htop -p $(pgrep -d',' rampart-core)

# Память
ps aux | grep rampart-core

# I/O (если много логов)
iotop

# Сеть (pps, bandwidth)
iftop -i eth0

# 2. Типичные причины:

#   A) Не хватает воркеров
#   → Увеличить workers = vCPU
rampart config set workers_count $(nproc)
systemctl restart rampart-edge

#   B) CPU > 80% от L7 парсинга
#   → Включить XDP чтобы разгрузить userspace
#   → Уменьшить rate_limit до разумных пределов
#   → Проверить что нет SQL injection или других атак (парсинг hostname!)

#   C) Утечка памяти
#   → Проверить RSS за последние часы
#   → Если растёт - включить профилирование
rampart debug pprof

# 3. Временное решение
rampart config set max_connections 50000  # ограничить

# 4. Постоянное решение
# Добавить ещё одну edge ноду
rampart add-node --role edge --name edge-eu-2 --ip 45.200.10.2
```

---

## 6. ClickHouse переполнен

```bash
# 1. Проверить дисковое пространство
df -h /var/lib/clickhouse

# 2. Очистить старые партиции (> 90 дней)
clickhouse-client --query "
  SELECT partition, formatReadableSize(bytes_on_disk)
  FROM system.parts
  WHERE table = 'blocked'
  ORDER BY partition
"

# Удалить старые
clickhouse-client --query "
  ALTER TABLE rampart.blocked DROP PARTITION '2025-01'
"

# 3. Настроить TTL если не сделано
clickhouse-client --query "
  ALTER TABLE rampart.blocked
  MODIFY TTL ts + INTERVAL 90 DAY
"

# 4. Отключить логирование на время (если совсем плохо)
rampart config set clickhouse_enabled false
# Данные складываются в буфер, не теряются
```

---

## 7. Краткий справочник команд

```bash
rampart status                    # Общее состояние системы
rampart doctor                    # Полная диагностика

rampart config get workers.count  # Получить параметр
rampart config set workers.count 4  # Установить параметр (hot reload)

rampart blacklist add 1.2.3.4     # Забанить IP
rampart blacklist add asn 24940   # Забанить ASN
rampart blacklist list            # Список забаненных
rampart blacklist remove 1.2.3.4  # Разбанить

rampart whitelist add 10.0.0.0/16  # Добавить в whitelist
rampart emergency --enable        # Включить emergency mode
rampart emergency --disable       # Выключить

rampart drain edge-eu-1           # Плавно вывести ноду
rampart reload backend            # Перезагрузить список бэкендов
rampart pki rotate --role edge    # Ротация сертификатов
rampart wg sync                   # Синхронизация WireGuard

rampart debug pprof               # CPU профиль
rampart debug heap                # Heap профиль
rampart debug metrics             # Prometheus метрики в CLI
```

---

*Версия: 1.0 | Июль 2026*
