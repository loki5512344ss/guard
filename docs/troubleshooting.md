# Troubleshooting - FAQ и диагностика

---

## Edge нода

### "XDP не загружается"

```bash
# Проверяем виртуализацию
systemd-detect-virt
# openvz / lxc -> XDP не работает, нужен KVM

# Проверяем ядро
uname -r
# Нужно 5.10+

# Проверяем зависимости
dpkg -l | grep libbpf
# libbpf-dev должен быть установлен

# Смотрим ошибку загрузки
journalctl -u rampart-edge | grep -i "xdp\|ebpf\|bpf"

# Если драйвер не поддерживает native - fallback на generic
# В конфиге:
[xdp]
mode = "generic"   # вместо "native" или "auto"
```

### "Edge не коннектится к Manager"

```bash
# Проверяем WireGuard
ping 10.0.0.1
# Нет ответа -> WireGuard не работает

wg show
# Смотрим peer Manager - есть ли last handshake?
# Нет handshake -> проблема с ключами или firewall у Manager

# Проверяем firewall на Manager
ssh root@MANAGER_IP 'iptables -L INPUT -n | grep 51820'
# Должно быть правило ACCEPT для UDP 51820

# Проверяем что Manager слушает
ssh root@MANAGER_IP 'ss -ulnp | grep 51820'

# Пересоздаём WireGuard handshake
wg set wg0 peer MANAGER_PUBKEY endpoint MANAGER_IP:51820
```

### "Rate limit блокирует реальных игроков"

```bash
# Симптом: игроки жалуются что не могут зайти

# Смотрим кого блокируем
journalctl -u rampart-edge | grep "RATE_LIMIT" | tail -50

# Если блокируем целые подсети мобильных операторов (NAT):
# Увеличиваем лимит для мобильных ASN
rampart config set rate_limit.mobile_multiplier 3.0

# Или поднимаем общий лимит
rampart config set rate_limit.max_connections_per_ip 10
rampart config reload
```

### "Высокое CPU на edge ноде"

```bash
# Смотрим что жрёт CPU
top -p $(pgrep rampart-edge)

# Профилируем
perf top -p $(pgrep rampart-edge)

# Частые причины:
# 1. Слишком много активных соединений -> включить XDP чтобы дропать раньше
# 2. HMAC считается для каждого пакета -> норма, так и должно быть
# 3. GeoIP lookup медленный -> включить кэш
[geo]
cache_size = 100000
cache_ttl_secs = 3600
```

---

## Velocity плагин

### "Velocity не видит серверы"

```bash
# В логах Velocity ищем:
grep -i "rampart\|registry\|redis" /opt/velocity/logs/latest.log

# Частые причины:

# 1. Redis недоступен
redis-cli -h 10.0.0.1 -a $REDIS_PASSWORD ping
# Connection refused -> Redis не слушает на WireGuard IP

# 2. Неверный пароль Redis
# В config.yml проверяем redis.password

# 3. Velocity не в WireGuard сети
ping 10.0.0.1   # с ноды Velocity
# Нет ответа -> настраиваем WireGuard

# 4. Серверы не зарегистрированы (Paper агент не запущен)
redis-cli -h 10.0.0.1 -a $REDIS_PASSWORD keys "rampart:servers:*"
# Пустой ответ -> Paper агент не работает
```

### "Игроков не пускает - 'Подключение по IP запрещено'"

```bash
# Это нормально если игрок подключается по IP, а не домену
# Проверяем что DNS работает:
nslookup play.yourserver.com
# Должен вернуть IP edge ноды

# Если игрок подключается через домен и всё равно кикает:
# Проверяем что edge HMAC совпадает с Velocity

# На Velocity смотрим логи:
grep "HMAC\|shield" /opt/velocity/logs/latest.log

# Частые причины:
# 1. Разные HMAC секреты на edge и Velocity
# Сравниваем:
cat /etc/rampart/config.toml | grep hmac_secret
grep RAMPART_HMAC_SECRET /opt/velocity/velocity.conf

# 2. Edge нода не добавляет HMAC (add_hmac_header = false)
# В /etc/rampart/config.toml:
[shield]
add_hmac_header = true
```

### "Игрок попадает не на тот сервер"

```bash
# Проверяем стратегию балансировщика
grep "strategy" /opt/velocity/plugins/rampart/config.yml

# Смотрим онлайн по серверам
rampart server list

# Если сервер переполнен но всё равно получает игроков:
# Проверяем что Paper агент обновляет онлайн
redis-cli -h 10.0.0.1 -a $REDIS_PASSWORD \
  GET rampart:servers:hub_1
# В JSON смотрим "online" - должно обновляться
```

---

## Paper агент

### "Агент не регистрирует сервер"

```bash
# В логах Minecraft сервера:
grep -i "rampart\|shield agent" /opt/minecraft/logs/latest.log

# Частые причины:

# 1. Redis недоступен с этой ноды
redis-cli -h 10.0.0.1 -a $REDIS_PASSWORD ping

# 2. Неверный IP в конфиге (указан публичный вместо WireGuard)
# Проверить env RAMPART_SERVER_IP
# Должен быть 10.0.x.x (WireGuard IP)

# 3. Дублирующееся имя сервера
redis-cli -h 10.0.0.1 -a $REDIS_PASSWORD \
  keys "rampart:servers:*"
# Если имя уже есть - изменить RAMPART_SERVER_NAME

# 4. Агент не установлен
ls /opt/minecraft/plugins/ | grep rampart-paper
# Должен быть .jar файл
```

---

## Redis

### "Redis падает с OOM"

```bash
# Проверяем использование памяти
redis-cli -a $REDIS_PASSWORD INFO memory | grep used_memory_human

# Настраиваем eviction policy
redis-cli -a $REDIS_PASSWORD CONFIG SET maxmemory 2gb
redis-cli -a $REDIS_PASSWORD CONFIG SET maxmemory-policy allkeys-lru

# Смотрим что занимает место
redis-cli -a $REDIS_PASSWORD --bigkeys
```

### "Redis медленно отвечает"

```bash
# Запускаем latency monitor
redis-cli -a $REDIS_PASSWORD --latency-history -i 1

# Смотрим slowlog
redis-cli -a $REDIS_PASSWORD SLOWLOG GET 10

# Частые причины:
# 1. KEYS команда (блокирует) -> заменить на SCAN
# 2. Нет persistent connection pool -> Jedis pool в Velocity плагине
# 3. Сеть: проверяем пинг от Velocity до Redis через WireGuard
ping 10.0.0.1
```

---

## WireGuard

### "Ноды не видят друг друга"

```bash
# На каждой ноде
wg show
# Смотрим:
# - есть ли peer с нужным PublicKey
# - есть ли "latest handshake" (должен быть свежий)
# - endpoint правильный

# Если нет handshake:
# 1. Проверяем что Manager слушает UDP 51820
ss -ulnp | grep 51820

# 2. Проверяем firewall на Manager
iptables -L INPUT -n | grep 51820

# 3. Проверяем что ключи правильные
wg pubkey < /etc/wireguard/private.key
# Должен совпасть с PublicKey у peer на Manager

# Форс рестарт
systemctl restart wg-quick@wg0
```

### "Высокий пинг через WireGuard"

```bash
# Измеряем
ping 10.0.0.1
# Нормально: < 5 мс внутри датацентра, < 50 мс между регионами

# Если > 200 мс -> проблема с маршрутизацией
traceroute 10.0.0.1

# MTU проблема (фрагментация):
ping -M do -s 1400 10.0.0.1
# Если drops -> MTU слишком большой
# В /etc/wireguard/wg0.conf добавить:
MTU = 1380
```

---

## ClickHouse

### "ClickHouse не принимает данные"

```bash
# Проверяем что запущен
systemctl status clickhouse-server
# или
docker compose ps rampart-clickhouse

# Проверяем таблицы
clickhouse-client --query "SHOW TABLES FROM rampart"

# Проверяем ошибки вставки в логах Manager
journalctl -u rampart-manager | grep -i "clickhouse\|insert"

# Частые причины:
# 1. Таблица не создана -> запускаем миграции
rampart db migrate

# 2. Нет места на диске
df -h
# ClickHouse хранит в /var/lib/clickhouse/

# 3. Неверная схема (после обновления)
clickhouse-client --query "DESCRIBE TABLE rampart.blocked"
```

---

## Общая диагностика

```bash
# Полная проверка системы одной командой
rampart doctor

# Что проверяет:
# ✅ WireGuard туннели
# ✅ Redis доступность
# ✅ NATS доступность
# ✅ Manager API
# ✅ Все edge ноды online
# ✅ Все Velocity ноды online
# ✅ Хотя бы один Hub онлайн
# ✅ HMAC секрет одинаковый везде
# ✅ Сертификаты не истекают в ближайшие 30 дней
# ✅ Redis память < 80%
# ✅ Место на дисках > 20%

# Вывод:
# [OK]   Redis: 10.0.0.1:6379
# [OK]   Manager API: /api/health
# [WARN] Edge eu-1: last seen 45 sec ago (порог 30 сек)
# [FAIL] Hub_5: не зарегистрирован в Redis
```

---

*Версия: 1.0 | Июль 2026*
