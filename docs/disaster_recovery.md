# Disaster Recovery - Rampart

> Что делать, когда что-то пошло не так.

## Схема failover

```
Redis упал:
  Edge: продолжает автономно на локальном кэше блэклиста
  Manager: API отдаёт пустые списки / ошибки → рестарт Redis

Manager упал:
  Edge: продолжает фильтрацию (фильтрация не зависит от Manager)
  Управление (CLI/API) недоступно до восстановления

Edge нода упала:
  Клиенты за ней теряют соединение
  При нескольких edge → DNS round-robin на живые
  Если edge одна — сервис недоступен

Полный сбой дата-центра:
  Edge в других ДЦ продолжают работу
  Баны/ноды не синхронизируются до восстановления Redis
```

---

## 1. Redis упал

### Симптомы
- Edge перестал синхронизировать блэклист
- Manager API отдаёт пустые списки nodes/servers/blacklist

### Влияние
- **Edge:** работает с локальным кэшем; новые баны не распространяются между нодами.
- **Manager:** данные из Redis недоступны.

### Действия

```bash
redis-cli ping || systemctl restart redis

# Поднять новый (пароль должен совпадать):
docker run -d --name rampart-redis -p 6379:6379 \
  redis:7-alpine redis-server --requirepass "$REDIS_PASSWORD"

systemctl restart rampart-manager   # переподключится
# Edge переподключается сам (retry в драйвере); иначе:
systemctl restart rampart
```

### Предотвращение
- AOF + RDB persistence включены
- Регулярные бэкапы: `redis-cli SAVE`

---

## 2. Manager упал

### Симптомы
- `rampart-cli` команды падают с ошибкой соединения
- `/api/v1/health` не отвечает

### Влияние
- Edge продолжает фильтровать трафик автономно.

### Действия

```bash
systemctl status rampart-manager
journalctl -u rampart-manager -n 50 --no-pager
systemctl restart rampart-manager

# Не стартует? Частая причина — env:
# JWT_SECRET < 32 байт или API_PASSWORD=changeme → процесс выходит с ошибкой.
journalctl -u rampart-manager -e | grep ERROR
```

---

## 3. Edge нода упала

### Симптомы
- Клиенты теряют соединение, метрики :9090 пропали

### Действия

```bash
systemctl status rampart
journalctl -u rampart -n 50 --no-pager

dmesg | grep -i "oom\|rampart"    # OOM kill?
systemctl restart rampart

# Не стартует — проверь конфиг и логи (см. runbook.md §2)
```

### Предотвращение
- Минимум 2 edge ноды + DNS round-robin
- systemd `Restart=always`
- Несколько edge нод за одним DNS-именем

---

## 4. ClickHouse упал

### Влияние
Только потеря аналитики: события буферизуются и пишутся асинхронно,
фильтрация не зависит от ClickHouse.

### Действия

```bash
curl http://localhost:8123/ping || systemctl restart clickhouse-server
df -h /var/lib/clickhouse   # диск полон?
```

---

## 5. Полный сбой инфраструктуры

```bash
# 1. Поднять Manager на новой VDS
docker compose up -d redis && cargo run --release --bin rampart-manager

# 2. Восстановить Redis из бэкапа
redis-cli --pipe < /backup/rampart-redis-$(date +%Y-%m-%d).rdb

# 3. Edge ноды переподключатся автоматически

# 4. Проверить
rampart-cli doctor
```

---

## 6. Cheatsheet быстрых команд

```bash
systemctl restart rampart rampart-manager redis clickhouse-server
journalctl -u rampart -n 50 -f
htop -p $(pgrep -d',' rampart)
iftop -i eth0
ss -s | grep TCP
```

---

*Версия: 2.0 | Август 2026*
