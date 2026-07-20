# Disaster Recovery - Rampart

> Что делать когда что-то пошло не так.

## Схема failover

```
Redis упал:
  Edge: продолжает с локальным кэшем
  Velocity: продолжает с последним кэшем серверов
  Manager: API не работает → рестарт Redis, рестарт Manager

Manager упал:
  Edge: продолжает автономно
  Velocity: читает Redis напрямую
  Dashboard: недоступен → рестарт Manager

Edge нода упала:
  Игроки на ней теряют коннект
  При реконнекте → BGP/DNS → другая Edge нода
  Если Edge одна → все офлайн

Полный сбой дата-центра:
  Edge ноды в других ДЦ продолжают работу
  Игроки на живых серверах продолжают играть
  Новые регистрации/баны не синхронизируются до восстановления
```

Все компоненты кроме Manager продолжают работать в degraded mode.
Manager - единственная single point of failure (без Redis Sentinel).

---

## 1. Redis упал

### Симптомы
- Velocity не видит новые серверы
- Edge не синхронизирует блэклист
- Manager API возвращает 500

### Влияние
- **Edge:** Продолжает работать с локальным кэшем блэклиста. Новые баны не синхронизируются между нодами.
- **Velocity:** Продолжает работать с последним кэшем server registry. Новые серверы недоступны до восстановления Redis.
- **Manager:** API не работает.

### Действия

```bash
# 1. Проверка Redis
redis-cli ping
systemctl status redis

# 2. Если Redis завис - рестарт
systemctl restart redis

# 3. Если Redis навсегда умер - поднять новый
# Убедись что пароль совпадает с конфигами
docker run -d --name rampart-redis \
  -p 6379:6379 \
  redis:7-alpine redis-server --requirepass "$REDIS_PASSWORD"

# 4. Перезапустить Manager (он переподключится)
systemctl restart rampart-manager

# 5. Edge ноды переподключатся автоматически (retry в драйвере Redis)
# Если не переподключились - рестарт:
systemctl restart rampart-edge

# 6. Velocity переподключится с задержкой до 5 сек
```

### Предотвращение
- Redis Sentinel для HA (3 ноды)
- AOF + RDB persistence включены
- Регулярные бэкапы: `redis-cli SAVE`

---

## 2. Manager упал

### Симптомы
- API не отвечает
- Blacklist изменения не применяются
- Edge heartbeat пропадает

### Влияние
- **Edge:** Продолжает работать автономно. Локальный блэклист активен.
- **Velocity:** Продолжает работать. Server registry из Redis доступен.
- **Dashboard:** Недоступен.

### Действия

```bash
# 1. Проверка
systemctl status rampart-manager
journalctl -u rampart-manager -n 50 --no-pager

# 2. Рестарт
systemctl restart rampart-manager

# 3. Если не стартует - проверить логи
journalctl -u rampart-manager -e | grep ERROR

# 4. Если проблема в конфиге
# Откатить последние изменения конфига
git checkout HEAD~1 -- config/manager.toml
systemctl restart rampart-manager
```

### Предотвращение
- systemd `Restart=always`
- Мониторинг: Prometheus alert `EdgeNodeDown`
- Два Manager в active/passive (v0.6+)

---

## 3. Edge нода упала

### Симптомы
- Игроки на этой ноде теряют соединение
- Prometheus alert: `EdgeNodeDown`
- Метрики перестали приходить

### Влияние
- Игроки, подключённые через эту ноду, дисконнектятся
- При переподключении → попадают на другую edge ноду
- Если edge нода одна → **все игроки офлайн**

### Действия

```bash
# 1. Проверка
systemctl status rampart-edge
journalctl -u rampart-edge -n 50 --no-pager

# 2. Если OOM kill
dmesg | grep -i "oom\|rampart"

# 3. Рестарт
systemctl restart rampart-edge

# 4. Если не стартует - проверить конфиг
rampart doctor

# 5. Если аппаратная проблема - переключить DNS на другую edge ноду
# (при нескольких edge нодах)
```

### Предотвращение
- Минимум 2 edge ноды
- DNS round-robin или BGP Anycast
- systemd `Restart=always`
- `rampart drain` для graceful maintenance

---

## 4. ClickHouse упал

### Симптомы
- Attack log не пишется
- Dashboard по блокировкам пустой

### Влияние
- **Edge / Velocity / Manager:** Продолжают работать. Потеря аналитики.
- Данные не теряются (буферизация в Manager на 1 секунду с батчем до 1000).

### Действия

```bash
# 1. Проверка
systemctl status clickhouse-server
curl http://localhost:8123/ping

# 2. Рестарт
systemctl restart clickhouse-server

# 3. Если долго восстанавливается - проверить диск
df -h /var/lib/clickhouse

# 4. Если диск полон - почистить старые партиции
clickhouse-client --query "ALTER TABLE rampart.blocked DROP PARTITION '2025-01'"
```

### Предотвращение
- TTL на таблицах (90 дней автоочистка)
- ClickHouse Cloud или Cluster (v0.6+)
- Alertmanager при заполнении диска > 80%

---

## 5. Root CA key скомпрометирован

### Симптомы
- Вы знаете что ключ утек
- Подозрительные сертификаты в сети

### Влияние
- **Полная компрометация mTLS:** Атакующий может выпустить сертификаты для любой ноды

### Действия

```bash
# 1. НЕМЕДЛЕННО: Сгенерировать новый Root CA
rampart pki init --root-ca rampart-ca-v2 --force

# 2. Выпустить новые сертификаты для ВСЕХ нод
for node in edge-eu-1 edge-us-1 vel-1 manager; do
  rampart pki issue --ca edge-ca --name "$node" \
    --ip "$(dig +short $node.rampart.internal)" \
    --san "$node.rampart.internal" \
    --output "/etc/rampart/pki/$node/"
done

# 3. Разослать новые сертификаты на все ноды
rampart pki sync --all-nodes

# 4. Перезапустить все сервисы (с новыми сертификатами)
rampart restart --all

# 5. Отозвать старый Root CA
rampart pki revoke --ca rampart-ca-v1

# 6. Расследовать утечку
# - Проверить кто имел доступ к ключу
# - Проверить логи доступа
# - Сменить все пароли
```

### Предотвращение
- Root CA ключ хранить **вне серверов** (на YubiKey или в Vault)
- Использовать Intermediate CA для повседневной работы
- Audit лог доступа к CA ключу

---

## 6. Полный сбой инфраструктуры

### Ситуация
Упали нода Manager + Redis + NATS одновременно (например, отключили дата-центр).

### Влияние
- Все edge ноды продолжают работать автономно
- Блэклист не синхронизируется
- Server registry не обновляется
- **Игроки продолжают играть на уже запущенных серверах**

### Восстановление

```bash
# 1. Поднять Manager на новой VDS
docker compose up -d

# 2. Восстановить Redis из бэкапа
redis-cli --pipe < /backup/rampart-redis-$(date +%Y-%m-%d).rdb

# 3. Edge ноды и Velocity переподключатся автоматически
# (они реконнектятся с экспоненциальной задержкой: 1s, 2s, 4s, 8s... max 60s)

# 4. Проверить что всё синхронизировалось
rampart doctor
```

### Предотвращение
- Бэкапы Redis: ежедневно, хранить 30 дней
- Terraform для быстрого поднятия инфраструктуры
- DNS записи с низким TTL (60 сек)

---

## 7. DDoS на Manager/Redis

### Симптомы
- Manager API не отвечает
- Redis latency > 1 секунды
- CPU Manager 100%

### Действия

```bash
# 1. Изолировать Manager - закрыть все порты кроме WireGuard
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -j DROP

# 2. Если DDoS идёт на публичный IP - отключить его
# (Оставить только WireGuard туннель)

# 3. Edge ноды переживут без Manager несколько часов
#   (они кэшируют блэклист локально)
```

---

## 8. Cheatsheet быстрых команд

```bash
# Рестарт всего
systemctl restart rampart-edge rampart-manager redis clickhouse-server

# Проверка здоровья всей системы
rampart doctor

# Последние 50 строк логов edge
journalctl -u rampart-edge -n 50 -f

# CPU/memory edge
htop -p $(pgrep -d',' rampart-edge)

# Трафик на интерфейсе
iftop -i eth0

# Статистика Redis
redis-cli info stats | grep -E "total_connections|total_commands|rejected"

# Активные соединения
ss -s | grep TCP
```

---

*Версия: 1.0 | Июль 2026*
