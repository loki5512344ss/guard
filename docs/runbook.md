# Runbook - Rampart

> Пошаговые инструкции для админа в критических ситуациях.

---

## 1. DDoS атака — пошагово

```bash
# ── ШАГ 1: Подтвердить атаку ──

# Метрики edge ноды
curl -s http://EDGE_IP:9090/metrics | grep -E "rampart_(connections|rate_limit|attack_status)"

# rampart_attack_status: 0 = normal, 1 = suspicious, 2 = under_attack
# (детектор по порогу pps, см. src/traffic/detector.rs)

# ── ШАГ 2: Определить тип атаки ──

# Много SYN без завершения handshake → L3/L4, смотрим kernel/XDP
ss -s

# Много установленных коннектов с малым трафиком → slow-атака (L4)
# Много коннектов/сек с одних IP → connection flood

# ── ШАГ 3: Действия через конфиг (правка + рестарт) ──

# A) Connection flood → ужесточить per-IP лимиты в /etc/rampart/config.toml:
#    [limits]
#    rate_limit_pps = 2.0
#    rate_limit_burst = 5.0
#    max_connections_per_ip = 5
systemctl restart rampart

# B) Атака с известных подсетей → внести в blacklist через Manager API или CLI:
rampart-cli blacklist add 1.2.3.4 "ddos source"
rampart-cli blacklist list

# C) Доверенные IP (мониторинг, админы) → whitelist в config.toml
#    (только IP-адреса), затем systemctl restart rampart

# D) Для Minecraft Java PoW не включай: он несовместим с протоколом.
#    Проверь фильтрацию трафика у upstream game-proxy и его лимиты.

# ── ШАГ 4: Если не помогает ──

# В крайнем случае — закрыть порт на firewall и разбираться:
iptables -A INPUT -p tcp --dport 25565 -j DROP

# ── ШАГ 5: После атаки ──

# События атак пишутся в ClickHouse (если настроен clickhouse_url):
clickhouse-client --query "SELECT count() FROM rampart.events WHERE event_type='attack'"

# Написать post-mortem
```

> Честно: hot-reload конфига не реализован — изменения применяются рестартом.
> ASN/CIDR-баны, GeoIP-блокировки стран и выбор типов challenge через CLI не
> реализованы; blacklist принимает цели в том виде, в котором их хранит Manager.
> Команды `emergency`, `drain` и `config set` пока не реализованы и завершатся
> явной ошибкой вместо изменения состояния.

## 2. Edge нода не стартует

```bash
systemctl status rampart
journalctl -u rampart -n 50 --no-pager

# Типичные причины:

# A) Порт занят
ss -tlnp | grep 25565

# B) Конфиг невалиден — проверь парсингом теста:
cargo test --test config_parse
# Или запусти вручную и прочитай ошибку:
RAMPART_CONFIG=/etc/rampart/config.toml /usr/local/bin/rampart

# C) Нет ни одного protocol handler
# rampart требует зарегистрированный ProtocolHandler (feature protocol-http
# или внешний крейт). Пока плагинов нет — edge в исследовательском режиме.

# D) XDP не загрузился
journalctl -u rampart | grep -i xdp
# Временное решение: [xdp] enabled = false в config.toml
```

## 3. XDP не загружается

```bash
systemd-detect-virt   # openvz/lxc → XDP не работает, нужен KVM
uname -r              # нужно 5.10+
ethtool -i eth0 | grep driver

# Проверить компиляцию BPF-программы:
clang -O2 -g -target bpf -c xdp/core/universal_filter.c -o /tmp/universal_filter.o

# Отключить XDP:
# [xdp] enabled = false → systemctl restart rampart
```

## 4. Клиенты не могут подключиться

```bash
curl -s http://EDGE_IP:9090/metrics | grep rampart_connections

nc -zv EDGE_IP 25565          # порт открыт?
iptables -L INPUT -n -v | grep 25565
dig +short your.domain         # DNS указывает на edge?

# NAT: много клиентов за одним IP упираются в max_connections_per_ip — увеличь.
```

## 5. Высокая нагрузка на edge

```bash
htop -p $(pgrep -d',' rampart)
iftop -i eth0                  # pps/bandwidth

# Не хватает воркеров → [workers] count = vCPU, рестарт.
# CPU > 80% от userspace → включи XDP ([xdp] enabled = true),
# чтобы дропать мусор раньше, и ужесточи rate limit.
```

## 6. ClickHouse переполнен

```bash
df -h /var/lib/clickhouse
clickhouse-client --query "ALTER TABLE rampart.events MODIFY TTL ts + INTERVAL 90 DAY"
# Временное отключение записи: закомментируй clickhouse_url в config.toml, рестарт.
```

## 7. Краткий справочник команд

```bash
rampart-cli status                        # Общее состояние системы
rampart-cli doctor                        # Полная диагностика
rampart-cli blacklist add <target> [reason]
rampart-cli blacklist remove <target>
rampart-cli blacklist list
```

Полный список: `rampart-cli --help` (источник — src/bin/rampart-cli.rs).

---

*Версия: 2.0 | Август 2026*
