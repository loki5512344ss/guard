# Runbook - Rampart

> Пошаговые инструкции для админа в критических ситуациях.

---

## 1. DDoS атака — пошагово

```bash
# ── ШАГ 1: Подтвердить атаку ──

# Метрики edge ноды
curl -s http://EDGE_IP:9090/metrics | grep -E "rampart_(connections_total|rate_limit_hits|attack_status)"

# rampart_attack_status: 0 = normal, 1 = suspicious, 2 = under_attack
# (детектор по порогу pps, см. src/traffic/intel/detector.rs)

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
rampart-cli blacklist add 1.2.3.4 "ddos source" --for 1h30m   # 30s, 5m, 1h30m, 2d
#    Голое число (--for 90) отвергается: единицы указываются явно (s, m, h, d).
#    Без --for действует срок по умолчанию manager API (300 с).
#    Отдельного старого флага --duration-secs в CLI нет; в API поле duration_secs
#    остаётся (и появился альтернативный абсолютный expires_at).
rampart-cli blacklist list    # показывает оставшееся время, например [1h29m left]

# C) Доверенные IP (мониторинг, админы) → whitelist в config.toml
#    (только IP-адреса), затем systemctl restart rampart

# D) Флуд со спуфленных адресов (много уникальных источников, SYN-throttle не
#    помогает) → RST-challenge в XDP. Работает для любого TCP-протокола, включая
#    Minecraft (PoW для Minecraft не включай: он несовместим с протоколом):
#      [xdp] syn_challenge_enabled = true
#            challenge_secret_hex  = "<openssl rand -hex 8>"
#    затем systemctl restart rampart. Живой клиент теряет ~10–20 мс на первый
#    connect (один RST и ретрансмит SYN), спуф не проходит. См. §2 метрики challenge.

# ── ШАГ 4: Если не помогает ──

# В крайнем случае — закрыть порт на firewall и разбираться:
iptables -A INPUT -p tcp --dport 25565 -j DROP

# ── ШАГ 5: После атаки ──

# События атак пишутся в ClickHouse (если настроен clickhouse_url):
clickhouse-client --query "SELECT count() FROM rampart_events WHERE event_type='attack'"

# Написать post-mortem
```

> Честно: hot-reload конфига не реализован — изменения применяются рестартом.
> ASN/CIDR-баны, GeoIP-блокировки стран и выбор типов challenge через CLI не
> реализованы; blacklist принимает цели в том виде, в котором их хранит Manager.

---

## 2. Сигналы деградации — что смотреть

| Метрика / лог | Что значит | Что делать |
|---------------|-----------|------------|
| `rampart_connections_total{result="overloaded"}` | исчерпан глобальный бюджет соединений (4×workers×max_connections_per_ip) | проверить, не атака ли; при легитимной нагрузке — поднять `max_connections_per_ip`/`workers.count` |
| `rampart_xdp_dropped` растёт, `rampart_xdp_passed` — нет | XDP дропает всё | проверить `protected_port_start/end`, баны и счётчики `stats_map` (список — [architecture.md](architecture.md) §6); смотреть через `bpftool` |
| `rampart_xdp_challenge_sent` растёт, `rampart_xdp_challenge_verified` стоит | challenge отвечает на SYN, но никто не проходит: либо это чистый спуф-флуд (норма), либо легитимные клиенты не доходят | `curl` к порту с внешнего хоста: если не открывается — проверить, что SYN-ACK уходит с NIC (`tcpdump -ni <if> 'tcp[13]=18'`) и что upstream не режет пакеты с неверным ack |
| `rampart_xdp_challenge_failed` растёт | RST по pending-flow с неверным seq или после `challenge_timeout_ms` | единичные — норма (поздние RST); лавина — кто-то подбирает challenge, источник смотреть в `tcpdump` |
| `rampart_clickhouse_dropped_total` > 0 | события не успевают уходить в ClickHouse | проверить доступность/латентность ClickHouse; события потеряны, защита работает |
| `rampart_xdp_whitelist` растёт | трафик от whitelist-адресов | норма, но если это неожиданно — проверить `whitelist` в конфиге |
| лог `global connection budget exhausted` | то же, что `overloaded` | см. выше |
| лог `accept error ... backing off` | кончились fd (`EMFILE`) или память под сокеты | поднять `ulimit -n`, проверить утечки соединений |
| лог `XDP filter attached ... (mode: generic (skb))` | драйвер не умеет native XDP | ожидаемо для virtio/veth; generic дороже по CPU |
| лог `XDP .rodata map expects N bytes` | рассинхрон `config.h` и `XdpGlobals` | это баг сборки: не запускать, сообщить с числами из лога |

Проверить, что XDP действительно снят после остановки демона:

```bash
bpftool net show dev eth0        # не должно быть xdp-программы
ip link show eth0 | grep xdp     # пусто
```

Если программа осталась — это регрессия загрузчика, а не норма: снимать вручную
`ip link set dev eth0 xdp off` и заводить баг.
> Команды `emergency`, `drain` и `config set` пока не реализованы и завершатся
> явной ошибкой вместо изменения состояния.

## 3. Edge нода не стартует

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
# Для Minecraft Java пересобери edge с --features protocol-minecraft и проверь
# секцию [protocol.minecraft]. Для HTTP используй --features protocol-http.
# Если активной protocol feature нет, edge завершится с ошибкой при запуске.

# D) XDP не загрузился
journalctl -u rampart | grep -i xdp
# Временное решение: [xdp] enabled = false в config.toml
```

## 4. XDP не загружается

```bash
systemd-detect-virt   # openvz/lxc → XDP не работает, нужен KVM
uname -r              # нужно 5.10+
ethtool -i eth0 | grep driver

# Проверить компиляцию BPF-программы:
clang -O2 -g -target bpf -I"/usr/include/$(gcc -print-multiarch)" \
  -c xdp/core/universal_filter.c -o /tmp/universal_filter.o

# Отключить XDP:
# [xdp] enabled = false → systemctl restart rampart
```

Edge при старте пишет строку `XDP environment: …`; ошибка attach содержит `hint:`
(см. [troubleshooting](troubleshooting.md#xdp-не-загружается)). Её же показывает
`rampart-cli doctor`.

### Если нода заблокировала администратора

При старте edge пишет `WARN active SSH client is not in whitelist` — добавьте адрес в
`whitelist` до атаки. Если доступ уже потерян, зайдите через консоль провайдера (VNC/KVM):

```bash
ip link set dev eth0 xdp off       # снять XDP-программу с интерфейса
systemctl stop rampart             # или [xdp] enabled = false и рестарт
```

## 5. Клиенты не могут подключиться

```bash
curl -s http://EDGE_IP:9090/metrics | grep rampart_connections

nc -zv EDGE_IP 25565          # порт открыт?
iptables -L INPUT -n -v | grep 25565
dig +short your.domain         # DNS указывает на edge?

# NAT: много клиентов за одним IP упираются в max_connections_per_ip — увеличь.
```

## 6. Высокая нагрузка на edge

```bash
htop -p $(pgrep -d',' rampart)
iftop -i eth0                  # pps/bandwidth

# Не хватает воркеров → [workers] count = vCPU, рестарт.
# CPU > 80% от userspace → включи XDP ([xdp] enabled = true),
# чтобы дропать мусор раньше, и ужесточи rate limit.
```

## 7. ClickHouse переполнен

```bash
df -h /var/lib/clickhouse
clickhouse-client --query "ALTER TABLE rampart_events MODIFY TTL timestamp + INTERVAL 90 DAY"
# Временное отключение записи: закомментируй clickhouse_url в config.toml, рестарт.
```

## 8. Краткий справочник команд

```bash
rampart-cli status                        # Общее состояние системы
rampart-cli doctor                        # Полная диагностика
rampart-cli blacklist add <target> [reason]
rampart-cli blacklist remove <target>
rampart-cli blacklist list
```

Полный список: `rampart-cli --help` (источник — src/bin/rampart-cli.rs).

---

*Версия: 3.0 | Ноябрь 2026*
