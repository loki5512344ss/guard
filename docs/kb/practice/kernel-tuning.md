# Kernel Tuning Against DDoS (sysctl)

> Knowledge Base · Practice
>
> Before any smart defense runs, the Linux kernel itself decides how many half-open connections it will tolerate, how deep its queues are, and when it gives up. Misconfigured defaults turn a moderate flood into a total outage. This article walks through the sysctl parameters that matter, explains each one, and provides a ready-to-adapt config.

## English

## 1. How it works

All parameters below live under `/proc/sys/` and can be set either at runtime (`sysctl -w`, lost on reboot) or persistently via files in `/etc/sysctl.d/*.conf` (applied by `systemd-sysctl` at boot or `sysctl --system` manually). The `/proc/sys/net/ipv4/tcp_syncookies` file corresponds to the `net.ipv4.tcp_syncookies` key, and so on.

## 2. Parameters explained

### TCP SYN flood protection

**`net.ipv4.tcp_syncookies = 1`**

When the SYN accept queue for a listening socket overflows, the kernel stops storing half-open connections and instead encodes the connection state into cryptographically signed cookies inside the SYN-ACK sequence number. A real client returns the cookie in its ACK; a flooder usually does not. This is the single most important anti-SYN-flood knob in stock Linux.

- `0` — disabled
- `1` — enabled unconditionally
- `2` — always send cookies regardless of queue state (more aggressive; use only if you know what you are doing, since some TCP option negotiation degrades)

Trade-off: cookies cannot carry TCP options negotiated during handshake (window scaling is preserved on Linux via a syncookie extension, but SACK/Timestamps may be lost), so throughput per connection can drop slightly. Keep it `1` — the cost is negligible versus being SYN-flooded to death with default settings.

**`net.ipv4.tcp_max_syn_backlog = 65535`**

Maximum number of half-open (SYN received, ACK not yet) connections queued **per listening socket** before the kernel starts dropping SYNs or engaging syncookies. Default is often 128–1024 depending on kernel version and `net.core.somaxconn`. Raising it lets a burst of legitimate clients through without immediately triggering cookie mode. Cost: each queued SYN consumes a small amount of memory (request_sock structure), so this scales with RAM, not much else.

**`net.ipv4.tcp_synack_retries = 2`** and **`net.ipv4.tcp_syn_retries = 2`**

How many times the kernel retransmits SYN-ACK (server side) / SYN (client side) without an answer before giving up. Lower values clean up dead half-open connections faster, freeing backlog slots during floods. Default 5–6 means a dead connection lingers for over a minute; value `2` cuts that to seconds.

### Listen queues

**`net.core.somaxconn = 65535`**

Upper bound on the *accept* queue (fully established connections waiting for the application to call `accept()`) of every listening socket. Critically: the application must also ask for a large backlog (the second argument of `listen()`); the effective value is `min(somaxconn, app_backlog)`. If your proxy accepts slower than clients connect, a full accept queue causes silent SYN drops or resets — raising `somaxconn` alone does nothing if the app requests 128.

**`net.ipv4.tcp_abort_on_overflow = 0`**

Leave at `0` (default): when the accept queue overflows, the kernel silently drops SYNs, letting clients retry gracefully. Setting it to `1` sends RST immediately — useful for fail-fast load tests, harmful in production.

### Packet ingress

**`net.core.netdev_max_backlog = 65535`**

Queue of frames received by the NIC but not yet processed by the CPU's softirq (NET_RX) loop. Under a packet burst faster than the CPU can drain it, this queue absorbs the difference; overflow means dropped packets *before* any filtering logic sees them. Default is often 1000, which a multi-million-pps burst exhausts instantly. Trade-off: larger backlog adds latency under sustained overload and holds more memory; it buys time for the drainer but never replaces actual filtering.

**`net.core.rmem_max` / `net.core.wmem_max`**

Ceiling for socket receive/send buffer sizes that applications can request via SO_RCVBUF/SO_SNDBUF (and for autotuning limits via the `tcp_rmem`/`tcp_wmem` third values). For high-throughput proxies moving bulk data, 16–128 MB ceilings are common; for a pure drop/throttle edge they matter little.

### Ephemeral ports and connection churn

**`net.ipv4.ip_local_port_range = 1024 65535`**

Range of source ports used for outgoing connections. When your node acts as a client — e.g., an edge proxy opening upstream connections toward backends — each concurrent outgoing connection consumes one tuple (src IP, src port, dst IP, dst port). The old default `32768 60999` gives ~28k ports; widening to the full range gives ~64k per destination tuple. Combined with:

**`net.ipv4.tcp_fin_timeout = 15`** (default 60)

Seconds a socket sits in FIN-WAIT-2 after the peer closed. Long waits tie up tuples and fd entries during churn-heavy attacks (connect-flood patterns). Lowering to 10–30 accelerates cleanup. Note: this does **not** affect TIME_WAIT duration (that's fixed at ~60s, controlled indirectly by `tcp_tw_reuse`).

**`net.ipv4.tcp_tw_reuse = 1`**

Allows reuse of TIME_WAIT sockets for *outgoing* connections when timestamps make it safe. Helps when port exhaustion, not memory, is the constraint.

### Conntrack

**`net.netfilter.nf_conntrack_max`**

Maximum number of tracked connections in the conntrack table. Only relevant if you use stateful filtering (nftables/iptables with `-m conntrack`, NAT). A connection flood can fill this table; once full, new legitimate connections get dropped too. Size it as: expected peak concurrent connections × safety factor (2–4). Each entry costs roughly 300 bytes, so 1M entries ≈ 300 MB.

**`net.netfilter.nf_conntrack_buckets`**

Hash table buckets (set at module load time, read-only afterwards). Rule of thumb: `conntrack_max / 4`. If you don't need conntrack at all on a dedicated edge box, disabling the modules entirely saves both memory and per-packet CPU.

## 3. Ready config

`/etc/sysctl.d/ddos.conf`:

```ini
# /etc/sysctl.d/ddos.conf
# Kernel hardening against volumetric L3/L4 attacks.
# Apply with: sudo sysctl --system

# --- SYN flood ---
# Enable SYN cookies when half-open queue overflows.
net.ipv4.tcp_syncookies = 1
# Deeper half-open queue per listening socket.
net.ipv4.tcp_max_syn_backlog = 65535
# Give up on dead handshakes fast.
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# --- Accept queues ---
# Allow applications to request large listen backlogs.
net.core.somaxconn = 65535
# Do NOT reset clients on queue overflow (graceful retry).
net.ipv4.tcp_abort_on_overflow = 0

# --- Ingress buffering ---
# Absorb bursts between NIC IRQ and softirq processing.
net.core.netdev_max_backlog = 65535
# Socket buffer ceilings for bulk transfer.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# --- Outgoing connection churn (edge -> backend) ---
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# --- Conntrack (only if using stateful rules) ---
# 1M tracked connections, ~300MB RAM.
net.netfilter.nf_conntrack_max = 1048576
# Reduce timeout of half-open tracked connections.
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30

# --- Optional: silence ICMP flood ---
# net.ipv4.icmp_echo_ignore_all = 1
```

Apply and verify:

```bash
sudo sysctl --system
sysctl net.ipv4.tcp_syncookies net.core.somaxconn net.core.netdev_max_backlog
# Confirm the app-side backlog matches:
ss -lnt   # Recv-Q column shows current accept queue usage vs limit on LISTEN sockets
```

## 4. Trade-offs and warnings

1. **Bigger queues ≠ protection.** Deep backlogs buy seconds of absorption. Without early dropping (XDP/nftables) they just delay the collapse and add memory pressure. Tuning raises the ceiling; it does not remove the attack.
2. **Memory accounting.** `tcp_max_syn_backlog=65535` × many listening ports × request_sock size, plus conntrack at ~300 B/entry — do the arithmetic for your VDS RAM. On a 2 GB box, don't set conntrack_max to 4M.
3. **Latency under overload.** Large `netdev_max_backlog` means packets wait longer in softirq queues exactly when the system is already overloaded — tail latency grows even though drops shrink.
4. **Application cooperation.** `somaxconn` is only a cap. The effective backlog is whatever the application passes to `listen()`. Check with `ss -lnt`.
5. **Conntrack is optional.** A dedicated edge doing stateless XDP drops + userspace verification may not need conntrack at all; loading it just to have big tables wastes CPU per packet.
6. **Test changes under load**, not just `sysctl --system`. A parameter that looks harmless can shift behavior dramatically at 100k pps (see stress-testing.md).

---
---

## Русский

# Тюнинг ядра Linux против DDoS (sysctl)

> Knowledge Base · Практика
>
> Прежде чем заработает какая-либо умная защита, само ядро Linux решает, сколько полуоткрытых соединений оно потерпит, насколько глубоки его очереди и когда сдаваться. Неоптимальные дефолты превращают умеренный флуд в полный отказ обслуживания. В этой статье разобраны значимые параметры sysctl, объяснён каждый и приведён готовый конфиг для адаптации.

## 1. Как это устроено

Все перечисленные параметры живут в `/proc/sys/` и задаются либо на лету (`sysctl -w`, сбрасывается при перезагрузке), либо постоянно через файлы в `/etc/sysctl.d/*.conf` (применяются `systemd-sysctl` при загрузке или вручную командой `sysctl --system`). Файл `/proc/sys/net/ipv4/tcp_syncookies` соответствует ключу `net.ipv4.tcp_syncookies` и так далее.

## 2. Разбор параметров

### Защита от SYN flood

**`net.ipv4.tcp_syncookies = 1`**

Когда очередь SYN для слушающего сокета переполняется, ядро перестаёт хранить полуоткрытые соединения и вместо этого кодирует состояние соединения в криптографически подписанные cookie внутри номера последовательности SYN-ACK. Реальный клиент вернёт cookie в своём ACK; флудер обычно нет. Это важнейший штатный регулятор против SYN-флуда в Linux.

- `0` — выключено
- `1` — включено по необходимости
- `2` — всегда слать cookie независимо от состояния очередей (агрессивнее; используйте, только если понимаете последствия, поскольку часть согласования TCP-опций деградирует)

Компромисс: cookie не могут переносить TCP-опции, согласовываемые в handshake (window scaling в Linux сохраняется через расширение syncookie, но SACK/Timestamps могут потеряться), поэтому пропускная способность соединения может слегка упасть. Держите `1` — цена ничтожна в сравнении с гибелью от SYN-флуда на дефолтах.

**`net.ipv4.tcp_max_syn_backlog = 65535`**

Максимум полуоткрытых (SYN получен, ACK ещё нет) соединений в очереди **на каждый слушающий сокет**, прежде чем ядро начнёт дропать SYN или включать syncookies. По умолчанию часто 128–1024 в зависимости от версии ядра и `net.core.somaxconn`. Увеличение позволяет всплеску легитимных клиентов пройти без немедленного перехода в cookie-режим. Цена: каждая SYN в очереди потребляет немного памяти (структура request_sock) — растёт расход RAM, больше почти ничего.

**`net.ipv4.tcp_synack_retries = 2`** и **`net.ipv4.tcp_syn_retries = 2`**

Сколько раз ядро ретранслирует SYN-ACK (сервер) / SYN (клиент) без ответа, прежде чем сдаться. Меньшие значения быстрее вычищают мёртвые полуоткрытые соединения, освобождая слоты backlog'а во время флуда. Дефолтные 5–6 означают, что мёртвое соединение висит больше минуты; значение `2` сокращает это до секунд.

### Очереди прослушивания

**`net.core.somaxconn = 65535`**

Верхняя граница *accept*-очереди (полностью установленные соединения, ожидающие вызова `accept()` приложением) каждого слушающего сокета. Критично: приложение тоже должно запросить большой backlog (второй аргумент `listen()`); эффективное значение — `min(somaxconn, backlog_приложения)`. Если прокси принимает медленнее, чем клиенты подключаются, переполненная accept-очередь вызывает тихие дропы SYN или reset'ы — поднятие одного лишь `somaxconn` ничего не даст, если приложение запрашивает 128.

**`net.ipv4.tcp_abort_on_overflow = 0`**

Оставьте `0` (дефолт): при переполнении accept-очереди ядро молча дропает SYN, позволяя клиентам корректно повторить попытку. Значение `1` шлёт RST немедленно — полезно для fail-fast нагрузочных тестов, вредно в продакшене.

### Приём пакетов

**`net.core.netdev_max_backlog = 65535`**

Очередь кадров, принятых NIC, но ещё не обработанных циклом softirq (NET_RX) на CPU. Когда всплеск пакетов быстрее, чем CPU успевает разгребать, эта очередь поглощает разницу; переполнение означает дроп пакетов *до* того, как их увидит хоть какая-то логика фильтрации. Дефолт часто 1000 — всплеск в миллионы pps исчерпывает его мгновенно. Компромисс: увеличенный backlog добавляет задержку при устойчивой перегрузке и держит больше памяти; он покупает время для разгребающего, но никогда не заменяет саму фильтрацию.

**`net.core.rmem_max` / `net.core.wmem_max`**

Потолок размеров буферов приёма/отправки сокетов, которые приложения могут запросить через SO_RCVBUF/SO_SNDBUF (и лимиты автотюнинга через третьи значения `tcp_rmem`/`tcp_wmem`). Для высокопроизводительных прокси, гоняющих объёмные данные, потолки 16–128 МБ обычны; для чистого drop/throttle-edge они мало что меняют.

### Эфемерные порты и churn соединений

**`net.ipv4.ip_local_port_range = 1024 65535`**

Диапазон исходящих портов для исходящих соединений. Когда нода выступает клиентом — например, edge-прокси открывает апстрим-соединения к бэкендам, — каждое одновременное исходящее соединение занимает один кортеж (src IP, src порт, dst IP, dst порт). Старый дефолт `32768 60999` даёт ~28 тыс. портов; расширение до полного диапазона — ~64 тыс. на кортеж назначения. В паре с:

**`net.ipv4.tcp_fin_timeout = 15`** (дефолт 60)

Секунды, которые сокет висит в FIN-WAIT-2 после закрытия пиром. Долгое ожидание связывает кортежи и fd во время churn-атак (паттерны connect-flood). Снижение до 10–30 ускоряет очистку. Заметьте: это **не влияет** на длительность TIME_WAIT (она фиксирована ~60 с, косвенно управляется через `tcp_tw_reuse`).

**`net.ipv4.tcp_tw_reuse = 1`**

Разрешает переиспользование сокетов в TIME_WAIT для *исходящих* соединений, когда timestamps делают это безопасным. Помогает, когда ограничением является нехватка портов, а не памяти.

### Conntrack

**`net.netfilter.nf_conntrack_max`**

Максимальное число отслеживаемых соединений в таблице conntrack. Актуально только при stateful-фильтрации (nftables/iptables с `-m conntrack`, NAT). Флуд соединений может заполнить таблицу; после этого дропаются уже и новые легитимные соединения. Размер: ожидаемый пик одновременных соединений × коэффициент запаса (2–4). Каждая запись стоит примерно 300 байт, значит 1 млн записей ≈ 300 МБ.

**`net.netfilter.nf_conntrack_buckets`**

Число корзин хеш-таблицы (задаётся при загрузке модуля, потом read-only). Правило большого пальца: `conntrack_max / 4`. Если conntrack на выделенном edge вообще не нужен — полное отключение модулей экономит и память, и CPU на каждом пакете.

## 3. Готовый конфиг

`/etc/sysctl.d/ddos.conf`:

```ini
# /etc/sysctl.d/ddos.conf
# Устойчивость ядра к объёмным атакам L3/L4.
# Применить: sudo sysctl --system

# --- SYN flood ---
# SYN cookies при переполнении очереди полуоткрытых.
net.ipv4.tcp_syncookies = 1
# Более глубокая очередь полуоткрытых на каждый слушающий сокет.
net.ipv4.tcp_max_syn_backlog = 65535
# Быстро отказываться от мёртвых handshake.
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# --- Очереди accept ---
# Разрешить приложениям большие listen-backlog.
net.core.somaxconn = 65535
# НЕ сбрасывать клиентов при переполнении очереди (мягкий retry).
net.ipv4.tcp_abort_on_overflow = 0

# --- Буферизация входа ---
# Поглощать всплески между IRQ сетевой карты и обработкой softirq.
net.core.netdev_max_backlog = 65535
# Потолки буферов сокетов для объёмной передачи.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# --- Churn исходящих соединений (edge → бэкенд) ---
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# --- Conntrack (только при stateful-правилах) ---
# 1 млн отслеживаемых соединений, ~300 МБ RAM.
net.netfilter.nf_conntrack_max = 1048576
# Сократить таймаут полуоткрытых записей.
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30

# --- Опционально: заглушить ICMP flood ---
# net.ipv4.icmp_echo_ignore_all = 1
```

Применить и проверить:

```bash
sudo sysctl --system
sysctl net.ipv4.tcp_syncookies net.core.somaxconn net.core.netdev_max_backlog
# Убедиться, что app-side backlog совпадает:
ss -lnt   # колонка Recv-Q показывает текущее использование accept-очереди против лимита на LISTEN-сокетах
```

## 4. Компромиссы и предупреждения

1. **Большие очереди ≠ защита.** Глубокие backlog'и покупают секунды поглощения. Без раннего отсечения (XDP/nftables) они лишь откладывают коллапс и давят на память. Тюнинг поднимает потолок, но не устраняет атаку.
2. **Учёт памяти.** `tcp_max_syn_backlog=65535` × число слушающих портов × размер request_sock, плюс conntrack по ~300 Б/запись — посчитайте под свою VDS. На машине со 2 ГБ не ставьте conntrack_max в 4M.
3. **Задержка при перегрузке.** Большой `netdev_max_backlog` означает, что пакеты ждут дольше в softirq-очередях именно тогда, когда система уже перегружена — хвостовая задержка растёт, даже хотя дропов меньше.
4. **Кооперация приложения.** `somaxconn` — только потолок. Эффективный backlog — то, что приложение передаёт в `listen()`. Проверяйте через `ss -lnt`.
5. **Conntrack опционален.** Выделенный edge с stateless XDP-дропами и юзерспейс-верификацией может вообще обходиться без conntrack; грузить его ради больших таблиц — тратить CPU на каждом пакете.
6. **Тестируйте изменения под нагрузкой**, а не только `sysctl --system`. Параметр, выглядящий безобидно, может радикально поменять поведение на 100 тыс. pps (см. stress-testing.md).
