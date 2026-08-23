# NIC Tuning: Queues, IRQ Affinity, Ring Buffers, Offloads

> Knowledge Base · Practice
>
> The network interface card is the first CPU consumer on the packet's path. A single-queue NIC feeding one core caps your entire defense at whatever that core can process; misconfigured offloads silently corrupt or slow traffic. This article covers multiqueue setup, receive-side scaling, interrupt distribution, ring buffers, and offload switches — with commands you can run to verify each step.

## English

## 1. Multiqueue NICs (ethtool -L)

Modern NICs expose multiple hardware RX/TX queues, each with its own interrupt. The kernel spreads packets across queues using a hash of header fields (RSS). If only 1 combined channel is active, all packets — including millions of flood packets — hit a single core.

```bash
# Show current queue count and max supported
ethtool -l eth0

# Example output:
# Channel parameters for eth0:
# Pre-set maximums:
# RX:             8
# TX:             8
# Other:          1
# Combined:       8
# Current hardware settings:
# RX:             1
# TX:             1
# Other:          1
# Combined:       1     <-- everything lands on one queue!

# Raise combined channels (RX+TX share) to maximum
sudo ethtool -L eth0 combined 8

# Or set RX/TX separately if the card distinguishes them
sudo ethtool -L eth0 rx 4 tx 4
```

On virtual machines (virtio), the number of queues is bounded by `queues` in the VM configuration and vCPUs available; match queues to vCPU count.

## 2. RSS / RPS / XPS

Three mechanisms with confusingly similar names:

| Mechanism | Layer | What it does | Configured via |
|---|---|---|---|
| **RSS** (Receive Side Scaling) | Hardware | NIC hashes packet headers → picks RX queue → raises that queue's IRQ | `ethtool -x eth0` (view), `ethtool -X eth0` (set indirection table) |
| **RPS** (Receive Packet Steering) | Software kernel | Same idea as RSS but done in software after the driver receives the packet — for NICs/queues without RSS or to spread further | sysfs per RX queue |
| **XPS** (Transmit Packet Steering) | Software kernel | Picks TX queue matching the transmitting CPU, keeping flow locality | sysfs per TX queue |

```bash
# View RSS indirection table and hash key
ethtool -x eth0

# Steer queues across CPUs evenly (example for 4 queues)
sudo ethtool -X eth0 equal 4

# Enable RPS on the first RX queue: point it at CPUs 2-3 (mask 0xc = bits 2,3)
echo c | sudo tee /sys/class/net/eth0/queues/rx-0/rps_cpus

# Check whether RPS is actually spreading (counters per CPU)
cat /proc/net/softnet_stat   # column 2 = dropped at softirq, column 10+ depend on kernel version

# XPS: steer tx-0 to CPU 0 (mask 0x1)
echo 1 | sudo tee /sys/class/net/eth0/queues/tx-0/xps_cpus
```

Rule of thumb: prefer RSS when the hardware supports it; add RPS only where hardware queues < cores; XPS matters mainly for high-throughput *outgoing* paths.

## 3. IRQ affinity

Each RX queue generates interrupts. By default, the kernel may route them all to CPU0 — creating a hotspot exactly where your XDP program will also run.

```bash
# See how interrupts are currently distributed
grep eth0 /proc/interrupts

# List IRQ numbers of the NIC queues
grep -E 'eth0.*TxRx' /proc/interrupts | awk '{print $1}' | tr -d ':'

# Pin IRQ 41 to CPU 2 (mask is a hex bitmask)
echo 2 | sudo tee /proc/irq/41/smp_affinity

# Pin IRQ 42 to CPU 3, etc.
echo 4 | sudo tee /proc/irq/42/smp_affinity
```

Notes:

- `smp_affinity` is a hexadecimal bitmask: `1`=CPU0, `2`=CPU1, `4`=CPU2, `c`=CPU2+CPU3, `ff`=first 8 CPUs.
- On systems with irqbalance daemon running, it may override manual pinning — stop/mask it (`systemctl stop irqbalance`) or configure exclusions.
- For NAPI-driven high pps, interrupts coalesce into softirq processing; check `mpstat -P ALL 1` — `%soft` shows which CPUs are doing network work.
- Common strategy for an edge node: dedicate some cores to network softirq/XDP and others to userspace application threads, so a flood saturating softirq does not starve the proxy logic.

## 4. Ring buffer size

The RX ring is on-NIC memory where received descriptors wait for the driver. Too small → drops under bursts; too large → latency and memory waste.

```bash
# View current and maximum ring sizes
ethtool -g eth0

# Example output:
# Ring parameters for eth0:
# Pre-set maximums:
# RX:             4096
# TX:             4096
# Current hardware settings:
# RX:             256    <-- small, drops under burst
# TX:             256

# Set RX ring to max
sudo ethtool -G eth0 rx 4096
```

Verify drops directly:

```bash
ip -s link show eth0        # look at "dropped" counter
ethtool -S eth0 | grep -i drop   # per-hardware-counter view
netstat -i                  # alternative overview
```

## 5. Offloads: GRO / TSO / LRO / checksumming

Offloads let the NIC or driver merge/split segments and compute checksums, cutting CPU per byte for bulk traffic:

- **GRO** (Generic Receive Offload): merges received segments into large skbs in software.
- **LRO** (Large Receive Offload): same in hardware — breaks forwarding/routing because merged skbs lose MAC/IP details; never enable on routers/proxies.
- **TSO** (TCP Segmentation Offload): NIC splits large outgoing buffers into MSS-sized segments.
- **RX/TX checksum offload**: NIC validates/computes checksums.

```bash
# View all offloads
ethtool -k eth0

# Toggle examples
sudo ethtool -K eth0 gro on
sudo ethtool -K eth0 tso on
sudo ethtool -K eth0 lro off      # usually already off; keep it off on proxies
```

**When to turn GRO/TSO OFF:** when running XDP programs that must inspect individual packets, aggressive GRO merging changes what your eBPF sees (merged super-packets on the generic XDP path). Also consider disabling during packet-rate benchmarking, since merging hides the true pps cost. Keep them ON for normal bulk throughput workloads — they save substantial CPU.

## 6. Verifying load distribution

```bash
# Per-CPU softirq utilization, refresh every second
mpstat -P ALL 1

# Interrupt counters per CPU (watch eth0 lines move)
watch -n1 'grep eth0 /proc/interrupts'

# Softirq backlog / drops per CPU
cat /proc/net/softnet_stat
# columns: processed | dropped | time_squeeze ...

# Kernel-side packet drops summary
ip -s link
dropwatch -l 1   # if installed: live trace of where kernel drops packets
```

Healthy picture on a tuned edge: `%soft` spread over several cores rather than 100% on one; `dropped` in `/proc/net/softnet_stat` stays near zero except during deliberate overload tests; NIC-level `dropped` grows only when the attack exceeds what early filtering absorbs.

## 7. Persistence

All `ethtool` and sysfs settings are volatile. Persist them via a systemd unit, a network dispatcher script (`/etc/network/if-up.d/`), NetworkManager dispatcher, or netplan `set-link` options depending on your distro.

---
---

## Русский

# Тюнинг NIC: очереди, привязка IRQ, кольцевые буферы, offload'ы

> Knowledge Base · Практика
>
> Сетевая карта — первый потребитель CPU на пути пакета. Одноочередевой NIC, кормящий одно ядро, ограничивает всю вашу защиту тем, что успеет это ядро; неверно настроенные offload'ы молча портят или замедляют трафик. Статья охватывает настройку multiqueue, масштабирование приёма, распределение прерываний, кольцевые буферы и переключатели offload — с командами для проверки каждого шага.

## 1. Multiqueue NIC (ethtool -L)

Современные NIC предоставляют несколько аппаратных очередей RX/TX, у каждой своё прерывание. Ядро распределяет пакеты по очередям через хеш полей заголовков (RSS). Если активен только 1 combined-канал, все пакеты — включая миллионы пакетов флуда — попадают на одно ядро.

```bash
# Показать текущее число очередей и максимум
ethtool -l eth0

# Пример вывода:
# Channel parameters for eth0:
# Pre-set maximums:
# RX:             8
# TX:             8
# Other:          1
# Combined:       8
# Current hardware settings:
# RX:             1
# TX:             1
# Other:          1
# Combined:       1     <-- всё валится в одну очередь!

# Поднять combined-каналы (общие RX+TX) до максимума
sudo ethtool -L eth0 combined 8

# Или задать RX/TX по отдельности, если карта их различает
sudo ethtool -L eth0 rx 4 tx 4
```

На виртуальных машинах (virtio) число очередей ограничено параметром `queues` в конфигурации ВМ и числом vCPU; согласуйте количество очередей с числом vCPU.

## 2. RSS / RPS / XPS

Три механизма с путающими названиями:

| Механизм | Уровень | Что делает | Настраивается через |
|---|---|---|---|
| **RSS** (Receive Side Scaling) | Железо | NIC хеширует заголовки пакета → выбирает RX-очередь → поднимает её IRQ | `ethtool -x eth0` (просмотр), `ethtool -X eth0` (таблица indirection) |
| **RPS** (Receive Packet Steering) | Софт ядра | Та же идея, что RSS, но программно после приёма драйвером — для карт/очередей без RSS или для дальнейшего распределения | sysfs на каждую RX-очередь |
| **XPS** (Transmit Packet Steering) | Софт ядра | Выбирает TX-очередь, соответствующую передающему CPU, сохраняя локальность потока | sysfs на каждую TX-очередь |

```bash
# Посмотреть таблицу indirection и хеш-ключ RSS
ethtool -x eth0

# Равномерно раскидать очереди по CPU (пример для 4 очередей)
sudo ethtool -X eth0 equal 4

# Включить RPS на первой RX-очереди: направить на CPU 2-3 (маска 0xc = биты 2,3)
echo c | sudo tee /sys/class/net/eth0/queues/rx-0/rps_cpus

# Проверить, реально ли RPS распределяет (счётчики по CPU)
cat /proc/net/softnet_stat   # колонка 2 = дропы в softirq

# XPS: направить tx-0 на CPU 0 (маска 0x1)
echo 1 | sudo tee /sys/class/net/eth0/queues/tx-0/xps_cpus
```

Правило большого пальца: предпочитайте RSS, если железо умеет; добавляйте RPS там, где аппаратных очередей меньше числа ядер; XPS важен прежде всего для высокопроизводительных *исходящих* путей.

## 3. Привязка IRQ (IRQ affinity)

Каждая RX-очередь генерирует прерывания. По умолчанию ядро может направить их все на CPU0 — создавая горячую точку ровно там, где будет работать и ваша XDP-программа.

```bash
# Как сейчас распределены прерывания
grep eth0 /proc/interrupts

# Номера IRQ очередей NIC
grep -E 'eth0.*TxRx' /proc/interrupts | awk '{print $1}' | tr -d ':'

# Привязать IRQ 41 к CPU 2 (маска — hex-битовая маска)
echo 2 | sudo tee /proc/irq/41/smp_affinity

# Привязать IRQ 42 к CPU 3 и т.д.
echo 4 | sudo tee /proc/irq/42/smp_affinity
```

Замечания:

- `smp_affinity` — шестнадцатеричная битовая маска: `1`=CPU0, `2`=CPU1, `4`=CPU2, `c`=CPU2+CPU3, `ff`=первые 8 CPU.
- Если работает демон irqbalance, он может перезаписать ручную привязку — остановите/замаскируйте его (`systemctl stop irqbalance`) или настройте исключения.
- При высоких pps обработка через NAPI сворачивает прерывания в обработку softirq; проверяйте `mpstat -P ALL 1` — колонка `%soft` показывает, какие CPU занимаются сетью.
- Частая стратегия для edge-ноды: выделить часть ядер под сетевой softirq/XDP, остальные — под потоки userspace-приложения, чтобы флуд, забивающий softirq, не душил логику прокси.

## 4. Размер кольцевого буфера

RX-ring — память на NIC, где принятые дескрипторы ждут драйвера. Слишком мал → дропы при всплесках; слишком велик → задержки и лишний расход памяти.

```bash
# Текущие и максимальные размеры ring
ethtool -g eth0

# Пример вывода:
# Ring parameters for eth0:
# Pre-set maximums:
# RX:             4096
# TX:             4096
# Current hardware settings:
# RX:             256    <-- мало, дропы при всплесках
# TX:             256

# Поставить RX ring на максимум
sudo ethtool -G eth0 rx 4096
```

Дропы проверяются напрямую:

```bash
ip -s link show eth0        # смотреть счётчик "dropped"
ethtool -S eth0 | grep -i drop   # вид по аппаратным счётчикам
netstat -i                  # альтернативный обзор
```

## 5. Offload'ы: GRO / TSO / LRO / контрольные суммы

Offload'ы позволяют NIC или драйверу склеивать/делить сегменты и считать чексуммы, снижая расход CPU на байт для объёмного трафика:

- **GRO** (Generic Receive Offload): склеивает принятые сегменты в крупные skb программно.
- **LRO** (Large Receive Offload): то же аппаратно — ломает маршрутизацию/форвардинг, потому что склеенные skb теряют детали MAC/IP; никогда не включать на роутерах/прокси.
- **TSO** (TCP Segmentation Offload): NIC сам делит большие исходящие буферы на сегменты размера MSS.
- **RX/TX checksum offload**: NIC проверяет/вычисляет чексуммы.

```bash
# Посмотреть все offload'ы
ethtool -k eth0

# Примеры переключения
sudo ethtool -K eth0 gro on
sudo ethtool -K eth0 tso on
sudo ethtool -K eth0 lro off      # обычно уже выключен; на прокси держать выключенным
```

**Когда выключать GRO/TSO:** когда запущены XDP-программы, обязанные видеть отдельные пакеты, агрессивное склеивание GRO меняет то, что видит ваш eBPF (склеенные супер-пакеты на generic-пути XDP). Также подумайте об отключении при бенчмарках частоты пакетов: склейка прячет настоящую стоимость pps. Для обычных объёмных нагрузок держите их включёнными — они заметно экономят CPU.

## 6. Проверка распределения нагрузки

```bash
# Загрузка softirq по CPU, обновление раз в секунду
mpstat -P ALL 1

# Счётчики прерываний по CPU (следим, как двигаются строки eth0)
watch -n1 'grep eth0 /proc/interrupts'

# Очередь softirq / дропы по CPU
cat /proc/net/softnet_stat

# Сводка дропов на стороне ядра
ip -s link
dropwatch -l 1   # если установлен: live-трейс мест дропа в ядре
```

Здоровая картина на настроенном edge: `%soft` распределён по нескольким ядрам, а не 100% на одном; `dropped` в `/proc/net/softnet_stat` держится около нуля вне специальных тестов перегрузки; аппаратный `dropped` растёт только когда атака превышает то, что поглощает раннее отсечение.

## 7. Сохранение настроек

Все настройки `ethtool` и sysfs летучи. Сохраняйте их через systemd unit, скрипт сетевого dispatcher'а (`/etc/network/if-up.d/`), dispatcher NetworkManager или опции `set-link` в netplan — в зависимости от дистрибутива.
