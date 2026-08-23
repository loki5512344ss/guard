# Stress Testing Your Own Infrastructure

> Knowledge Base · Practice
>
> A defense system that has never been attacked is a hypothesis, not a defense. This article covers the standard load-generation tools (hping3, iperf3, wrk/k6), a safe testing methodology, and the metrics that actually tell you whether your protection works. It ends with a real case study from this project.

## English

## 0. Ethics and legality — read first

- **Test only infrastructure you own or have explicit written permission to test.** Launching flood traffic against third-party systems is a crime in most jurisdictions (unauthorized impairment of computer systems), regardless of intent or duration.
- **Never test from cloud providers against targets outside their network without authorization** — most providers prohibit it in ToS and will terminate your account.
- **Use staging environments and loopback/bridge networks.** Everything in this article can be done on a single machine or a private two-node lab.
- Coordinate timing with your team: an unplanned "test" against production is indistinguishable from an outage caused by an attack.
- If you want to study attack traffic safely, generate it yourself against your own stub services — which is exactly what the tools below do.

## 1. The tools and what each one measures

| Tool | Attack/load type | Layer | What you learn |
|---|---|---|---|
| **hping3** | SYN flood, UDP flood, ICMP flood, flag-abuse | L3/L4 | How kernel + early filters behave under packet floods |
| **iperf3** | Bulk TCP/UDP throughput | L4 | Bandwidth ceiling of NIC/tunnel/kernel path |
| **wrk** | HTTP keep-alive requests | L7 | Request rate and latency of an HTTP endpoint under sustained load |
| **k6** | Scripted HTTP/API scenarios (JS) | L7 | Realistic user flows, thresholds, gradual ramp-up |
| **tcpkali** | Raw TCP connections/sec | L4/L7 | Connection-rate limits of a custom TCP service |

## 2. hping3 — L3/L4 floods

```bash
# Install
sudo apt install hping3

# SYN flood at full speed toward YOUR OWN server
# (run from a second machine or VM, not the target itself)
sudo hping3 -S --flood -p 443 TARGET_IP

# SYN flood with randomized source addresses — exercises
# anti-spoofing, syncookies, per-prefix throttling
sudo hping3 -S --flood -p 443 --rand-source TARGET_IP

# UDP flood (bandwidth-style)
sudo hping3 --udp --flood -p 53 TARGET_IP

# Invalid flag combination (SYN+FIN) — should be dropped by any sane filter
sudo hping3 -S -F -p 443 TARGET_IP

# Slower, controlled rate instead of --flood (packets per second)
sudo hping3 -S -p 443 --interval u1000 TARGET_IP   # ~1000 pps
```

Observe the effect while it runs:

```bash
watch -n1 'ss -s'                       # socket summary: timewait/synrecv counts
watch -n1 'cat /proc/net/netstat | grep -A1 TcpExt:'   # SYN cookies sent, etc.
nstat -az | grep -i syn                 # SynCookiesSent, ListenDrops counters
ip -s link                              # interface-level drops
```

`netstat -s` / `nstat` output worth knowing:

- `SYNs to LISTEN sockets dropped` — accept/SYN backlog overflowed
- `SYN cookies sent` — syncookie mode engaged (see kernel-tuning.md)

## 3. iperf3 — bandwidth

```bash
# Server side (target machine)
iperf3 -s

# Client side: TCP upload for 30 seconds
iperf3 -c TARGET_IP -t 30

# Parallel streams to saturate path
iperf3 -c TARGET_IP -t 30 -P 8

# UDP at fixed rate (e.g., 500 Mbit) with loss/jitter report
iperf3 -c TARGET_IP -u -b 500M -t 30

# Reverse direction (server sends to client)
iperf3 -c TARGET_IP -t 30 -R
```

What to look for: achieved throughput vs link capacity, UDP `lost/datagrams` ratio (packet loss under load), retransmits on TCP runs (`sender retransmits`). If a "protected" path shows far lower throughput than the bare one, your filter may be over-dropping legitimate bulk traffic.

## 4. wrk / k6 — L7 load

```bash
# wrk: 200 connections, 8 threads, 30 seconds against your own endpoint
wrk -t8 -c200 -d30s http://TARGET_IP/

# With a latency distribution summary
wrk -t8 -c200 -d30s --latency http://TARGET_IP/

# Custom request via Lua script file (POST example): wrk -s script.lua ...
```

```bash
# k6: scripted scenario with ramping virtual users
k6 run --vus 50 --duration 60s script.js
```

Minimal k6 script (`script.js`):

```javascript
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 100 },  // ramp to 100 VUs
    { duration: '60s', target: 100 },
    { duration: '30s', target: 0 },    // ramp down
  ],
};

export default function () {
  const res = http.get('http://TARGET_IP/');
  check(res, { 'status is 200': (r) => r.status === 200 });
}
```

L7 generators answer a different question than hping3: not "does the pipe survive" but "does the application logic stay correct and fast when many clients hammer valid-looking requests".

## 5. Methodology

### Environment rules

1. **Staging or isolated lab first.** Two VMs/VDS on the same internal network, or Docker bridge networks — never production.
2. **Load source separate from target.** Generating flood on the same box as the defense skews every number (shared CPU, shared softirq).
3. **Baseline before defense**: measure how the unprotected service dies. Only then can you prove the defense changed anything.
4. **One variable at a time**, minimum 3 runs, take the median; warm up ~10 s before counting.
5. **Record the environment**: kernel version, CPU model/count, RAM, NIC type (virtio vs physical), queue settings from nic-tuning.md.

### Metrics that matter

| Metric | Command / source | Healthy signal |
|---|---|---|
| Packet rate (pps) | `sar -n DEV 1`, `ethtool -S` | Matches generator's intended rate |
| Bitrate | `sar -n DEV 1`, `iftop` | Within link budget |
| CPU softirq % | `mpstat -P ALL 1` (`%soft`) | Spread across cores, not pegged on one |
| Interface drops | `ip -s link` | Grows during attack *only* if that's your drop policy |
| Socket states | `ss -s` | No runaway TIME_WAIT/SYN-RECV accumulation |
| Kernel drop reasons | `nstat -az`, `dropwatch` | Drops attributable to intended filters |
| App-level allowed/blocked | Your service metrics (e.g., Prometheus `/metrics`) | Block ratio rises under attack; legit clients still pass |
| Legit-client latency | Separate probe client measuring RTT | Stays within SLO during the attack |

The last two rows are the crucial ones: a defense that blocks everything including real users has failed.

### Interpreting results

- **Blocked ratio high + legit RTT stable** → defense works.
- **Everything blocked** → filter too aggressive (check thresholds).
- **Nothing blocked, CPU melts** → attack traffic bypasses your layers; check whether it reaches userspace at all (`mpstat`, XDP drop counters).
- **Generator saturates first** → your numbers measure the generator, not the target. Scale out sources or lower rates.

## 6. Case study: edge-only loopback test on a small VDS (2026-08-04)

Full report: `docs/research/load-test-report.md`; scripts: `deploy/test/stress/`.

Setup: single 2 vCPU / 3.8 GB VDS, Ubuntu 22.04, Docker bridge `172.30.0.0/24`. One container ran the Rampart edge process plus a stub echo backend; another container acted as attacker holding 100 additional source IPs (`172.30.0.101–200`) and generating handshake-shaped L7 floods indistinguishable from real clients at the protocol level. XDP was disabled and PoW disabled — deliberately, so the test measured pure L7 rate limiting + reputation.

Phases:

- **Phase A (limits off)**: raw throughput measurement — ~121.5k handshakes in 30 s (~4.0k conn/s), all proxied; edge CPU peaked ~179% (both cores). Without limits, the same flood also throttled legitimate probe clients (2 of 5 succeeded).
- **Phase B (default per-IP limit 5 pps/IP, burst 10, reputation ban)**: identical flood — **119,376 blocked vs 528 allowed ≈ 99.6% blocked** at max ~32% CPU. All 5 legitimate probe clients passed during the attack with RTT 2.2–5.8 ms; abusive IPs got blacklisted after repeated violations.
- **Phase C (hping3 SYN flood, `--rand-source`)**: no impact on the L7 edge — without XDP, raw SYN handling belongs entirely to the kernel (syncookies/backlog). Confirms the layer separation discussed in defense-levels.md.
- **Phase D (300 kept-open connections)**: all proxied, negligible CPU — steady-state connection holding was limited by the backend stub, not the edge.

Lessons transferable to any project:

1. Always run both phases: **defense off** (find raw ceiling) and **defense on** (prove block ratio + legit availability). Phase B alone would hide the fact that unlimited mode harms real clients.
2. Masked L7 floods (valid protocol payloads from many IPs) are the honest adversary; simple SYN tests only validate the kernel layer.
3. A tiny 2-vCPU box handled the attack at 32% CPU once per-IP limiting engaged — good early-layer filtering buys enormous headroom.
4. Keep a legit probe client running throughout every phase; it is your false-positive alarm.

---
---

## Русский

# Стресс-тестирование собственной инфраструктуры

> Knowledge Base · Практика
>
> Система защиты, которую никогда не атаковали, — это гипотеза, а не защита. Статья охватывает стандартные инструменты генерации нагрузки (hping3, iperf3, wrk/k6), безопасную методику тестирования и метрики, которые реально показывают, работает ли защита. В конце — реальный кейс этого проекта.

## 0. Этика и законность — прочтите сначала

- **Тестируйте только инфраструктуру, которой владеете или на тестирование которой есть явное письменное разрешение.** Запуск флуд-трафика в чужие системы — уголовное преступление в большинстве юрисдикций (несанкционированное нарушение работы компьютерных систем), независимо от намерений и длительности.
- **Никогда не тестируйте из облачных провайдеров против целей вне их сети без разрешения** — большинство провайдеров запрещают это в ToS и блокируют аккаунт.
- **Используйте staging и loopback/bridge-сети.** Всё описанное ниже выполняется на одной машине или в приватной лаборатории из двух узлов.
- Согласуйте время с командой: незапланированный «тест» продакшена неотличим от аварии, вызванной атакой.
- Если хотите безопасно изучать атакующий трафик — генерируйте его сами против собственных заглушек; ровно это и делают инструменты ниже.

## 1. Инструменты и что каждый измеряет

| Инструмент | Тип атаки/нагрузки | Уровень | Что вы узнаёте |
|---|---|---|---|
| **hping3** | SYN flood, UDP flood, ICMP flood, злоупотребление флагами | L3/L4 | Как ведут себя ядро и ранние фильтры под пакетным флудом |
| **iperf3** | Объёмная пропускная способность TCP/UDP | L4 | Потолок пропускной способности пути NIC/туннель/ядро |
| **wrk** | HTTP-запросы поверх keep-alive | L7 | Частота запросов и задержки HTTP-эндпоинта под устойчивой нагрузкой |
| **k6** | Скриптовые HTTP/API-сценарии (JS) | L7 | Реалистичные пользовательские сценарии, пороги, плавный разгон |
| **tcpkali** | Сырые TCP-соединения/сек | L4/L7 | Предел частоты соединений кастомного TCP-сервиса |

## 2. hping3 — флуды L3/L4

```bash
# Установка
sudo apt install hping3

# SYN flood на полной скорости в СВОЙ сервер
# (запускать со второй машины или ВМ, не с самой цели)
sudo hping3 -S --flood -p 443 TARGET_IP

# SYN flood со случайными адресами источника — проверяет
# анти-спуфинг, syncookies, троттлинг по префиксам
sudo hping3 -S --flood -p 443 --rand-source TARGET_IP

# UDP flood (полосно-затратный)
sudo hping3 --udp --flood -p 53 TARGET_IP

# Неверная комбинация флагов (SYN+FIN) — любой адекватный фильтр должен дропнуть
sudo hping3 -S -F -p 443 TARGET_IP

# Медленнее, управляемая скорость вместо --flood (пакетов в секунду)
sudo hping3 -S -p 443 --interval u1000 TARGET_IP   # ~1000 pps
```

Наблюдайте за эффектом во время запуска:

```bash
watch -n1 'ss -s'                       # сводка сокетов: счётчики timewait/synrecv
watch -n1 'cat /proc/net/netstat | grep -A1 TcpExt:'   # отправленные SYN cookies и пр.
nstat -az | grep -i syn                 # счётчики SynCookiesSent, ListenDrops
ip -s link                              # дропы на уровне интерфейса
```

Полезные строки вывода `netstat -s` / `nstat`:

- `SYNs to LISTEN sockets dropped` — переполнение accept/SYN backlog'а
- `SYN cookies sent` — включился режим syncookies (см. kernel-tuning.md)

## 3. iperf3 — полоса пропускания

```bash
# Серверная сторона (целевая машина)
iperf3 -s

# Клиентская сторона: TCP-загрузка 30 секунд
iperf3 -c TARGET_IP -t 30

# Параллельные потоки для насыщения канала
iperf3 -c TARGET_IP -t 30 -P 8

# UDP на фиксированной скорости (например, 500 Мбит) с отчётом о потерях/джиттере
iperf3 -c TARGET_IP -u -b 500M -t 30

# Обратное направление (сервер шлёт клиенту)
iperf3 -c TARGET_IP -t 30 -R
```

На что смотреть: достигнутая полоса против ёмкости линка, отношение `lost/datagrams` по UDP (потери под нагрузкой), ретрансмиты в TCP-прогонах (`sender retransmits`). Если «защищённый» путь показывает заметно меньшую полосу, чем голый, ваш фильтр может перерезать и легитимный объёмный трафик.

## 4. wrk / k6 — нагрузка L7

```bash
# wrk: 200 соединений, 8 потоков, 30 секунд против своего эндпоинта
wrk -t8 -c200 -d30s http://TARGET_IP/

# С разбивкой задержек
wrk -t8 -c200 -d30s --latency http://TARGET_IP/

# Кастомный запрос через Lua-скрипт (пример POST): wrk -s script.lua ...
```

```bash
# k6: скриптовый сценарий с плавным числом виртуальных пользователей
k6 run --vus 50 --duration 60s script.js
```

Минимальный скрипт k6 (`script.js`):

```javascript
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 100 },  // разгон до 100 VU
    { duration: '60s', target: 100 },
    { duration: '30s', target: 0 },    // спуск
  ],
};

export default function () {
  const res = http.get('http://TARGET_IP/');
  check(res, { 'status is 200': (r) => r.status === 200 });
}
```

L7-генераторы отвечают на другой вопрос, нежели hping3: не «выживет ли труба», а «остаётся ли логика приложения корректной и быстрой, когда множество клиентов долбят похожими на настоящие запросами».

## 5. Методика

### Правила окружения

1. **Сначала staging или изолированная лаборатория.** Две ВМ/VDS в одной внутренней сети или docker bridge-сети — никогда продакшен.
2. **Источник нагрузки отдельно от цели.** Генерация флуда на той же машине, где защита, искажает все цифры (общий CPU, общий softirq).
3. **Базлайн до защиты**: замерьте, как умирает незащищённый сервис. Только так можно доказать, что защита что-то изменила.
4. **По одной переменной за раз**, минимум 3 прогона, берём медиану; прогрев ~10 с до начала подсчёта.
5. **Фиксируйте окружение**: версия ядра, модель/число CPU, RAM, тип NIC (virtio против физического), настройки очередей из nic-tuning.md.

### Метрики, которые имеют значение

| Метрика | Команда / источник | Здоровый сигнал |
|---|---|---|
| Частота пакетов (pps) | `sar -n DEV 1`, `ethtool -S` | Совпадает с задуманной скоростью генератора |
| Битрейт | `sar -n DEV 1`, `iftop` | В пределах бюджета линка |
| CPU softirq % | `mpstat -P ALL 1` (`%soft`) | Распределено по ядрам, не упирается в одно |
| Дропы интерфейса | `ip -s link` | Растут при атаке *только* если это ваша политика дропа |
| Состояния сокетов | `ss -s` | Нет неконтролируемого накопления TIME_WAIT/SYN-RECV |
| Причины дропов в ядре | `nstat -az`, `dropwatch` | Дропы объясняются задуманными фильтрами |
| Allowed/blocked на уровне приложения | Метрики сервиса (например, Prometheus `/metrics`) | Доля блокировки растёт под атакой; легитимные клиенты проходят |
| Задержка легитимного клиента | Отдельный пробный клиент, меряющий RTT | Остается в рамках SLO во время атаки |

Последние две строки — решающие: защита, блокирующая всех подряд, включая реальных пользователей, провалилась.

### Интерпретация результатов

- **Высокая доля блокировки + стабильный RTT легитимных** → защита работает.
- **Заблокировано всё** → фильтр слишком агрессивен (проверьте пороги).
- **Ничего не заблокировано, CPU плавится** → атакующий трафик обходит ваши слои; проверьте, доходит ли он вообще до userspace (`mpstat`, счётчики XDP-дропов).
- **Генератор насыщается первым** → вы меряете генератор, а не цель. Масштабируйте источники или снизьте скорость.

## 6. Кейс: edge-only тест на loopback небольшой VDS (2026-08-04)

Полный отчёт: `docs/research/load-test-report.md`; скрипты: `deploy/test/stress/`.

Окружение: одна VDS 2 vCPU / 3.8 ГБ, Ubuntu 22.04, docker bridge `172.30.0.0/24`. Один контейнер запускал процесс Rampart edge плюс stub echo-бэкенд; второй контейнер выступал атакующим с сотней дополнительных IP-источников (`172.30.0.101–200`) и генерировал маскированные под протокол L7-флуды, неотличимые от реальных клиентов на уровне протокола. XDP был выключен и PoW выключен — сознательно, чтобы тест измерял чистый L7: rate limiting + репутацию.

Фазы:

- **Фаза A (лимиты сняты)**: измерение сырой пропускной способности — ~121,5 тыс. хендшейков за 30 с (~4.0 тыс. conn/s), всё проксировано; пик CPU edge ~179% (оба ядра). Без лимитов тот же флуд «душит» и легитимных пробных клиентов (успешны 2 из 5).
- **Фаза B (дефолтный лимит 5 pps/IP, burst 10, репутационный бан)**: идентичный флуд — **119 376 заблокировано против 528 пропущенных ≈ 99,6% blocked** при пике CPU ~32%. Все 5 легитимных пробных клиентов прошли во время атаки с RTT 2.2–5.8 мс; злоупотребляющие IP уходили в блэклист после повторных нарушений.
- **Фаза C (SYN flood через hping3, `--rand-source`)**: влияния на L7 edge нет — без XDP сырая обработка SYN целиком принадлежит ядру (syncookies/backlog). Подтверждает разделение слоёв из defense-levels.md.
- **Фаза D (300 удерживаемых соединений)**: все проксированы, CPU незначителен — удержание соединений в установившемся режиме ограничивал stub-бэкенд, а не edge.

Выводы, переносимые на любой проект:

1. Всегда гоняйте обе фазы: **защита выключена** (находим сырой потолок) и **защита включена** (доказываем долю блокировки и доступность легитимных клиентов). Одна лишь фаза B скрыла бы тот факт, что режим без лимитов вредит реальным клиентам.
2. Маскированные L7-флуды (валидные полезные нагрузки протокола с множества IP) — честный противник; простые SYN-тесты проверяют только слой ядра.
3. Маленькая VDS на 2 vCPU отбивала атаку при 32% CPU, как только включился per-IP лимит — хорошее раннее отсечение покупает огромный запас прочности.
4. Пробный легитимный клиент должен работать на протяжении каждой фазы — это ваш детектор ложных срабатываний.
