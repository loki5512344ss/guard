# Rampart

**Универсальная платформа сетевой защиты: L3/L4/L7-фильтрация DDoS для VDS, веб-сервисов и игровых серверов.**

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
![eBPF](https://img.shields.io/badge/C%2FeBPF%20XDP-FF6C37?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-GPLv3-blue?style=flat-square&logo=gnu&logoColor=white)
![Version](https://img.shields.io/badge/version-0.3.0--dev-green?style=flat-square)
![Status](https://img.shields.io/badge/status-development-yellow?style=flat-square)

[![Docs](https://img.shields.io/badge/docs-index-blue?style=for-the-badge&logo=readthedocs&logoColor=white)](docs/README.md)
[![Quick start](https://img.shields.io/badge/quick%20start-2%20minutes-success?style=for-the-badge)](#быстрый-старт)
[![Configuration](https://img.shields.io/badge/configuration-config.toml-yellow?style=for-the-badge)](docs/configuration.md)
[![API](https://img.shields.io/badge/API-manager-purple?style=for-the-badge&logo=openapiinitiative&logoColor=white)](docs/api.md)
[![License](https://img.shields.io/badge/license-GPLv3-lightgrey?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)

[Русский](#русский) · [English](#english)

> **Статус:** проект в активной разработке — API и числа производительности могут меняться.

---

## Русский

[Обзор](#обзор) · [Возможности](#возможности) · [Требования](#требования) · [Установка](#установка) · [Быстрый старт](#быстрый-старт) · [Конфигурация](#конфигурация) · [Плагины](#протокол-плагины) · [Производительность](#производительность) · [Документация](#документация) · [Разработка](#разработка) · [Лицензия](#лицензия)

### Обзор

Rampart отбрасывает атакующий трафик до того, как он дойдёт до вашего сервиса.
Фильтрация идёт в три уровня: XDP/eBPF в ядре, PoW-challenge в userspace и
L7-анализ протокола. Логика конкретного протокола вынесена в плагины, поэтому
одна платформа защищает и веб-сервис, и игровой сервер.

Подходит, если нужен свой edge-фильтр на VDS: без покупки «коробки», с
конфигом в TOML и метриками в Prometheus.

**Как это работает**

```
Атакующий → [XDP/eBPF] → [PoW] → [Userspace Core] → [Плагин] → Ваш сервис
                1          2           3                4
```

| Уровень | Что делает | Стек |
|---------|------------|------|
| **1. Ядро / XDP** | Дроп пакетов до стека Linux: TCP state machine, SYN-throttle, CIDR blacklist/whitelist, UDP policy, IPv4 + IPv6 | C, eBPF |
| **2. PoW challenge** | Повышает цену флуда соединений для любого TCP-протокола (по умолчанию выключен) | Rust, SHA-256 hashcash |
| **3. Userspace core** | L7-handshake, rate limit, репутация, профилирование трафика | Rust, tokio |
| **4. Протокол-плагины** | Разбор и фильтрация конкретного протокола | Rust (feature crates) |

### Возможности

- **XDP-фильтр в ядре** — blacklist/whitelist CIDR, SYN-throttle, детект поддельных
  TCP-флагов, UDP policy (`pass` / `drop` / `rate-limit`), prefix-статистика.
- **IPv4 и IPv6** — отдельные LPM-таблицы для обоих семейств: баны по `/32` и `/128`,
  UDP rate-limit с 128-битным ключом, детект TCP-bypass, статистика по `/24` и `/64`.
- **PoW-challenge** — hashcash с динамической сложностью, работает поверх любого TCP.
- **Протокол-плагины** — HTTP/1.1 и Minecraft Java, API плагинов стабилизируется.
- **Ringbuf-события и авто-бан** — события из ядра в userspace, opt-in авто-бан по
  rate-limit и обрывам соединений.
- **Управление и наблюдаемость** — Prometheus-метрики, management API + Redis-синхронизация,
  CLI и TUI-дашборд.
- **Traffic Intel** — EWMA-пороги, профилирование и репутация поверх всех уровней.

### Требования

| Компонент | Требование |
|-----------|------------|
| Rust | 1.85+ (edition 2024) |
| XDP | Linux 5.10+, `clang` с `-target bpf`, `libbpf`/`libelf` |
| Опционально | Redis (синхронизация блэклиста), ClickHouse (события), GeoIP-база |

### Установка

```bash
# Сборка edge-ноды с HTTP-обработчиком
cargo build --release --features protocol-http

# Конфиг: путь по умолчанию /etc/rampart/config.toml,
# переопределяется переменной $RAMPART_CONFIG
sudo mkdir -p /etc/rampart
sudo cp deploy/config/edge-http.toml /etc/rampart/config.toml
```

С XDP-фильтром (нужен root либо `CAP_BPF` + `CAP_NET_ADMIN`):

```bash
cargo build --release --features protocol-http,xdp
```

### Быстрый старт

```bash
RAMPART_CONFIG=/etc/rampart/config.toml ./target/release/rampart
```

В конфиге для XDP: `[xdp] enabled = true`, `interface = "eth0"`. Метрики —
`http://127.0.0.1:9090/metrics`.

Проверить чекаут перед изменениями:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Конфигурация

```toml
[bind]
address = "0.0.0.0"
port = 25565

[backend]
upstreams = ["127.0.0.1:25566"]

[xdp]
enabled = false          # требует сборки с feature `xdp`
interface = "eth0"
udp_policy = "pass"      # pass | drop | rate-limit
```

Все поля и значения по умолчанию — [docs/configuration.md](docs/configuration.md).

### Протокол-плагины

| Плагин | Feature | Что даёт |
|--------|---------|----------|
| HTTP/1.1 | `protocol-http` | Парсинг request-head, вердикт Allow/Reject, туннель на upstream |
| Minecraft Java | `protocol-minecraft` | TCP-handshake, туннель на Paper (включая PROXY protocol) |
| gRPC | план | — |

Minecraft-edge: `cargo build --release --features protocol-minecraft --bin rampart`,
конфиг — `deploy/config/edge.toml`, инструкция — [docs/minecraft-java.md](docs/minecraft-java.md).
Rampart не спасёт уже забитый домашний канал: перед edge нужен игровой прокси или
провайдер с фильтрацией DDoS.

### Производительность

Только подтверждённые замеры — VDS stress test, edge-only на loopback, 2 vCPU
([отчёт](docs/research/load-test-report.md)):

| Сценарий | Результат |
|----------|-----------|
| Пропускная способность L7 | ~4k conn/s |
| Маскированный flood с 100 IP (5 pps/IP) | **99.6% заблокировано**, легитимные клиенты работают |
| SYN flood без XDP | обрабатывается ядром |

Полный набор бенчмарков — в работе.

### Документация

| Раздел | Где |
|--------|-----|
| Индекс всей документации | [docs/README.md](docs/README.md) |
| Деплой | [docs/deployment.md](docs/deployment.md) |
| Конфигурация | [docs/configuration.md](docs/configuration.md) |
| Эксплуатация (runbook) | [docs/runbook.md](docs/runbook.md) |
| Диагностика | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Тестирование | [docs/testing.md](docs/testing.md) |
| API manager'а | [docs/api.md](docs/api.md) |
| База знаний (атаки, защита, практика) | [docs/kb/](docs/kb/) |
| Research: архитектура, eBPF, DDoS | [docs/research/](docs/research/) |

### Разработка

- Правила кода и Definition of Done — [TODO.md](TODO.md) (§0).
- Комментарии в коде — только по-английски, JavaDoc/Rustdoc-стиль (§0.8).
- Тесты живут в `tests/`, без `#[cfg(test)]` в файлах с кодом.
- Перед PR: `cargo fmt`, `cargo clippy -D warnings`, `cargo test --all-features`.

Трекер идей и статус задач — [TODO.md](TODO.md), issues и PR — во вкладках репозитория.

### Лицензия

GNU General Public License v3.0 — [LICENSE](LICENSE).

---

## English

[Overview](#overview) · [Features](#features) · [Requirements](#requirements) · [Installation](#installation) · [Quick start](#quick-start) · [Configuration](#configuration) · [Plugins](#protocol-plugins) · [Performance](#performance) · [Documentation](#documentation) · [Development](#development) · [License](#license)

### Overview

Rampart drops malicious traffic before it reaches your service. Filtering happens
at three levels: XDP/eBPF in the kernel, a proof-of-work challenge in userspace,
and L7 protocol analysis. Protocol-specific logic lives in plugins, so the same
platform protects a web service and a game server alike.

It fits teams that need their own edge filter on a VDS: no appliance to buy, a
TOML config, and Prometheus metrics out of the box.

**How it works**

```
Attacker → [XDP/eBPF] → [PoW] → [Userspace Core] → [Plugin] → Your service
               1          2            3               4
```

| Layer | Responsibility | Stack |
|-------|----------------|-------|
| **1. Kernel / XDP** | Drop packets before the Linux stack: TCP state machine, SYN throttle, CIDR black/white lists, UDP policy, IPv4 + IPv6 | C, eBPF |
| **2. PoW challenge** | Raises the cost of connection floods for any TCP protocol (off by default) | Rust, SHA-256 hashcash |
| **3. Userspace core** | L7 handshake analysis, rate limiting, reputation, traffic profiling | Rust, tokio |
| **4. Protocol plugins** | Protocol-aware parsing and filtering | Rust (feature crates) |

### Features

- **Kernel XDP filter** — CIDR blacklist/whitelist, SYN throttle, forged TCP flag
  detection, UDP policy (`pass` / `drop` / `rate-limit`), per-prefix statistics.
- **IPv4 and IPv6** — separate LPM tables for both families: `/32` and `/128` bans,
  UDP rate limiting keyed by the full 128-bit address, TCP bypass detection,
  `/24` and `/64` prefix stats.
- **PoW challenge** — hashcash with dynamic difficulty over any TCP protocol.
- **Protocol plugins** — HTTP/1.1 and Minecraft Java; the plugin API is stabilizing.
- **Ringbuf events and auto-ban** — kernel events delivered to userspace, with
  opt-in auto-ban on rate limits and connection drops.
- **Operations** — Prometheus metrics, management API with Redis sync, CLI and a
  terminal dashboard.
- **Traffic Intel** — EWMA thresholds, profiling and reputation across all layers.

### Requirements

| Component | Requirement |
|-----------|-------------|
| Rust | 1.85+ (edition 2024) |
| XDP | Linux 5.10+, `clang` with `-target bpf`, `libbpf`/`libelf` |
| Optional | Redis (blacklist sync), ClickHouse (events), GeoIP database |

### Installation

```bash
# Build the edge node with the HTTP handler
cargo build --release --features protocol-http

# Config: default path is /etc/rampart/config.toml,
# override it with $RAMPART_CONFIG
sudo mkdir -p /etc/rampart
sudo cp deploy/config/edge-http.toml /etc/rampart/config.toml
```

With the XDP filter (root or `CAP_BPF` + `CAP_NET_ADMIN`):

```bash
cargo build --release --features protocol-http,xdp
```

### Quick start

```bash
RAMPART_CONFIG=/etc/rampart/config.toml ./target/release/rampart
```

For XDP set `[xdp] enabled = true` and `interface = "eth0"`. Metrics are served
at `http://127.0.0.1:9090/metrics`.

Verify the checkout before making changes:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Configuration

```toml
[bind]
address = "0.0.0.0"
port = 25565

[backend]
upstreams = ["127.0.0.1:25566"]

[xdp]
enabled = false          # requires the `xdp` feature
interface = "eth0"
udp_policy = "pass"      # pass | drop | rate-limit
```

Every field and its default: [docs/configuration.md](docs/configuration.md).

### Protocol plugins

| Plugin | Feature | Provides |
|--------|---------|----------|
| HTTP/1.1 | `protocol-http` | Request-head parsing, Allow/Reject verdict, upstream tunnel |
| Minecraft Java | `protocol-minecraft` | TCP handshake, tunnel to Paper (PROXY protocol supported) |
| gRPC | planned | — |

Minecraft edge: `cargo build --release --features protocol-minecraft --bin rampart`,
config in `deploy/config/edge.toml`, guide in
[docs/minecraft-java.md](docs/minecraft-java.md). Rampart cannot rescue an already
saturated home uplink: put a game proxy or a DDoS-filtering provider in front.

### Performance

Confirmed numbers only — VDS stress test, edge-only on loopback, 2 vCPU
([report](docs/research/load-test-report.md)):

| Scenario | Result |
|----------|--------|
| L7 throughput | ~4k conn/s |
| Masked 100-IP handshake flood (5 pps/IP) | **99.6% blocked**, legitimate clients unaffected |
| SYN flood without XDP | handled by the kernel |

The full benchmark suite is in progress.

### Documentation

| Topic | Where |
|-------|-------|
| Documentation index | [docs/README.md](docs/README.md) |
| Deployment | [docs/deployment.md](docs/deployment.md) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Operations runbook | [docs/runbook.md](docs/runbook.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Testing | [docs/testing.md](docs/testing.md) |
| Manager API | [docs/api.md](docs/api.md) |
| Knowledge base | [docs/kb/](docs/kb/) |
| Research notes | [docs/research/](docs/research/) |

### Development

- Coding rules and Definition of Done: [TODO.md](TODO.md) (§0).
- Code comments are English only, JavaDoc/Rustdoc style (§0.8).
- Tests live in `tests/`; no `#[cfg(test)]` modules in code files.
- Before a PR: `cargo fmt`, `cargo clippy -D warnings`, `cargo test --all-features`.

Roadmap and task status live in [TODO.md](TODO.md); issues and PRs are in the
repository tabs.

### License

GNU General Public License v3.0 — [LICENSE](LICENSE).
