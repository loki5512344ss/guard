<div align="center">

> **⚠️ UNDER DEVELOPMENT** — All performance data, benchmarks, and specifications shown are approximate and subject to change.
>
> **⚠️ В РАЗРАБОТКЕ** — Все показатели производительности, тесты и характеристики являются примерными и могут измениться.

</div>

<div align="center">

# Rampart

Universal network protection platform (L3/L4/L7 DDoS filtering framework)

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
![eBPF](https://img.shields.io/badge/C/eBPF%20XDP-FF6C37?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-GPLv3-blue?style=flat-square&logo=gnu&logoColor=white)
![Version](https://img.shields.io/badge/version-0.3.0--dev-green?style=flat-square)
![Status](https://img.shields.io/badge/status-development-yellow?style=flat-square)

[English](#english) | [Русский](#russian)

</div>

---

<a name="english"></a>

## English

### Overview

Rampart filters traffic at three levels before it reaches your service:

- **Kernel level** — XDP/eBPF drops unwanted packets before they reach the Linux TCP stack;
- **Network level** — PoW challenge raises the cost of connection floods for any TCP protocol;
- **Application level** — Rust userspace core performs L7 handshake analysis, rate limiting and reputation checks.

Protocol-specific logic lives in **modular protocol plugins**, so the same platform protects VDS, web services, and game servers alike.

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│  Layer 1: Kernel / XDP (C)                                         │
│    universal TCP state machine · SYN throttle · CIDR black/white   │
│    lists · UDP policy · pluggable BPF protocol hooks               │
├────────────────────────────────────────────────────────────────────┤
│  Layer 2: Universal PoW Challenge (Rust)                           │
│    SHA256 hashcash · dynamic difficulty                            │
│    works over any TCP protocol            ⚠️ OFF by default        │
├────────────────────────────────────────────────────────────────────┤
│  Layer 3: Userspace Core (Rust)                                    │
│    L7 handshake analysis · rate limit · HMAC · death-code patterns │
├────────────────────────────────────────────────────────────────────┤
│  Layer 4: Protocol Plugins (feature crates)                        │
│    http (protocol-http) · Minecraft Java (protocol-minecraft) · grpc (planned) │
└────────────────────────────────────────────────────────────────────┘
          Traffic Intel (EWMA thresholds, profiling, reputation)
                    runs across all layers
```

```
Attacker → [XDP/eBPF] → [PoW] → [Userspace Core] → [Plugin] → Your Service
                1           2             3             4
```

### Components

| Component | Role | Stack |
|-----------|------|-------|
| **rampart** | Edge engine: XDP loader, PoW challenge, L7 filtering, traffic intel | Rust (tokio, libbpf) + C (XDP) |
| **rampart-manager** | Management API + Redis sync | Rust (axum, redis) |
| **rampart-cli** | CLI tool for operators | Rust (clap) |
| **rampart-tui** | Live metrics terminal dashboard, polls the Prometheus `/metrics` endpoint | Rust (ratatui) |
| **protocol plugins** | Protocol-aware filtering as feature crates | Rust |
| ↳ `http` | HTTP/1.1 handler, compiled with the `protocol-http` feature | Rust |
| ↳ `minecraft` | Minecraft Java TCP handshake and tunnel, compiled with `protocol-minecraft` | Rust |
| ↳ `grpc` | Planned | Rust |
| **docs/kb** | Bilingual knowledge base: attack anatomy, defense levels, practice guides | Markdown |

### Performance

Confirmed numbers only — VDS stress test ([load-test-report.md](docs/research/load-test-report.md)), edge-only setup on loopback, 2 vCPU:

| Scenario | Result |
|----------|--------|
| Raw L7 throughput | ~4k conn/s proxied |
| Masked 100-IP handshake flood (default 5 pps/IP) | **99.6% blocked**, legit clients OK |
| SYN flood without XDP | 0 impact — handled by the kernel |

Full benchmark suite in progress.

### Quick Start

```bash
# Build the HTTP edge handler
cargo build --release --features protocol-http

# Install the default config
sudo mkdir -p /etc/rampart
sudo cp deploy/config/edge-http.toml /etc/rampart/config.toml

# Run edge node (config path comes from $RAMPART_CONFIG, default /etc/rampart/config.toml)
RAMPART_CONFIG=/etc/rampart/config.toml ./target/release/rampart
```

### Minecraft Java Edge

Rampart also has an early Minecraft Java TCP handler. Build it with
`cargo build --release --features protocol-minecraft --bin rampart`, copy
`deploy/config/edge.toml` as its config, and follow
[docs/minecraft-java.md](docs/minecraft-java.md) for Paper PROXY-protocol and
private-backend setup. This handler does not protect an already-saturated home
uplink; use a DDoS-filtering game proxy/provider in front of the edge.

### Documentation

| Path | Description |
|------|-------------|
| [docs/kb/](docs/kb/) | Knowledge base: attack anatomy, defense levels, practice guides |
| [docs/research/architecture.md](docs/research/architecture.md) | Layered architecture, ADRs, migration notes |
| [docs/research/load-test-report.md](docs/research/load-test-report.md) | VDS stress test report (2026-08-04) |
| [docs/research/](docs/research/) | Research notes: eBPF, anti-bot, DDoS vectors, networking |
| [docs/deployment.md](docs/deployment.md) | Deployment guide |
| [docs/minecraft-java.md](docs/minecraft-java.md) | Minecraft Java edge and Paper setup |
| [docs/configuration.md](docs/configuration.md) | Configuration reference |
| [docs/runbook.md](docs/runbook.md) | Operations runbook |

### Roadmap

- Stabilize the protocol plugin API
- BPF hook modules for deep protocol parsing in XDP

---

<a name="russian"></a>

## Русский

### Обзор

Rampart фильтрует трафик на трёх уровнях до того, как он дойдёт до вашего сервиса:

- **Уровень ядра** — XDP/eBPF отбрасывает нежелательные пакеты до того, как они попадут в TCP-стек Linux;
- **Сетевой уровень** — PoW-challenge повышает стоимость флуда соединений для любого TCP-протокола;
- **Прикладной уровень** — userspace-ядро на Rust выполняет анализ L7-handshake, rate limiting и проверку репутации.

Логика, специфичная для протоколов, вынесена в **модульные протокол-плагины** — одна платформа защищает VDS, веб-сервисы и игровые серверы.

### Архитектура

```
┌────────────────────────────────────────────────────────────────────┐
│  Слой 1: Ядро / XDP (C)                                            │
│    универсальный TCP state machine · SYN throttle · CIDR black/    │
│    white списки · UDP policy · подключаемые BPF протокол-хуки      │
├────────────────────────────────────────────────────────────────────┤
│  Слой 2: Универсальный PoW Challenge (Rust)                        │
│    SHA256 hashcash · dynamic difficulty                            │
│    работает поверх любого TCP-протокола   ⚠️ ВЫКЛЮЧЕН по умолчанию │
├────────────────────────────────────────────────────────────────────┤
│  Слой 3: Userspace Core (Rust)                                     │
│    L7 handshake analysis · rate limit · HMAC · death-code паттерны │
├────────────────────────────────────────────────────────────────────┤
│  Слой 4: Протокол-плагины (feature crates)                         │
│    http (protocol-http) · Minecraft Java (protocol-minecraft) · grpc (в планах) │
└────────────────────────────────────────────────────────────────────┘
     Traffic Intel (EWMA thresholds, профилирование, репутация)
                 работает поперёк всех слоёв
```

```
Атакующий → [XDP/eBPF] → [PoW] → [Userspace Core] → [Плагин] → Ваш сервис
                1           2             3             4
```

### Компоненты

| Компонент | Роль | Технологии |
|-----------|------|------------|
| **rampart** | Edge-движок: XDP loader, PoW challenge, L7-фильтрация, traffic intel | Rust (tokio, libbpf) + C (XDP) |
| **rampart-manager** | Management API + Redis sync | Rust (axum, redis) |
| **rampart-cli** | CLI для операторов | Rust (clap) |
| **rampart-tui** | Терминальный дашборд live-метрик, опрашивает Prometheus `/metrics` | Rust (ratatui) |
| **Протокол-плагины** | Протоколозависимая фильтрация в виде feature crates | Rust |
| ↳ `http` | HTTP/1.1-обработчик, собирается с фичей `protocol-http` | Rust |
| ↳ `minecraft` | TCP-handshake и туннель Minecraft Java, фича `protocol-minecraft` | Rust |
| ↳ `grpc` | В планах | Rust |
| **docs/kb** | Двуязычная база знаний: анатомия атак, уровни защиты, практические руководства | Markdown |

### Производительность

Только подтверждённые числа — VDS stress test ([load-test-report.md](docs/research/load-test-report.md)), edge-only на loopback, 2 vCPU:

| Сценарий | Результат |
|----------|-----------|
| Raw L7 пропускная способность | ~4k conn/s проксировано |
| Маскированный flood с 100 IP (default 5 pps/IP) | **99.6% заблокировано**, легитимные клиенты в порядке |
| SYN flood без XDP | 0 влияния — обрабатывается ядром |

Полный набор бенчмарков в процессе подготовки.

### Быстрый старт

```bash
# Сборка HTTP-обработчика
cargo build --release --features protocol-http

# Установка дефолтного конфига
sudo mkdir -p /etc/rampart
sudo cp deploy/config/edge-http.toml /etc/rampart/config.toml

# Запуск edge ноды (путь конфига берётся из $RAMPART_CONFIG, по умолчанию /etc/rampart/config.toml)
RAMPART_CONFIG=/etc/rampart/config.toml ./target/release/rampart
```

### Minecraft Java Edge

В проекте появился ранний TCP-обработчик Minecraft Java. Соберите его командой
`cargo build --release --features protocol-minecraft --bin rampart`, скопируйте
`deploy/config/edge.toml` как конфиг и настройте
Paper и закрытый backend по инструкции
[docs/minecraft-java.md](docs/minecraft-java.md). Сам Rampart не спасёт домашний
канал, если атака уже забила его: перед edge нужен игровой прокси или провайдер
с фильтрацией DDoS.

### Документация

| Путь | Описание |
|------|----------|
| [docs/kb/](docs/kb/) | База знаний: анатомия атак, уровни защиты, практические руководства |
| [docs/research/architecture.md](docs/research/architecture.md) | Слоистая архитектура, ADR, миграционные заметки |
| [docs/research/load-test-report.md](docs/research/load-test-report.md) | Отчёт по VDS stress test (2026-08-04) |
| [docs/research/](docs/research/) | Research-заметки: eBPF, антибот, векторы DDoS, сети |
| [docs/deployment.md](docs/deployment.md) | Руководство по деплою |
| [docs/minecraft-java.md](docs/minecraft-java.md) | Minecraft Java edge и настройка Paper |
| [docs/configuration.md](docs/configuration.md) | Справочник конфигурации |
| [docs/runbook.md](docs/runbook.md) | Операционный runbook |

### Roadmap

- Стабилизация API протокол-плагинов
- BPF hook модули для глубокого парсинга протоколов в XDP

---

### Links

- [Releases](../../releases)
- [Issues](../../issues)
- [License](LICENSE)

### License

GNU General Public License v3.0
