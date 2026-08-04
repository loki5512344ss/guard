<div align="center">

> **⚠️ UNDER DEVELOPMENT** — All performance data, benchmarks, and specifications shown are approximate and subject to change.
>
> **⚠️ В РАЗРАБОТКЕ** — Все показатели производительности, тесты и характеристики являются примерными и могут измениться.

</div>

<div align="center">

# Rampart

6-layer DDoS protection for Minecraft servers.

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
![Java](https://img.shields.io/badge/Java_21-ED8B00?style=flat-square&logo=openjdk&logoColor=white)
![eBPF](https://img.shields.io/badge/eBPF/XDP-FF6C37?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-GPLv3-blue?style=flat-square&logo=gnu&logoColor=white)
![Version](https://img.shields.io/badge/version-0.2.0-green?style=flat-square)
![Status](https://img.shields.io/badge/status-development-yellow?style=flat-square)

[English](#english) | [Русский](#russian)

</div>

---

<a name="english"></a>

## English

### Overview

Rampart filters traffic at kernel level (XDP/eBPF), network level (PoW challenge), and application level (Rust + Java) before it reaches game servers.

### 6-Layer Architecture

```
Layer 1: XDP/eBPF (C)        TCP state machine, SYN throttle, blacklist, UDP drop
Layer 2: PoW Challenge (Rust) SHA256 hashcash, dynamic difficulty, anti-handshake-flood
         ⚠️ OFF by default: the current text-challenge protocol is incompatible with
         vanilla clients, which cannot solve it — enable only with a client mod.
Layer 3: Rust Core           MC handshake parse, HMAC sign, rate limit, death code
Layer 4: Velocity (Java)     Domain whitelist, HMAC verify, physics check, CAPTCHA
Layer 5: Paper Agent (Java)  Redis heartbeat, auto-registration
Layer 6: Traffic Intel       EWMA thresholds, 168h profiling, reputation
```

```
Атакующий → [XDP/eBPF] → [PoW] → [Rust Core] → [Velocity] → Game Server
               1           2           3             4
```

### Components

| Component | Role | Stack |
|-----------|------|-------|
| **rampart-core** | Edge node - layers 2+3 | Rust (tokio, socket2, prometheus) |
| **rampart-manager** | Management API + Redis sync | Rust (axum, jsonwebtoken, redis) |
| **rampart-cli** | CLI tool for operators | Rust (clap) |
| **velocity-plugin** | Layer 4 - domain, HMAC, physics, router | Java 21 (Velocity API) |
| **paper-plugin** | Layer 5 - Redis heartbeat, auto-reg | Java 21 (Paper API) |
| **dashboard** | Web UI - servers, blacklist, nodes | React + Vite + TypeScript |

### Performance

Tested on Hetzner CX31 (4 vCPU, 8GB, KVM), Ubuntu 22.04, kernel 5.15

| Mode | New conn/s | Active conn | CPU |
|------|-----------|-------------|-----|
| 4 core, epoll | 80k | 200k | ~65% |
| 4 core, io_uring | 110k | 260k | ~48% |
| XDP drop (generic) | 3-5M pps | - | ~25% |
| XDP drop (native) | 15-20M pps | - | ~15% |

Note: Real L7 throughput (handshake + HMAC + rate limit): ~60-70k conn/s (epoll), ~85-95k (io_uring).

#### VDS stress test (2026-08-04) — edge-only, loopback

VDS 2 vCPU / 3.8GB / Ubuntu 22.04, Docker bridge. Edge-only (слои 1–3), без Redis/Velocity/Paper.
Атака маскировалась под обычный трафик: 100 source IP, валидные Minecraft handshake.
Подробности: [load-test-report.md](docs/research/load-test-report.md), скрипты: [deploy/test/stress](deploy/test/stress).

| Scenario | Result |
|----------|--------|
| Raw L7 throughput (valid handshake → HMAC → backend) | ~4k conn/s proxied, 100% (121.5k/30s; edge CPU ~179%, 2 cores) |
| Defense vs masked 100-IP flood (default 5 pps/IP) | **99.6% blocked** (528 allowed vs 119,376 blocked), CPU ~32% |
| Legit clients during attack | 5/5 OK, RTT 2.2–5.8ms |
| SYN flood (no XDP) | 0 impact — handled by kernel |
| Active connections | 300 held trivially (CPU ~0%, 7MB); limit is backend/fd, not edge |

### Quick Start

```bash
# Build Rust components
cargo build --release

# Create config
mkdir -p /etc/rampart
rampart config init > /etc/rampart/config.toml

# Run edge node
./target/release/rampart-core --config /etc/rampart/config.toml

# Java plugins
cd plugins && ./gradlew build
```

### Documentation

| File | Description |
|------|-------------|
| [architecture](docs/research/architecture.md) | 6-layer architecture, components, ADRs |
| [anti-bot](docs/research/anti-bot.md) | Bot detection, PoW, fingerprinting, known issues |
| [ebpf](docs/research/ebpf.md) | XDP/eBPF: TCP state machine, maps, fixes |
| [ddos](docs/research/ddos.md) | Attack vectors, L3/L4/L7, AI bots |
| [deployment](docs/deployment.md) | Step-by-step deployment guide |
| [configuration](docs/configuration.md) | Configuration examples |
| [networking](docs/research/networking.md) | WireGuard, BGP Anycast, QUIC |
| [runbook](docs/runbook.md) | Operations runbook |
| [disaster_recovery](docs/disaster_recovery.md) | Failover scenarios |
| [troubleshooting](docs/troubleshooting.md) | FAQ and diagnostics |

---

<a name="russian"></a>

## Русский

### Обзор

Rampart — 6-слойная система DDoS-защиты для Minecraft. Фильтрует трафик на уровне ядра (XDP/eBPF), уровне сети (PoW), уровне приложений (Rust) и уровне прокси (Velocity).

### 6 слоёв защиты

```
Слой 1: XDP/eBPF (C)       TCP state machine, SYN throttle, blacklist, UDP drop
Слой 2: PoW Challenge (Rust) SHA256 hashcash, dynamic difficulty
         ⚠️ ВЫКЛЮЧЕН по умолчанию: текущий text-challenge несовместим с ванильными
         клиентами (они не умеют его решать) — включать только с клиентским модом.
Слой 3: Rust Core          MC handshake, HMAC sign, rate limit, death code
Слой 4: Velocity (Java)    Domain whitelist, HMAC verify, physics, CAPTCHA
Слой 5: Paper Agent (Java) Redis heartbeat, auto-registration
Слой 6: Traffic Intel      EWMA thresholds, 168h profiling, reputation
```

```
Атакующий → [XDP] → [PoW] → [Rust] → [Velocity] → Game Server
              1       2        3          4
```

### Компоненты

| Компонент | Роль | Технологии |
|-----------|------|------------|
| **Edge нода** | Слои 1-3: XDP + PoW + фильтрация | Rust + XDP/eBPF |
| **Manager** | Слой 6: API + мониторинг | Rust (Axum) |
| **Velocity** | Слой 4: прокси, верификация | Java 21 |
| **Paper Agent** | Слой 5: регистрация сервера | Java 21 |
| **Dashboard** | Web UI | React + TypeScript |

### Защита от атак

| Атака | Метод защиты | Слой |
|-------|-------------|------|
| SYN flood | XDP дроп + SYN throttle | 1 |
| Handshake flood | PoW challenge + rate limit | 2+3 |
| Slow Loris | Timeout 5 сек | 3 |
| VarInt overflow | Строгий bounds check | 3 |
| Death code | Auto-ban по малициозным пакетам | 3 |
| Direct IP | Domain whitelist | 4 |
| Подмена hostname | HMAC-SHA256 подпись | 3+4 |
| Боты (физика) | Falling check + Vehicle check | 4 |
| AI-боты | PoW (CPU cost) + reputation | 2+6 |

> **Примечание:** Layer 2 (PoW) **выключен по умолчанию** (`pow.enabled = false`) из-за
> несовместимости с ванильными клиентами: текстовый challenge отправляется до handshake,
> и ванильный клиент не умеет его решать — при включении никто не сможет зайти.
> Включать только после появления клиентского мода или PoW, совместимого с протоколом Minecraft.

### Быстрый старт

```bash
# Сборка Rust компонентов
cargo build --release

# Создание конфига
mkdir -p /etc/rampart
rampart config init > /etc/rampart/config.toml

# Запуск edge ноды
./target/release/rampart-core --config /etc/rampart/config.toml

# Сборка Java плагинов
cd plugins && ./gradlew build
```

### Документация

| Файл | Описание |
|------|----------|
| [architecture](docs/research/architecture.md) | 6-слойная архитектура, компоненты, ADR |
| [anti-bot](docs/research/anti-bot.md) | Антибот: PoW, fingerprinting, известные проблемы |
| [ebpf](docs/research/ebpf.md) | XDP/eBPF: TCP state machine, карты, исправления |
| [ddos](docs/research/ddos.md) | Векторы атак, L3/L4/L7, AI-боты |
| [deployment](docs/deployment.md) | Пошаговый деплой |
| [configuration](docs/configuration.md) | Примеры конфигов |
| [networking](docs/research/networking.md) | WireGuard, BGP, QUIC |
| [runbook](docs/runbook.md) | Инструкции для админа |
| [disaster_recovery](docs/disaster_recovery.md) | Failover сценарии |
| [troubleshooting](docs/troubleshooting.md) | FAQ и диагностика |

---

### Links

- [Releases](../../releases)
- [Issues](../../issues)
- [License](LICENSE)

### License

GNU General Public License v3.0
