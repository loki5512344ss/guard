<div align="center">

> **⚠️ UNDER DEVELOPMENT** — All performance data, benchmarks, and specifications shown are approximate and subject to change.
>
> **⚠️ В РАЗРАБОТКЕ** — Все показатели производительности, тесты и характеристики являются примерными и могут измениться.

</div>

<div align="center">

# Rampart

Multi-layer DDoS protection for Minecraft servers.

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

Rampart is a multi-layer DDoS protection system for Minecraft networks. It filters traffic at kernel level (XDP/eBPF) and application level (Rust) before it reaches your game servers.

```
Player -> Rampart Edge (XDP + Rust) -> Load Balancer -> Velocity -> Game Server
```

### Architecture

```
                    +--------------------------------------+
                    |          EDGE LAYER (VDS)             |
                    |  XDP/eBPF -> Rust Core -> HMAC sign   |
                    +------------------+-------------------+
                                       | clean traffic
                    +------------------v-------------------+
                    |      Rust Load Balancer / HAProxy     |
                    +------------------+-------------------+
                                       |
                    +------------------+------------------+
                    v                  v                  v
              Velocity x20         Hub x100          Game Servers
              (MC Proxy)           (lobby)           (Survival, Skyblock)
```

### Features

| Layer | Technology | What it does |
|-------|-----------|--------------|
| **L3/L4** | XDP/eBPF (C) | SYN flood drop, UDP drop (MC=TCP), invalid TCP flags, IP blacklist |
| **L7** | Rust (tokio) | MC handshake parsing, HMAC-SHA256, rate limit, death code auto-ban |
| **Proxy** | Velocity (Java) | Domain whitelist, HMAC verification, server registry, load balancing |
| **Agent** | Paper plugin | Auto-registration in Redis, heartbeat (TPS/online), cleanup on disable |
| **Management** | Rust (Axum) | REST API with JWT auth, Redis pub/sub blacklist sync, dashboard |

### Components

| Component | Role | Stack |
|-----------|------|-------|
| **rampart-core** | Edge node - traffic filter proxy | Rust (tokio, socket2, prometheus) |
| **rampart-manager** | Management API + Redis sync | Rust (axum, jsonwebtoken, redis) |
| **rampart-cli** | CLI tool for operators | Rust (clap) |
| **velocity-plugin** | Proxy plugin - domain check, HMAC, server registry | Java 21 (Velocity API) |
| **paper-plugin** | Server agent - Redis registration, heartbeat | Java 21 (Paper API) |
| **dashboard** | Web UI - servers, blacklist, nodes | React + Vite + TypeScript |

### Performance

Tested on Hetzner CX31 (4 vCPU, 8GB, KVM), Ubuntu 22.04, kernel 5.15

| Mode | New conn/s | Active conn | CPU |
|------|-----------|-------------|-----|
| 4 core, epoll | 80k | 200k | ~65% |
| 4 core, io_uring | 110k | 260k | ~48% |
| XDP drop (generic) | 3-5M pps | - | ~25% |
| XDP drop (native) | 15-20M pps | - | ~15% |

Note: 110k conn/s is synthetic echo benchmark. Real L7 throughput (handshake parsing + HMAC + rate limit): ~60-70k conn/s on epoll, ~85-95k on io_uring.

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
| [deployment](docs/deployment.md) | Step-by-step deployment guide |
| [configuration](docs/configuration.md) | Configuration examples |
| [architecture](docs/research/architecture.md) | C4 diagrams, ADRs |
| [ddos](docs/research/ddos.md) | Attack vectors and defense |
| [networking](docs/research/networking.md) | WireGuard, BGP Anycast, QUIC |
| [runbook](docs/runbook.md) | Operations runbook |
| [disaster_recovery](docs/disaster_recovery.md) | Failover scenarios |
| [troubleshooting](docs/troubleshooting.md) | FAQ and diagnostics |

---

<a name="russian"></a>

## Русский

### Обзор

Rampart - многослойная система DDoS-защиты для Minecraft-серверов. Фильтрует трафик на уровне ядра (XDP/eBPF) и на уровне приложений (Rust) до того, как он достигнет игровых серверов.

### Как это работает

```
Атакующий (ботнет)
    |
    v
[1] XDP/eBPF (ядро)     L3/L4: SYN flood, UDP drop, IP blacklist
    |                    CPU < 30%, дроп до 10M pps
    v (чистый TCP)
[2] Rust Core           L7: парсинг handshake, HMAC, rate limit
    |                    death code auto-ban, blacklist check
    v (валидный MC клиент)
[3] Load Balancer       Round-robin, circuit breaker (TPS < 12 = out)
    |
    v
[4] Game Server         Чистый трафик без DDoS нагрузки
```

### Компоненты

| Компонент | Роль | Технологии |
|-----------|------|------------|
| **Edge нода** | Фильтрация + прокси | Rust + XDP/eBPF |
| **Load Balancer** | Балансировка на Velocity | Rust / HAProxy |
| **Velocity** | MC прокси, антибот | Java 21 |
| **Manager** | API + оркестрация | Rust (Axum) |
| **Paper Agent** | Регистрация сервера | Java 21 (Paper plugin) |

### Защита от атак

| Атака | Метод защиты |
|-------|-------------|
| SYN flood | XDP дроп на уровне драйвера |
| Handshake flood | Token bucket rate limit (Rust) |
| Slow Loris | Timeout 5 сек на handshake |
| VarInt overflow | Строгий bounds check |
| Death code | Auto-ban по невалидным пакетам |
| Direct IP | Domain whitelist (Velocity) |
| Подмена hostname | HMAC-SHA256 подпись |

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
| [deployment](docs/deployment.md) | Пошаговый деплой |
| [configuration](docs/configuration.md) | Примеры конфигов |
| [architecture](docs/research/architecture.md) | C4-диаграммы, ADR |
| [ddos](docs/research/ddos.md) | Векторы атак и защита |
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
