# Architecture - Rampart

> Актуально: v0.2+
> Статус: основной документ

---

## 6-слойная архитектура защиты

```
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 1: XDP/eBPF (ядро)           дроп L3/L4 до kernel TCP stack │
│  ─────────────────────────────                                       │
│  TCP state machine (minecraft_filter.c):                             │
│    AWAIT_ACK → AWAIT_MC_HANDSHAKE → AWAIT_LOGIN → verified          │
│  + SYN throttle per-IP                                              │
│  + IP blacklist (LPM_TRIE)                                          │
│  + Invalid TCP flags drop (SYN+FIN, SYN+RST, URG, пустые)          │
│  + UDP drop (MC = TCP only)                                         │
│  + Per-connection seq tracking                                      │
│  + bpf_timer idle cleanup                                           │
│  + IP/CIDR whitelist                                                │
│  ───────────────────────────────────────                             │
│  Reference: Minecraft-XDP-eBPF (исправленный: нет pure ACK deadlock,│
│             LRU maps, IPv6, idle таймеры на conntrack)              │
├──────────────────────────────────────────────────────────────────────┤
│  LAYER 2: PoW Challenge (Rust)          анти-handshake-flood        │
│  ─────────────────────────────                                       │
│  SHA256 hashcash перед HMAC handshake:                              │
│    1. Edge шлёт challenge (random + timestamp + difficulty)          │
│    2. Клиент решает PoW (nonce brute-force)                         │
│    3. Edge верифицирует SHA256(data + nonce) prefix                 │
│  + Dynamic difficulty: повышается при CPS > threshold               │
│  + Per-connection одноразовый challenge (nonce replay защита)       │
│  ───────────────────────────────────────                             │
│  Reference: PowGo (адаптирован: per-request challenge, timestamp,   │
│             dynamic difficulty, без Redis, без IP+UA сессии)        │
├──────────────────────────────────────────────────────────────────────┤
│  LAYER 3: Rust Core (userspace)          L7 фильтрация              │
│  ─────────────────────────────                                       │
│  + MC handshake парсинг (VarInt, bounds check)                      │
│  + HMAC-SHA256 hostname signature                                   │
│  + Rate limit (token bucket per-IP)                                 │
│  + Death code auto-ban (8 паттернов)                                │
│  + ASN/GeoIP reputation                                             │
│  + Blacklist (Redis sync)                                           │
├──────────────────────────────────────────────────────────────────────┤
│  LAYER 4: Velocity Proxy (Java)           верификация игроков       │
│  ─────────────────────────────                                       │
│  + Domain whitelist (блок прямых IP)                                │
│  + HMAC verification (constant-time compare)                        │
│  + Falling check (детерминированная физика: pre-computed кэш)      │
│  + Protocol check (Transaction, SetHeldItem, ArmAnimation)          │
│  + Vehicle check (Boat/Minecart gravity)                            │
│  + CAPTCHA challenge (Map item / PoW)                               │
│  + Redis server registry (delta-sync)                               │
│  + TPS-aware load balancer (circuit breaker < 12 TPS)               │
│  ───────────────────────────────────────                             │
│  Reference: Sonar pipeline + LimboFilter falling check              │
│  (исправлено: HMAC fingerprint, idempotent finishVerification,      │
│   без QuietDecoderException, без race в handler switching)          │
├──────────────────────────────────────────────────────────────────────┤
│  LAYER 5: Paper Agent (Java)              авто-регистрация         │
│  ─────────────────────────────                                       │
│  + Redis heartbeat (TPS, online игроки, память, CPU)                │
│  + Auto-registration/unregistration                                 │
│  + HMAC login check                                                 │
│  + Graceful shutdown                                                │
├──────────────────────────────────────────────────────────────────────┤
│  LAYER 6: Traffic Intelligence (Rust + Redis)   аналитика          │
│  ─────────────────────────────                                       │
│  + 168-hour traffic profiling (per-hour-slot baseline)              │
│  + EWMA adaptive thresholds (правильная variance формула)           │
│  + Z-Score anomaly detection (3 consecutive minutes для алерта)     │
│  + Attack detection (CPS, PPS thresholds)                           │
│  + Reputation system (IP score -100..+100)                          │
│  + Discord webhook на события                                       │
│  ───────────────────────────────────────                             │
│  Reference: AtomGuard (исправлено: EWMA variance, Isolation Forest  │
│             реально используется, без race в pipeline)              │
└──────────────────────────────────────────────────────────────────────┘
```

## Схема прохождения трафика

```
Атакующий (ботнет)
    |
    v
[1] XDP/eBPF ─── TCP state machine ─── blacklist ─── SYN throttle
    |           дроп: SYN flood, UDP, invalid flags, non-MC port
    v (чистый TCP, прошёл state machine)
[2] PoW Challenge ─── SHA256 hashcash ─── dynamic difficulty
    |           дроп: не решил PoW за N секунд
    v (валидный PoW)
[3] Rust Core ─── handshake parse ─── HMAC sign ─── rate limit ─── death code
    |           дроп: rate limit, invalid packet, bad HMAC
    v (валидный MC handshake + HMAC)
[4] Velocity ─── domain check ─── HMAC verify ─── falling/physics check ─── CAPTCHA
    |           дроп: bad domain, bad HMAC, failed physics
    v (верифицированный игрок)
[5] Game Server
    |           Чистый трафик, без DDoS нагрузки
```

## Компоненты системы

```
┌────────────────────────────────────────────────────────────────┐
│                        EDGE NODE                               │
│  XDP/eBPF (C)  →  PoW (Rust)  →  Rust Core  →  Manager API   │
│  ────────────────────────────────────────────────────────────  │
│  Требования: KVM/Bare Metal, 2-4 vCPU, 2-4 GB, kernel 5.10+  │
│  XDP native: Intel i40e, Mellanox ConnectX, virtio (generic)  │
└────────────────────────┬───────────────────────────────────────┘
                         │ mTLS/QUIC
┌────────────────────────▼───────────────────────────────────────┐
│                      VELOCITY CLUSTER                          │
│  Java 21, Velocity 3.4+, x20 нод                              │
│  Domain check → HMAC verify → Physics → CAPTCHA → Router      │
└────────────────────────┬───────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    Hub (x100)     Game Servers    Game Servers
    лобби          Survival (x100) Skyblock (x100)
                   разные VDS/дедики
```

## Требования к хостингу

| Нода | Роль | CPU | RAM | Тип | XDP |
|------|------|-----|-----|-----|-----|
| **Edge** | XDP + PoW + фильтрация | 2-4 vCPU | 2-4 GB | KVM / Bare Metal | ✅ |
| **Velocity** | MC Proxy + верификация | 4 vCPU | 4-8 GB | KVM | ❌ |
| **Manager** | API + Redis | 2-4 vCPU | 4-8 GB | KVM | ❌ |
| **Hub** | Лобби | 4-8 vCPU | 8-16 GB | KVM / Bare Metal | ❌ |
| **Game** | Игровой процесс | 4-8 vCPU | 8-32 GB | KVM / Bare Metal | ❌ |

> ⚠️ XDP требует KVM или Bare Metal. OpenVZ/LXC контейнеры — XDP не работает.
> Проверить: `systemd-detect-virt`

## Sizing guide

| Игроков | Edge нод | Velocity нод | Edge RAM | Стоимость/мес |
|---------|----------|--------------|----------|---------------|
| до 500 | 1 | 2 | 2 GB | ~$15-30 |
| до 2 000 | 2 | 4 | 4 GB | ~$40-80 |
| до 10 000 | 4-6 | 8-10 | 8 GB | ~$150-300 |
| до 50 000 | 10-15 | 15-20 | 16 GB | ~$600-1200 |

## Граница XDP / Rust (критично)

```
XDP делает:                             Rust делает:
  TCP state machine (stateful)           PoW challenge (SHA256)
  SYN throttle per-IP                   MC handshake парсинг
  IP blacklist (LPM_TRIE)               HMAC подпись hostname
  Invalid TCP flags drop                Rate limit (connections/sec)
  UDP drop                              Death code auto-ban
  Per-connection seq tracking           GeoIP/ASN lookup
  bpf_timer idle cleanup                Blacklist (сложные правила)
```

XDP **не может**: SHA256, HMAC, floating point, heap allocation, сложные строки.
Всё L7 — только в Rust userspace.

## ADR-001: Rust для Edge Core

**Решение:** Rust + tokio
**Альтернативы:** Go (GC паузы), C (небезопасен), Java (память)
**Причина:** Zero-cost abstractions, memory safety, нет GC, libbpf-rs

## ADR-002: Redis как хранилище состояния

**Решение:** Redis + локальный кэш на edge нодах
**Оговорка:** При падении Redis — edge работает с кэшем, Velocity с кэшем серверов
**Масштаб:** Redis Cluster при 1000+ серверов, Redis Sentinel для HA

## ADR-003: NATS для критических событий

**Решение:** NATS JetStream для blacklist updates, attack events, audit log
**Причина:** Redis Pub/Sub — fire-and-forget, NATS — at-least-once delivery
