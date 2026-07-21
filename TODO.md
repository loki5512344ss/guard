# Rampart — Development TODO & Roadmap

> Живой документ. Философия: **KISS → DRY → SOLID → YAGNI**.

---

## 0. Принципы разработки

### KISS
- Не добавляй абстракцию до третьего повторения.
- Функция ≤ 60 строк, модуль ≤ 500 строк.
- Не используй generics где хватит `&str` и `Vec<u8>`.

### DRY
- Повтор > 2 раз → выноси, но лучше копипаста чем неправильная абстракция.

### SOLID (Rust)
- **S**: один файл = одна ответственность
- **O**: расширяй через трейты
- **L**: `dyn Filter` — любая реализация без side effects
- **I**: маленькие трейты вместо одного `ShieldTrait`
- **D**: core зависит от `trait StateStore`, не от Redis

### YAGNI
- Не пиши BGP до v0.6, K8s Operator до v0.5
- Не добавляй feature flag если фича не готова

### Rust-специфичные
1. `unwrap()` — только в main() и тестах
2. `unsafe` — только в xdp/, комментарий обязателен
3. `clone()` осознанно, профилируй hot path
4. Блокирующие операции → `spawn_blocking`
5. Логи: `tracing::info!` / `debug!` / `error!`
6. Метрики: register один раз при старте, инкремент в hot path

---

## 1. Текущее состояние (v0.2+)

### ✅ Готово

| Компонент | Статус |
|-----------|--------|
| **rampart-core** (Rust Edge) | ~85% — работает: TCP listener, handshake parse, HMAC sign, rate limit, death code (8 паттернов), blacklist (DashMap + TTL), Redis sync, Prometheus metrics, graceful shutdown |
| **rampart-manager** (Rust API) | ~80% — работает: JWT auth, CRUD blacklist, servers/nodes list, heartbeat мониторинг |
| **rampart-cli** (Rust CLI) | ~40% — 3/6 команд (status, doctor, blacklist list/add) |
| **velocity-plugin** (Java) | ~90% — domain whitelist, HMAC verify (constant-time), Redis server registry (delta-sync), TPS-aware load balancer (circuit breaker < 12 TPS) |
| **paper-plugin** (Java) | ~90% — Redis heartbeat (TPS/online/sec), auto-registration, graceful shutdown |
| **dashboard** (React/TS) | ~85% — login, Servers/Blacklist/Nodes таблицы, auto-refresh, dark theme |
| **CI/CD** | GitHub Actions (Rust check+test+clippy+deny + Java build + Dashboard build + Docker), Makefile, deny.toml |
| **Docs** | ~80% — architecture, anti-bot, ebpf, ddos, deployment, configuration |
| **Ref analysis** | Проанализированы Sonar, LimboFilter, AtomGuard, Infrarust, MC-XDP-eBPF, PowGo |
| **ref/ в .gitignore** | Добавлено |

### ❌ Не начато / частично

| Компонент | Статус |
|-----------|--------|
| **xdp/xdp_filter.c** | 0% — пустой каталог |
| **PoW Challenge (Layer 2)** | 0% — нужно писать |
| **GeoIP/ASN reputation** | 0% — enum есть, реализации нет |
| **Velocity physics** (falling + protocol + vehicle) | 0% |
| **Traffic Intelligence (Layer 6)** | 0% — EWMA, 168h profiling |
| **ClickHouse + Grafana** | 0% |
| **Bloom filter blacklist** | 0% |

---

## 2. 6-слойная архитектура (план)

```
Layer 1: XDP/eBPF (C)        TCP state machine, SYN throttle, blacklist, UDP drop
Layer 2: PoW Challenge (Rust) SHA256 hashcash, dynamic difficulty
Layer 3: Rust Core (Rust)     MC handshake, HMAC sign, rate limit, death code
Layer 4: Velocity (Java)      Domain whitelist, HMAC verify, physics, CAPTCHA
Layer 5: Paper Agent (Java)   Redis heartbeat, auto-registration
Layer 6: Traffic Intel (Rust) EWMA thresholds, 168h profiling, reputation
```

---

## 3. Этапы разработки

### Этап 4: XDP/eBPF — Layer 1 (сейчас)

Цель: Написать полноценный XDP фильтр с TCP state machine, исправив баги Minecraft-XDP-eBPF.

- [x] **Изучен reference Minecraft-XDP-eBPF:**
  - Найден **TCP handshake deadlock** (pure ACK drop)
  - Найден **VarInt sign extension UB**
  - Найдена **stale conntrack на RST/FIN**
  - Найден **IPv6 bypass**
  - Найдена **отсутствие LRU на player map**

- [x] `xdp/xdp_filter.c` — TCP state machine (465 строк):
  - AWAIT_ACK → AWAIT_MC_HANDSHAKE → AWAIT_LOGIN → VERIFIED
  - **Исправление:** pure ACK → PASS, не DROP
  - **Исправление:** RST/FIN → удалять conntrack entry
- [x] `xdp/maps.h` — 6 BPF maps:
  - `conntrack_map` (LRU_HASH, 16384)
  - `player_connection_map` (LRU_HASH, 65535) — **LRU, не plain HASH**
  - `connection_throttle` (LRU_HASH, 65535) — SYN throttle per-IP
  - `blacklist_map` (LPM_TRIE, 100000) — CIDR blacklist
  - `whitelist_map` (LPM_TRIE, 1000) — CIDR whitelist
  - `stats_map` (PERCPU_ARRAY) — счетчики для Prometheus
- [x] `xdp/protocol.h` — парсеры Minecraft на C
- [x] `xdp/varint.h` — VarInt (без sign extension UB)
- [x] `xdp/config.h` — Runtime-конфигурация (volatile const)
- [x] **Rust loader** (`crates/rampart-core/src/xdp/mod.rs`):
  - Загрузка .o через libbpf-rs
  - Attach XDP к интерфейсу через `bpf_xdp_attach`
  - `ban_ip` / `unban_ip` / `get_stats` методы
- [x] `build.rs` — компиляция .c → .o (clang -target bpf)
- [ ] Пропатчить глобальные переменные из config.toml
- [ ] Чтение ringbuf → blacklist events
- [ ] BPF stats → Prometheus интеграция
- [ ] **Тесты:**
  - `hping3 -S --flood` → XDP дропает, CPU < 30%
  - `iperf3` UDP flood → XDP дропает
  - TCP handshake проверка: Minecraft клиент коннектится без задержки

**DoD:** SYN flood 1M pps дропается в XDP, TCP handshake без deadlock, CPU < 30%, CI собирает xdp_filter.o

---

### Этап 2b: PoW Challenge — Layer 2 (после XDP)

- [ ] Challenge generator: случайный token + timestamp + difficulty
- [ ] Dynamic difficulty: 4 (спокойно) → 12 (атака) по CPS
- [ ] Nonce verification: SHA256(challenge + nonce) prefix check
- [ ] Одноразовый challenge (token + timestamp, max 30 сек)
- [ ] Интеграция в rampart-core: PoW перед HMAC handshake
- [ ] Тесты: PoW solver timing, nonce replay защита, dynamic adjustment

**DoD:** Edge требует PoW перед handshake, бот не может флудить >50 handshake/сек

---

### Этап 4b: Velocity Physics — Layer 4 (после PoW)

- [ ] Falling check (pre-computed cache: `(0.98^t-1)*3.92`, 128 ticks)
  - **Исправление:** checkY() без fast-forward, сброс ignoredTicks
- [ ] Protocol check (Transaction, SetHeldItem, ArmAnimation)
- [ ] Vehicle check (Boat gravity + Minecart gravity)
- [ ] CAPTCHA (Map item или PoW как fallback)
- [ ] HMAC fingerprint (не hashCode!) для verified DB
- [ ] Idempotent finishVerification() (нет race condition)

---

### Этап 6: Traffic Intelligence — Layer 6

- [ ] 168-hour traffic profiling (per-hour-slot baseline)
- [ ] EWMA adaptive thresholds (правильная variance формула)
- [ ] Z-Score anomaly detection (3 consecutive minutes)
- [ ] Attack detection (CPS/PPS thresholds)
- [ ] Reputation system (IP score -100..+100)
- [ ] Discord webhook на атаки

---

### Этап 5: Observability

- [ ] ClickHouse writer (batch, раз в сек, буфер 1000)
- [ ] Grafana dashboard JSON
- [ ] Страница Attack Log в dashboard

---

### Этап 6b: Scale + HA

- [ ] NATS JetStream (blacklist, drain, audit)
- [ ] mTLS между всеми компонентами (rustls)
- [ ] Auto-discovery edge нод
- [ ] rampart-cli: `drain`, `wg sync`, `add-node`

---

### Этап 7: Polish

- [ ] io_uring runtime (feature flag)
- [ ] Zero-copy splice после handshake
- [ ] SLSA Level 3: signed releases, reproducible builds
- [ ] secret rotation (dual-key HMAC)

---

## 4. Backlog

- [ ] Bedrock / RakNet (UDP модуль)
- [ ] Plugin API через WASM (как Infrarust)
- [ ] BGP Anycast (требует AS + /24)
- [ ] ML anomaly detection (Isolation Forest — многомерный, не univariate)
- [ ] Fuzzing для handshake parser (`cargo-fuzz`)
- [ ] Chaos engineering (random node kills)

---

## 5. Definition of Done

```
☐ cargo check / cargo test проходят
☐ cargo clippy -- -D warnings — 0 warnings
☐ cargo fmt --check проходит
☐ Unit тесты покрывают happy path + 2+ error cases
☐ Интеграционный тест проходит
☐ Документация обновлена
☐ CI зелёный
```

---

## 6. Anti-Patterns

```
❌ Тесты после кода. Пиши до (TDD) или вместе.
❌ Коммиты в main напрямую. Только PR.
❌ TODO в коде без issue. TODO = баг.
❌ Оптимизация без профиля.
❌ Зависимость ради 1 функции.
❌ async где хватит sync.
❌ Секреты в репозитории. Используй .env + SOPS.
❌ Игнор compiler warnings.
```

---

*Версия: 2.0 | Обновлён: июль 2026*
