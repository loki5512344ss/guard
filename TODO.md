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
- Не пиши io_uring до v0.4, BGP до v0.6, K8s Operator до v0.5
- Не добавляй feature flag если фича не готова

### Rust-специфичные
1. `unwrap()` — только в main() и тестах
2. `unsafe` — только в xdp/, комментарий обязателен
3. `clone()` осознанно, профилируй hot path
4. Блокирующие операции → `spawn_blocking`
5. Логи: `tracing::info!` / `debug!` / `error!`
6. Метрики: register один раз при старте, инкремент в hot path

---

## 1. Этапы разработки

### Этап 0: Bootstrap (неделя 1)
- [ ] Инициализировать Cargo workspace (`crates/*`)
- [ ] GitHub Actions: `cargo check`, `cargo test`, `cargo clippy -- -D warnings`
- [ ] `cargo-deny` (лицензии, CVE, дубликаты)
- [ ] `Makefile` с целями: `build`, `test`, `fmt`, `ebpf`, `docker`
- [ ] `docker-compose.yml` для dev (redis, clickhouse)
- [ ] `.gitignore`, `CONTRIBUTING.md`, `rustfmt.toml`, `clippy.toml`
- [ ] **DoD:** `make test` проходит, CI зелёный, `cargo build --release` собирает

---

### Этап 1: MVP — v0.1 (недели 2–4)
> Edge нода принимает MC соединения, парсит handshake, HMAC, проксирует на Velocity.

#### rampart-core
- [ ] TCP listener с SO_REUSEPORT
- [ ] VarInt парсер с bounds check
- [ ] MC Handshake парсер (packet_id=0x00)
- [ ] HMAC-SHA256 signer
- [ ] Timeout 1.5s на handshake (Slowloris защита)
- [ ] TCP proxy (tokio::io::copy_bidirectional)
- [ ] Config из `config.toml`
- [ ] Логи через `tracing`

#### rampart-cli
- [ ] `rampart pki init` — CA + сертификаты
- [ ] `rampart pki issue --name edge-1 --ip 10.0.100.1`

#### plugins/velocity
- [ ] DomainCheck: whitelist доменов, блок direct IP
- [ ] HmacCheck: verify HMAC, extract real IP
- [ ] Передача real IP в Velocity forwarding

#### plugins/paper
- [ ] ShieldAgent: авто-регистрация в YAML
- [ ] Heartbeat: online/tps в файл каждые 10 сек

#### docs
- [ ] `deployment.md`: как поднять v0.1
- [ ] `configuration.md`: примеры конфигов

#### Тестирование
- [ ] Unit: VarInt парсер (overflow, incomplete, граничные случаи)
- [ ] Unit: HMAC sign/verify (timing, wrong secret)
- [ ] Integration: tcpkali → handshake доходит до Velocity
- [ ] Ручной: реальный Minecraft клиент через edge

- [ ] **DoD v0.1:** Реальный игрок заходит через Edge → Velocity, HMAC работает, direct IP блокируется, `cargo test` проходит

---

### Этап 2: Registry + Redis — v0.2 (недели 5–7)
- [ ] `trait StateStore` + `impl StateStore for Redis`
- [ ] DashMap blacklist cache (TTL 5 мин)
- [ ] Pub/Sub `rampart:blacklist:events`
- [ ] Token bucket rate limiter per IP
- [ ] Graceful shutdown (SIGTERM)

#### rampart-manager
- [ ] Axum REST API: `GET /api/servers`, `POST /api/blacklist`
- [ ] JWT auth (Bearer token)

#### plugins/velocity
- [ ] ServerRegistry: delta-sync из Redis
- [ ] LoadBalancer: round-robin

#### plugins/paper
- [ ] ShieldAgent: писать в Redis (`rampart:servers`)
- [ ] HeartbeatTask: online/tps в Redis
- [ ] OnDisable: удалять себя из Redis

#### dashboard
- [ ] React + Vite
- [ ] Страница Servers (online, tps, статус)
- [ ] Страница Blacklist

- [ ] **DoD v0.2:** Серверы регистрируются автоматически, блэклист синхронизируется, dashboard работает

---

### Этап 3: Observability — v0.3 (недели 8–10)
#### rampart-core
- [ ] Prometheus метрики (порт 9090): connections, active, handshake duration, rate limit hits, blacklist size
- [ ] OpenTelemetry tracing (feature flag)
- [ ] Structured logs (JSON)

#### rampart-manager
- [ ] Prometheus метрики
- [ ] ClickHouse writer (batch, раз в сек, буфер 1000)
- [ ] ClickHouse schema: `rampart.blocked`

#### plugins/velocity
- [ ] Prometheus метрики: online, domain failures, registry size

#### plugins/paper
- [ ] Prometheus метрики: tps, mspt, online

#### dashboard / docs
- [ ] Grafana dashboard JSON
- [ ] Страница Attack Log
- [ ] `observability.md`

- [ ] **DoD v0.3:** Grafana показывает онлайн/TPS/блокировки, ClickHouse хранит логи, алерт на DDoS

---

### Этап 4: XDP + eBPF — v0.4 (недели 11–14)
#### xdp/
- [ ] `xdp_filter.c`: UDP drop, SYN rate limit, blacklist (LPM_TRIE)
- [ ] Ringbuf для событий (баны, rate limit hits)
- [ ] Rust loader (libbpf-rs, attach/detach)
- [ ] Feature flag: `xdp`

#### rampart-core
- [ ] Интеграция XDP loader в startup
- [ ] Чтение ringbuf → DashMap blacklist
- [ ] BPF stats → Prometheus

#### Тестирование
- [ ] `hping3 -S --flood` → XDP дропает, CPU < 30%
- [ ] `iperf3` UDP flood → XDP дропает

- [ ] **DoD v0.4:** SYN flood 1M pps дропается в XDP, CPU < 30%, XDP отключается feature flag

---

### Этап 5: Anti-Bot — v0.5 (недели 15–18)
- [ ] GeoIP lookup (maxminddb)
- [ ] ASN reputation (datacenter строже, mobile мягче)
- [ ] Adaptive rate limiting (EWMA)
- [ ] Bloom filter для whitelist

#### plugins/velocity
- [ ] Интеграция Sonar 3.0
- [ ] Custom challenge API (timing, map CAPTCHA)
- [ ] IP reputation score → Redis

- [ ] **DoD v0.5:** Боты блокируются, GeoIP работает, Sonar интегрирован

---

### Этап 6: Scale + HA — v0.6 (недели 19–24)
- [ ] WireGuard hub-and-spoke (CLI автоконфиг)
- [ ] Rust Load Balancer (SO_REUSEPORT, несколько инстансов)
- [ ] mTLS между всеми компонентами (rustls)
- [ ] QUIC канал Edge ↔ Manager

#### rampart-manager
- [ ] NATS JetStream (blacklist, drain)
- [ ] xDS-like API для динамической конфигурации
- [ ] Auto-discovery edge нод

#### rampart-cli
- [ ] `add-node`, `wg sync`, `drain`

- [ ] **DoD v0.6:** 5+ edge нод, drain без потери соединений, mTLS везде

---

### Этап 7: Polish — v0.7 (недели 25–28)
- [ ] io_uring runtime (feature flag, 5.10+)
- [ ] NUMA-aware allocation (bare metal)
- [ ] Zero-copy splice после handshake
- [ ] SLSA Level 3: signed releases, reproducible builds
- [ ] `cargo-vet`, secret rotation (dual-key HMAC)
- [ ] Docker images, GitHub Releases

- [ ] **DoD v0.7:** io_uring +30% throughput, релизы подписаны, доки позволяют поднять систему за час

---

## 2. Технический долг (Backlog)

- [ ] **Refactor:** Вынести `rampart-store` в отдельный crate
- [ ] **Refactor:** BufferPool на `crossbeam::queue::ArrayQueue`
- [ ] **Perf:** Registered buffers для io_uring
- [ ] **Feat:** Bedrock / RakNet (UDP модуль)
- [ ] **Feat:** Plugin API через WASM
- [ ] **Feat:** BGP Anycast (требует AS + /24)
- [ ] **Feat:** ML anomaly detection (IsolationForest)
- [ ] **Test:** Chaos engineering (random node kills)
- [ ] **Test:** Fuzzing для handshake parser (`cargo-fuzz`)

---

## 3. Definition of Done

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

## 4. Anti-Patterns

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

*Версия: 1.0 | Обновляется каждый понедельник*
