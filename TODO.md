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
| **Аудит-фикс v0.3** | **открыт** — все P0/P1/P2 из code review 2026-08 (см. сек. 2) |
| **GeoIP/ASN reputation** | 0% — enum есть, реализации нет |
| **Bloom filter blacklist** | 0% |

### ⚠️ Ревизия статусов (после аудита 2026-08)

Прошлые строки «XDP 0%» / «PoW 0%» были устаревшими: код уже написан, но **не докатан**.
Реальное состояние (подробности — в сек. 2):

| Компонент | Реальность |
|-----------|------------|
| **xdp_filter.c + loader** | ~написан, но: не собирается в Docker/CI (feature `xdp` не в default), баги IPv6 (`daddr` вместо `saddr`), dead-код в `DIRECT_READ_LOGIN` |
| **PoW (Layer 2)** | ~написан, но **ломает ванильных клиентов** — по умолчанию никто не войдёт (P0) |
| **Layer 6 (Traffic Intel)** | написан, но **не подключён** ни в один hot path (мёртвый код) |
| **ClickHouse + Grafana** | врайтер написан, вызовов `push()` нет — мёртвый код |
| **Velocity physics** | написан, но **фейк**: не читает позиции, проверка по времени между событиями |
| **CAPTCHA** | написан, но `challenge()` нигде не вызывается — мёртвый код |

---

## 2. Аудит-фикс v0.3 (code review 2026-08) — закрыть до релиза

> Полный список минусов из ревью. Философия: «мёртвый код = баг», «по умолчанию безопасно».

### P0 — Showstopper (блокируют релиз)

- [x] **PoW совместимость с ванильными клиентами.** Решение (a): **PoW off по умолчанию** (`config.rs`), код PoW сохранён, включение только с клиентским модом или MC-совместимым PoW. README + docs + `deploy/config/edge.toml` обновлены. Follow-up (клиентский мод / PoW поверх MC) — в backlog.
- [x] **`API_PASSWORD` без дефолта.** Fail-fast при старте (нет env или `changeme` → ошибка), constant-time сравнение (`subtle`), rate-limit 5/60с на `/api/v1/auth/login` (429), `CorsLayer::permissive()` → `CORS_ORIGIN` из env. Неверный пароль → 401.
- [x] **Чтение полного кадра.** `read_full_frame()` в `tunnel.rs`: накопление по varint-длине, лимит 8192, таймаут, EOF/ошибки → death-code path.
- [x] **IPv6.** Полная поддержка: rate-limit/blacklist/whitelist переведены на `IpAddr` (DashMap<IpAddr>), `redis.rs` парсит через `IpAddr::parse`, whitelist валидируется на старте. Попутно исправлен overflow-panic в redis.rs (octet > 255). XDP остаётся IPv4-only (задокументировано).

### P1 — Безопасность

- [ ] **HMAC**: nonce/timestamp + TTL в подпись; реализовать ротацию ключей (dual-key) и задействовать `key_rotation_interval_secs` (сейчас мёртвый конфиг). Детерминированная подпись = вечная утечка.
- [ ] **RateLimiter**: TTL-эвикция idle bucket'ов (фоновый sweep) + cap размера карты — иначе ботнет съест память.
- [ ] **Blacklist**: вызывать `clear_expired()` по таймеру (сейчас мёртвый код).
- [ ] **Redis IP-parse**: валидировать октеты ≤ 255 (`redis.rs:95`) — сейчас `(ip_u32<<8)|octet` с октетом >255 даёт **panic** в debug.
- [ ] **JWT**: валидация ролей/audience, secret ≥ 32 байт, rate-limit на login.

### P1 — Целостность слоёв

- [ ] **XDP в Docker/CI**: собирать `rampart-core --features xdp`, clang+libbpf в builder-образ, smoke-attach в CI.
- [ ] **Синхронизация blacklist Rust ↔ XDP**: `XdpFilter::ban_ip` вызывать при death-code бане; TTL из конфига, не хардкод 300с.
- [ ] **Подключить Layer 6** (`AttackDetector`/`IpReputation`/`TrafficProfiler`) в hot path: метрики, reputation-скоринг, auto-ban.
- [ ] **Подключить ClickHouse**: реальные `push()` из hot path + flush task + таблица (сейчас мёртвый код).
- [ ] **CAPTCHA**: вызвать `challenge()` на входе ИЛИ удалить (сейчас мёртвый код; `markVerified`/`verifiedPlayers` пишутся, но не читаются).
- [ ] **`routeServer(domain)`**: реализовать доменную маршрутизацию по `ServerInfo` (сейчас параметр игнорируется, только round-robin).

### P2 — Баги и долг

- [ ] **XDP IPv6**: `src_ip = ip6->daddr` (`xdp_filter.c:141`) → исправить на `saddr`; иначе whitelist/blacklist/flow-ключи по чужому IP.
- [ ] **XDP seq-трекинг**: пересмотреть `expected_seq`; убрать dead-код в `DIRECT_READ_LOGIN` (`login_consumed < (end-cursor)` всегда false).
- [ ] **Порядок фильтров**: rate limit ДО PoW (сейчас PoW-работа тратится на rate-limited IP); убрать двойной `check()` на соединение (съедает 2 токена).
- [ ] **`std::sync::Mutex` в async** (`DifficultyAdjuster` в `tunnel.rs`) → `tokio::sync::Mutex`/атомика; whitelist-сравнение по строке → пре-парс IP/CIDR.
- [ ] **`replace_hostname`**: проверка длины подписанного hostname ≤ 255 (добавка сигнатуры выбивает длинные домены).
- [ ] **Physics**: переделать на реальные данные позиций или удалить фейковый falling check; «re-verify» должен реально что-то проверять, а не дисконнектить.
- [ ] **Redis**: `KEYS` → `SCAN` (manager + `ServerRegistry`), TTL на ключи серверов (иначе мусор копится), **reconnect** pubsub-подписчика (сейчас умирает навсегда).

### P2 — Мёртвый код / конфиг

- [ ] Удалить или использовать: `max_connections_per_ip`, `rate_limit_status_pps`, `logging.level/format`, `ACTIVE_CONNECTIONS`, `BLACKLIST_SIZE`, `io-uring`/`tokio-splice`, `ClickHouseWriter` без вызовов.
- [ ] **Manager blacklist**: хранить reason/created/expires, применять `duration_secs` (сейчас фабрикуются фейковые поля).
- [ ] **CLI**: `drain`/`emergency` из заглушек → реальная логика или явный `unimplemented`.
- [ ] **README**: убрать неподтверждённые цифры (io_uring 110k, XDP 15–20M pps), привести в соответствие коду и TODO.

**DoD этапа 0:** все P0 закрыты, P1/P2 закрыты или явно задекларированы как «позже с issue», `cargo test` + `cargo clippy -D warnings` + Java build + Docker (с XDP) зелёные.

---

## 3. Anti-Regression — как не допускать

> Каждая фича обязана пройти чеклист ниже. Мёртвый код, «бумажные слои» и дефолт-секреты = reject на ревью.

### Правила

1. **No dead code**: каждый `pub` в prod-модуле имеет вызов вне `#[cfg(test)]`. Если компонент не вызывается — он не существует (CAPTCHA, ClickHouse, Layer 6).
2. **Config field = потребитель**: нет конфиг-поля без использования. Добавил поле — сразу потребитель (или не добавляй).
3. **Метрика регистрируется → обновляется**: каждый Gauge/Counter имеет единственного «writer»; ревью проверяет, что `inc`/`set` реально вызываются.
4. **Feature flag = сборка в CI**: любое `feature` собирается в CI (`--all-features` уже есть) и в Docker-образе. «Фича не в образе» = фичи нет.
5. **По умолчанию безопасно**: нет дефолтных секретов/паролей; отсутствие обязательного env = fail-fast, а не warn.
6. **Интеграционный тест на слой**: PoW+handshake (симуляция ванильного клиента), XDP attach smoke, Redis sync, router по домену.
7. **Парсеры читают полный кадр**: никогда «один read» для MC-пакета; неполный кадр = accumulate или отказ, но не молчаливый drop валидного клиента.
8. **Listener/Handler = вызывается**: новый Java-listener или Rust-модуль подключается в `main`/plugin `onEnable`, иначе reject.
9. **CI guardrails** (добавить в `.github/workflows/ci.yml`):
   - [ ] `cargo clippy --all-targets --all-features -- -D warnings`
   - [ ] `cargo test` (уже есть) + сборка XDP (`clang -target bpf`) + Docker build с `--features xdp`
   - [ ] grep-проверка отсутствия дефолт-секретов: `changeme`, `password = "` в коде/конфигах
   - [ ] Java build (уже есть) + `./gradlew test`
10. **README/TODO не врут**: каждое заявленное число/слой имеет ссылку на код или тест. Нет — не пишем.

---

## 4. 6-слойная архитектура (план)

```
Layer 1: XDP/eBPF (C)        TCP state machine, SYN throttle, blacklist, UDP drop
Layer 2: PoW Challenge (Rust) SHA256 hashcash, dynamic difficulty
Layer 3: Rust Core (Rust)     MC handshake, HMAC sign, rate limit, death code
Layer 4: Velocity (Java)      Domain whitelist, HMAC verify, physics, CAPTCHA
Layer 5: Paper Agent (Java)   Redis heartbeat, auto-registration
Layer 6: Traffic Intel (Rust) EWMA thresholds, 168h profiling, reputation
```

---

## 5. Этапы разработки

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

## 6. Backlog

- [ ] Bedrock / RakNet (UDP модуль)
- [ ] Plugin API через WASM (как Infrarust)
- [ ] BGP Anycast (требует AS + /24)
- [ ] ML anomaly detection (Isolation Forest — многомерный, не univariate)
- [ ] Fuzzing для handshake parser (`cargo-fuzz`)
- [ ] Chaos engineering (random node kills)

---

## 7. Definition of Done

```
☐ cargo check / cargo test проходят
☐ cargo clippy -- -D warnings — 0 warnings
☐ cargo fmt --check проходит
☐ Unit тесты покрывают happy path + 2+ error cases
☐ Интеграционный тест проходит (PoW+handshake, XDP smoke, Redis sync)
☐ Нет мёртвого кода: каждый pub-модуль/конфиг-поле/метрика имеют потребителя
☐ Нет дефолтных секретов/паролей (grep-чек в CI)
☐ Docker-образ собирает те же features, что CI (включая XDP)
☐ README соответствует коду (нет «бумажных» цифр/слоёв)
☐ Документация обновлена
☐ CI зелёный
```

---

## 8. Anti-Patterns

```
❌ Тесты после кода. Пиши до (TDD) или вместе.
❌ Коммиты в main напрямую. Только PR.
❌ TODO в коде без issue. TODO = баг.
❌ Оптимизация без профиля.
❌ Зависимость ради 1 функции.
❌ async где хватит sync.
❌ Секреты в репозитории. Используй .env + SOPS.
❌ Игнор compiler warnings.
❌ Мёртвый код: pub без вызовов, конфиг-поле без потребителя, метрика без writer.
❌ «Бумажный слой»: фича в README/архитектуре, которой нет в коде или она не вызывается.
❌ Дефолтный секрет: `changeme`/`password="..."` в коде или конфиге.
❌ Парсер за «один read» — MC-пакет может прийти фрагментами.
❌ Feature flag, который не собирается в Docker/CI — фичи нет.
```

> Статус секций 5–8: план на будущее. Актуальный приоритет — **Аудит-фикс v0.3 (сек. 2)**: закрыть P0/P1/P2 до релиза.

---

*Версия: 3.0 | Обновлён: август 2026 (аудит-фикс v0.3)*
