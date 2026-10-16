# Rampart — Development TODO & Roadmap

> Живой документ. Философия: **KISS → DRY → SOLID → YAGNI**.
>
> v0.3.0-dev — big-bang редизайн: из Minecraft-специфичной защиты в **универсальную
> L3/L4/L7 платформу сетевой защиты**. MC-код, Java-плагины и dashboard удалены
> (доступны в git-истории до тега v0.2.0).

---

## 0. Принципы разработки

### KISS
- Не добавляй абстракцию до третьего повторения.
- **Функция ≤ 60 строк, файл ≤ 250 строк, ≤ 4 .rs-файлов на папку** (жёсткий лимит;
  больше — декомпозиция или группировка доменами с ре-экспортами в mod.rs).
  Гейт: `scripts/check_module_size.sh` + ratchet-базлайн `.module_size_baseline`
  (легаси — WARN, новые нарушения — FAIL; после рефакторинга `--update-baseline`).
- Не используй generics где хватит `&str` и `Vec<u8>`.

### DRY
- Повтор > 2 раз → выноси, но лучше копипаста чем неправильная абстракция.

### SOLID (Rust)
- **S**: один файл = одна ответственность
- **O**: расширяй через трейты (`ProtocolHandler`, `Filter`, `StateStore`)
- **L**: `dyn Filter` — любая реализация без side effects
- **I**: маленькие трейты вместо одного God-trait
- **D**: core зависит от trait-ов, не от Redis/ClickHouse напрямую

### YAGNI
- Не пиши BGP до v0.6, WASM-плагины до стабилизации compile-time API.
- Не добавляй feature flag если фича не готова.

### Rust-специфичные
1. `unwrap()` — только в main() и тестах
2. `unsafe` — только в xdp/, комментарий `// SAFETY:` обязателен
3. `clone()` осознанно, профилируй hot path
4. Блокирующие операции → `spawn_blocking`
5. Логи: `tracing::info!` / `debug!` / `error!`
6. Метрики: register один раз при старте, инкремент в hot path

---

## 1. Целевая структура (v0.3)

```
guard/
├── Cargo.toml                  # ОДИН пакет rampart, features = ["protocol-http", ...]
├── scripts/                    # check_module_size.sh (гейт 250/4), check_default_secrets.sh
├── src/
│   ├── bin/{rampart, rampart-manager, rampart-cli, rampart-tui}.rs   # тонкие, логика в lib
│   ├── app/                    # thin-main: runtime wiring, services (spawn-циклы)
│   ├── engine/                 # listener, tunnel; challenge/ (pow+difficulty), subnet/ (tracker+monitor)
│   ├── filter/                 # blacklist, rate_limit, geo — trait Filter
│   ├── traffic/                # hook + prefix/ (key+stats) + intel/ (ewma,detector,reputation) + profile/ (profiler,alert)
│   ├── store/                  # redis (+ trait StateStore)
│   ├── manager/                # api/ (+ api/inventory/), auth/, sync/
│   ├── cli/                    # команды; commands/node/ (status,drain,emergency)
│   ├── config/                 # config + sections/{edge,platform,detect}
│   ├── tui/                    # app/state/ui + metrics/ (prometheus,fetch)
│   ├── protocol/               # trait ProtocolHandler + registry; http/ под фичей
│   └── xdp/                    # filter/ (attach,maps), probe/ (diagnostics/,stats,metrics), globals, noop
├── xdp/
│   ├── core/                   # universal_filter.c + maps/stats/config/common.h + prefix_stats/syn_challenge
│   └── hooks/hook_api.h        # контракт подключаемых BPF-протокол-хуков
├── tests/                      # интеграционные (вне гейта 4-файлов: cargo требует 1 файл = 1 бинарь)
└── docs/                       # kb/ (knowledge base) + research/ + ops-доки
```

## 1a. Статус после редизайна (2026-08-24)

| Что | Статус |
|-----|--------|
| plugins/ velocity+paper, dashboard/ | ✅ удалены (git-история) |
| crates/* → единый пакет `rampart` + src/bin | ✅ сделано |
| MC-код (handshake, death_code, varint, hostname-HMAC) | ✅ удалён полностью |
| PoW как универсальный hashcash (`engine/challenge.rs`) | ✅ сохранён |
| XDP: universal L3/L4 фильтр + hooks API | ✅ код готов, clang build OK |
| IPv6 баг в XDP (daddr→saddr) | ✅ исправлен |
| Knowledge Base docs/kb (attacks, defense-levels, practice) | ✅ написана, двуязычная |
| README + architecture.md под новую концепцию | ✅ переписаны |
| cargo build / clippy -D warnings / test | ✅ зелёные |

---

## 2. Ближайшие задачи (v0.3)

### Subnet-level detection (ботнет с ротацией IP) — ✅ готово (2026-08/09)
- [x] **XDP**: карта `prefix_stats` (LRU_HASH, ключ /24 v4 | /64 v6) — счётчики SYN/pps
      per-префикс (xdp/core/prefix_stats.h, трафик-слой: src/traffic/prefix/).
- [x] **Detector**: превышение порога префиксом при IP под лимитом → флаг подсети
      (src/traffic/intel/detector.rs, src/engine/subnet/).
- [x] **Мягкая эскалация**: monitor → strict_limit → challenge → block
      (SubnetVerdict-лестница; блок /24 идёт через ban_cidr, не слепой hard-ban).
- [x] Блок подсети через `blacklist_map` (LPM trie) — `XdpFilter::ban_cidr`.

### Движок без протоколов — сделать полезным — ✅ готово
- [x] **Первый протокол-плагин**: `protocol-http` — HTTP/1.1 request-head анализ
      (src/protocol/http/, tests/http_protocol.rs).
- [x] **Minecraft Java TCP MVP**: ограниченный handshake status/login, передача исходных
      байтов backend и опциональный PROXY protocol v2 (`protocol-minecraft`).
- [x] **TCP-proxy режим**: tunnel.rs + ProtocolHandler интегрированы в listener/app wiring.
- [x] **Fail-fast сообщение** при пустом registry (`ProtocolRegistry::primary()`).

### Подключение мёртвого интеллекта (правило: «мёртвый код = баг») — ✅ готово
- [x] Traffic Intel в hot path: AttackDetector/IpReputation → метрики + auto-ban
      (src/traffic/hook.rs, src/engine/tunnel.rs, src/app/services.rs).
- [x] Blacklist: `clear_expired()` по таймеру (src/app/).
- [x] RateLimiter: TTL-эвикция idle bucket'ов.

### Безопасность — ✅ кроме ролей
- [x] Rate limiter на login endpoint manager API (per-IP, tests в api/auth.rs).
- [x] JWT: audience-валидация, secret ≥ 32 байт fail-fast (rampart-manager.rs).
- [ ] JWT-роли: сейчас единственный hardcoded `admin`; RBAC-ролей нет — либо убрать поле,
      либо делать роли (решение отложить до второго потребителя).
- [x] Redis: `KEYS` → `SCAN` (scan_options), pubsub-подписчик — честный reconnect
      с экспоненциальным backoff (src/store/redis.rs).

### XDP
- [x] Verifier-проверка на реальном ядре (live-тест 2026-09: два бага RST-challenge найдены и
      исправлены, d6bcae5).
- [x] Rust loader (`src/xdp/filter/`): open/load/attach, patch глобалов G_* из config.toml
      (src/xdp/globals.rs), CString-safe if_nametoindex, реальный detach по fd прогрессы.
- [x] Ringbuf events → blacklist: opt-in `auto_ban` ([xdp] config, default OFF) —
      EVENT_RATE_LIMIT всегда, EVENT_CONN_DROP при fails>=порога; EVENT_BAN/POLICY_DROP не
      банят (ядро уже отработало / статик-политика без аккумуляции). Парсер 24-байтного
      `struct xdp_event` с фиксом endianness (IP — сетевой порядок, скаляры — host),
      метрика `rampart_xdp_autobans_total`, tests/xdp_events.rs (10 тестов).
- [ ] Smoke-test attach в CI (VM runner с CAP_BPF) + netns+veth харнесс — вывод №7 из
      конкурентного анализа, приоритет v0.4.

### Документация
- [x] docs/deployment.md, configuration.md, runbook.md — старых крейтов/MC не упоминают (grep чисто).
- [x] docs/kb/README.md — индекс KB со ссылками.
- [x] TUI (ratatui): live-метрики из Prometheus endpoint — готово (src/tui/, 564613b).

## 2a. Раунд 2026-09-15 — исправлено по итогам ревью

- **unsafe-баги XDP-лоадера** (src/xdp/filter/): `&str.as_ptr()` без NUL в `if_nametoindex` → `CString`;
  фиктивный `borrow_raw(-1)`-fd в `unload()` → реальный detach по fd прогрессы с propagatable ошибкой;
  `unsafe impl Send` получил `// SAFETY:`; `saturating_mul` в expiry. +5 юнит-тестов.
- **Redis**: fake-reconnect pubsub (sleep+return) → настоящий reconnect-loop с backoff;
  `KEYS` → `SCAN` в heartbeat.
- **CI**: `cargo test --all-features` (раньше тесты фич не гонялись); job `repo-gates`:
  гейт 250/4 + grep дефолтных секретов; Makefile `ci` обновлён.
- **README**: несуществующие `rampart-core`/`rampart config init` → реальные команды;
  таблица компонентов/плагинов приведена к коду (http готов, minecraft удалён, добавлен rampart-tui).
- **Рефакторинг под новые лимиты 250/4** без изменения поведения: app/, challenge/, subnet/,
  prefix/, intel/, profile/, commands/node/, api/inventory/, tui/metrics/, filter/, probe/;
  bin-файлы тонкие (rampart.rs: 330 → 6 строк).

### Новые найденные проблемы (чинить в v0.4)
- [ ] Redis blacklist: сохранять срок/причину бана и восстанавливать edge-состояние после reconnect;
      Pub/Sub сейчас только для подключённых узлов.
- [ ] Minecraft Java: Velocity modern forwarding, игровые netns smoke-тесты и нагрузочная проверка.
- [ ] Принимать client IP от внешнего DDoS-прокси через доверенный inbound PROXY protocol.
- [x] `cargo check --no-default-features` починен (2026-09-15, раунд 2): redis-код в
      manager/sync/api/store/app закрыт `#[cfg(feature = "store-redis")]`, менеджер без фичи fail-fast'ит на старте;
      CI теперь гоняет `cargo check --no-default-features --all-targets` гейтом.
- [x] `src/app/runtime.rs`: `#[allow(clippy::exit)]` убран — `app::run()` возвращает
      `RunExit`, единственный `process::exit` теперь в `main` бина (clippy там не срабатывает).
- [x] Флакающий тест `pow_roundtrip::verifier_rejects_garbage_and_replay` (p≈1/16 из-за
      случайного токена) — сидирован, 50 прогонов до (3 fail) / после (0 fail).
- [ ] IPv6-банов в XDP-putи нет (`ban_cidr` bail'ит на v6) — IPv6-паритет (вывод №8).

## 3. Backlog

- [ ] protocol-gRPC plugin (после http)
- [ ] BPF hook #1 реальный: HTTP поверх XDP (rate-limit до userspace)
- [ ] GeoIP/ASN reputation (enum есть, реализации нет)
- [ ] Bloom filter для blacklist
- [ ] io_uring runtime (feature flag)
- [ ] ML anomaly detection (Isolation Forest)
- [ ] Fuzzing парсеров (`cargo-fuzz`)
- [ ] BGP Anycast (AS + /24)

---

## 3a. Бенчмарк-конкуренты: чем превзойти

> Все репо склонированы в `ref/` (gitignored). Анализ issues/PRs проведён 2026-08-24
> через gh по трекерам конкурентов. Ниже — выжимка «что у них болит и что берём».

### Карта конкурентов

| Проект | Что это | Похож на Rampart тем, что | Что взять |
|--------|---------|---------------------------|-----------|
| [eBPFsentinel](https://github.com/ebpfsentinel/ebpfsentinel) | Rust, один бинарник: firewall+IDS+DDoS через XDP/TC/uprobe | Ближайший аналог, та же архитектура | Rootless BPF token (kernel 6.9+); tail-call цепочки; MITRE-теги алертов; Swagger UI |
| [CrabShield](https://github.com/aleksgrim/crab-shield) | Rust + XDP, гибрид L7→L3 | «Умный юзерспейс, кара в ядре» | Static musl бинарник; reaper истекающих банов; (log-tailing НЕ брать — хрупко) |
| [lnvps_fw](https://github.com/LNVPS/api) | XDP+TC защита VDS | Прямо наша ниша | ⭐ SYN-proxy в XDP; port learning из TC egress; лестница PORT_FILTER→SYN_PROXY→SOURCE_BLOCK + spoof gate; netns+veth harness |
| [Oubliette](https://f0o.dev/projects/2026/04/oubliette/) | Linerate scrubber | Решает нашу боль с PoW | ⭐ RST-challenge: SYN-ACK с неверным ACK → спуф молчит, живой клиент шлёт RST → whitelist. Совместимо с любым клиентом |
| [Couic](https://github.com/fcsc-fr/couic) (CERT Франции) | XDP-фаервол + REST API | Наш manager API | Anti-lockout; теги+TTL записей; OpenAPI spec; синк инстансов; fail2ban-интеграция |
| [gamemann/XDP-Firewall](https://github.com/gamemann/XDP-Firewall) (~830★) | Классический C XDP-фаервол | Референс по XDP | Pinned maps для внешнего управления; их issues = карта граблей верификатора |
| [gen0sec/synapse](https://github.com/gen0sec/synapse) | NDR: eBPF + JA4-фингерпринты + ratatui TUI | TUI как наш план | JA4+/JA4T фингерпринтинг (бан по отпечатку); fallback-цепочка XDP→nftables→iptables |

### Топ-10 выводов из их issues/PRs (приоритет)

1. **Диагностика окружения при старте** — проверять ядро/BTF/driver NIC до загрузки,
   человекочитаемый вердикт. ≈80% issues XDP-Firewall — про attach на неподдерживаемом
   окружении (#70/#71/#9/#44). Печатать режим (native/generic) честно.
2. **Эскалационная лестница защиты** (lnvps_fw): pass-all steady state → PORT_FILTER →
   SYN_PROXY (tail-call, keyed cookie, ротация секрета) → SOURCE_BLOCK только со spoof-gate.
3. **RST-challenge** (Oubliette) вместо мёртвого текстового PoW — универсально совместимо.
4. **REST API + OpenAPI + pinned maps**: динамические IP-списки без перекомпиляции —
   самый частый feature request (#79/#77/#78 у gamemann); web-панель так и не сделана автором = свободная ниша.
5. **Anti-lockout + per-port баны**: слепой XDP_DROP по IP = self-lockout по SSH
   (crab-shield docs). Whitelist обязателен, но не единственная защита.
6. **LRU во всех data-path maps** — иначе silent default-deny под атакой (netshield DD-003).
   Per-src-IP rate limit не работает против spoofed flood 50–100 Mpps (gamemann #45) —
   нужны per-port/per-subnet/flow агрегаты.
7. **netns+veth тестовый харнесс** + eBPF test_run тесты в CI (подтверждено в 2 проектах,
   отсутствует у всех) — наше конкурентное преимущество в надёжности.
8. **IPv6-паритет с первого дня** + VLAN/QinQ парсинг (issue #75 висит годами).
9. **Rootless BPF token как опция**, fallback CAP_BPF для ядер 5.15+ — не повторять жёсткий
   floor 6.9+ (ebpfsentinel отсёк enterprise) и не требовать root (crab-shield).
10. **События атак наружу с первого дня**: poll-and-persist, дедуп алертов на переходе
    состояния (урок LNVPS #331 — отложили = дыра в продукте).

### Наши козыри (чем превзошли уже)

- Двуязыная Knowledge Base (docs/kb/) — educational killer-feature, нет ни у одного конкурента
- Один Rust-бинарник без C-зависимостей сборки (класс сегфолтов/libbpf-hell gamemann исключён)
- Честные бенчмарки: цифры только с отчётами, методология опубликована
- Модульный лимит ≤300 строк + no-dead-code политика в CI

---

## 4. Anti-Regression — правила приёмки

1. **No dead code**: каждый `pub` имеет вызова вне `#[cfg(test)]`.
2. **Config field = потребитель**: нет поля без использования.
3. **Метрика регистрируется → обновляется**: единственный writer на каждую метрику.
4. **Feature flag = сборка в CI**: `--all-features` зелёный, иначе фичи нет.
5. **По умолчанию безопасно**: нет дефолтных секретов; отсутствие обязательного env = fail-fast.
6. **Интеграционный тест на слой**: config parse, filter logic, registry fail-fast (есть);
   новый слой = новый тест.
7. **Файл ≤ 250 строк, папка ≤ 4 .rs**: CI-гейт `scripts/check_module_size.sh`
   (ratchet-базлайн `.module_size_baseline`: легаси — WARN, новые нарушения — FAIL).
8. **CI guardrails**: `cargo clippy --all-targets -- -D warnings`, `cargo test`,
   clang-build xdp/core/universal_filter.c, grep на `changeme`.
9. **README/TODO не врут**: каждое число имеет ссылку на тест или отчёт.

## 5. Definition of Done

```
☐ cargo check / cargo test проходят
☐ cargo clippy --all-targets -- -D warnings — 0 warnings
☐ cargo fmt --check проходит
☐ Ни один файл не превышает 250 строк; ни в одной папке src/ больше 4 .rs-файлов
☐ Unit тесты покрывают happy path + 2+ error cases
☐ Нет мёртвого кода: pub без вызовов, конфиг-поле без потребителя, метрика без writer
☐ Нет дефолтных секретов
☐ README соответствует коду
☐ Документация обновлена
☐ CI зелёный
```

## 6. Anti-Patterns

```
❌ Тесты после кода. Пиши вместе.
❌ Файл > 250 строк или > 4 .rs в папке — сигнал декомпозировать/сгруппировать немедленно.
❌ TODO в коде без issue.
❌ Мёртвый код: pub без вызовов, конфиг-поле без потребителя, метрика без writer.
❌ «Бумажный слой»: фича описана, но не вызывается.
❌ Дефолтный секрет.
❌ Парсер за «один read» — TCP-поток приходит фрагментами.
❌ Feature flag, который не собирается в CI.
```

---

*Версия: 5.0 | Обновлён: 2026-09-15 (bug-fix раунд: XDP unsafe, Redis reconnect/SCAN, CI-гейты, лимиты 250/4)*
