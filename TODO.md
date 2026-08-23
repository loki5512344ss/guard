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
- **Функция ≤ 60 строк, модуль ≤ 300 строк** (жёсткий лимит; больше — декомпозиция).
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
├── src/
│   ├── bin/{rampart, rampart-manager, rampart-cli}.rs
│   ├── engine/                 # listener, tunnel (generic TCP proxy), challenge (PoW)
│   ├── filter/                 # blacklist, rate_limit, geo — trait Filter
│   ├── traffic/                # EWMA, detector, profiler, reputation, alert
│   ├── store/                  # redis (+ trait StateStore)
│   ├── manager/                # api/, auth/, sync/
│   ├── cli/                    # команды CLI
│   └── protocol/               # trait ProtocolHandler + registry (реализаций пока 0)
├── xdp/
│   ├── core/                   # universal_filter.c + maps/stats/config/common.h
│   └── hooks/hook_api.h        # контракт подключаемых BPF-протокол-хуков
├── tests/                      # интеграционные
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

### Subnet-level detection (ботнет с ротацией IP)
- [ ] **XDP**: карта `prefix_stats` (LRU_HASH, ключ /24 v4 | /64 v6) — счётчики SYN/pps
      per-префикс рядом с per-IP (референс: caddy-mitigator CIDR promotion, lnvps_fw carpet-bomb).
- [ ] **Detector**: префикс превышает порог при том что отдельные IP под лимитом
      → распределённая атака → флаг подсети.
- [ ] **Мягкая эскалация для подсетей**: monitor → strict limits → challenge → блок.
      Хард-бан /24 только через challenge (CGNAT: за одним /24 легитимно живут сотни людей).
- [ ] Блок самой подсети — уже умеем: `blacklist_map` это LPM trie (CIDR из коробки).

### Движок без протоколов — сделать полезным
- [ ] **Первый протокол-плагин**: `protocol-http` (feature) — минимальный HTTP/1.1
      handshake-анализ (request line, заголовки, размер), чтобы edge-нода заработала
      для веб-сервисов.
- [ ] **TCP-proxy режим**: generic upstream forwarding за ProtocolHandler
      (tunnel.rs уже generic — проверить интеграцию).
- [ ] **Fail-fast сообщение** при пустом registry — улучшить текст подсказки сборки.

### Подключение мёртвого интеллекта (правило: «мёртвый код = баг»)
- [ ] Layer Traffic Intel подключить в hot path: AttackDetector/IpReputation →
      метрики + auto-ban (сейчас не вызывается).
- [ ] Blacklist: `clear_expired()` по таймеру.
- [ ] RateLimiter: TTL-эвикция idle bucket'ов + cap карты.

### Безопасность (перенос из аудита v0.3, актуальное)
- [ ] Rate limiter на login endpoint manager API (5/60с).
- [ ] JWT: валидация ролей/audience, secret ≥ 32 байт.
- [ ] Redis: `KEYS` → `SCAN`, reconnect pubsub-подписчика.

### XDP
- [ ] Verifier-проверка на реальном ядре (в контейнере нет CAP_BPF — компиляция OK,
      загрузка не проверялась).
- [ ] Rust loader (`src/xdp/`): пути к xdp/core/universal_filter.c, patch глобалов
      G_* из config.toml, ringbuf events → blacklist.
- [ ] Smoke-test attach в CI (VM runner с CAP_BPF).

### Документация
- [ ] docs/deployment.md, configuration.md, runbook.md — переписать под новую структуру
      (сейчас упоминают старые крейты/MC).
- [ ] docs/kb/README.md — индекс KB со ссылками на все статьи.
- [ ] TUI (ratatui): live-метрики из Prometheus endpoint (planned, v0.4).

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
7. **Модуль ≤ 300 строк**: CI-гейт через grep/wc скрипт или ревью.
8. **CI guardrails**: `cargo clippy --all-targets -- -D warnings`, `cargo test`,
   clang-build xdp/core/universal_filter.c, grep на `changeme`.
9. **README/TODO не врут**: каждое число имеет ссылку на тест или отчёт.

## 5. Definition of Done

```
☐ cargo check / cargo test проходят
☐ cargo clippy --all-targets -- -D warnings — 0 warnings
☐ cargo fmt --check проходит
☐ Ни один модуль не превышает 300 строк
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
❌ Модуль > 300 строк — сигнал декомпозировать немедленно.
❌ TODO в коде без issue.
❌ Мёртвый код: pub без вызовов, конфиг-поле без потребителя, метрика без writer.
❌ «Бумажный слой»: фича описана, но не вызывается.
❌ Дефолтный секрет.
❌ Парсер за «один read» — TCP-поток приходит фрагментами.
❌ Feature flag, который не собирается в CI.
```

---

*Версия: 4.0 | Обновлён: 2026-08-24 (universal redesign)*
