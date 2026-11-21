# Changelog

Все значимые изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [Semantic Versioning](https://semver.org/lang/ru/).

---

## [Unreleased]

### Added

- Anti-lockout: при старте edge предупреждает (`WARN`) о каждом активном SSH-клиенте, которого
  нет в `whitelist` (разбор `/proc/net/tcp{,6}`, без root).
- Startup-диагностика XDP: детект контейнера (lxc/openvz/docker), единая строка окружения
  для edge и `rampart-cli doctor`, вердикт и `hint:` в ошибках load/attach.
- `docs/architecture.md` — текущее устройство системы (процессы, путь трафика,
  слои, хранилища, метрики).
- `docs/development.md` — принципы, лимиты, гейты, Definition of Done.
- `docs/roadmap/` — по одному файлу на задачу; `TODO.md` стал тонким индексом.
- `CHANGELOG.md` — этот файл.
- `scripts/check_docs_links.sh` — проверка относительных ссылок в документации,
  запускается в CI.

### Changed

- `[profile.release]`: `lto = "thin"`, `codegen-units = 1`. Релизный бинарь с
  `protocol-http` уменьшился с 12.3 МБ до 9.7 МБ (−21%); `http_parser/evaluate`
  в criterion — 314 нс → 278 нс (−12%), остальные бенчмарки в пределах шума.
- CI: экшены обновлены до node24-версий, раннер закреплён на `ubuntu-24.04`.

### Fixed

- Docker edge image: в сборку добавлен `benches/`, без него Cargo не парсил
  манифест и образ не собирался (exit 101).
- `rampart-cli status` подсказывал неверный бинарь (`rampart doctor` вместо
  `rampart-cli doctor`).
- Документация приведена в соответствие с кодом: дефолты `[xdp]`/`[detect]`,
  имена метрик XDP, таблица ClickHouse (`rampart_events`), восстановление Redis
  из RDB, путь к схеме конфига, команда сборки BPF с multiarch-инклюдом.

### Removed

- Неиспользуемое поле `role` в JWT claims (RBAC не реализован; вернуть вместе с
  реальными ролями).

---

## [0.3.0-dev] — 2026-11-16

Big-bang редизайн: из Minecraft-специфичной защиты в универсальную L3/L4/L7
платформу.

### Added

- Единый пакет `rampart` с бинарями `rampart`, `rampart-manager`, `rampart-cli`,
  `rampart-tui`; Java-плагины и dashboard удалены.
- Протокол-плагины: `protocol-http` (HTTP/1.1 request-head) и
  `protocol-minecraft` (handshake/list/login, один upstream, PROXY v2).
- XDP: universal-фильтр для IPv4/IPv6, LPM blacklist/whitelist, SYN-throttle,
  UDP policy (pass/drop/rate-limit), prefix-статистика, RST-challenge,
  ringbuf-события и opt-in auto-ban.
- Subnet-level detection: prefix-статистика `/24` и `/64`, оценка числа
  источников по bitmap, лестница вердиктов strict → challenge → block.
- Traffic Intel в горячем пути: EWMA-детектор, репутация, авто-баны, webhook
  алерты на переход состояния.
- Manager API: pagination/`SCAN` вместо `KEYS`, rate-limit мутаций, body limit
  и таймауты, graceful shutdown, backfill метаданных blacklist, `X-Forwarded-For`
  только от `MANAGER_TRUSTED_PROXIES`.
- PROXY protocol v2 на входе: строгая валидация адреса, доверенные CIDR,
  запрет бана доверенных сетей.
- TUI-дашборд live-метрик; Prometheus `/metrics`.
- Инфраструктура: fuzz-цели `http_head` и `proxy_v2`, criterion-бенчмарки
  горячего пути, e2e-тест edge на loopback, netns-скрипты XDP.

### Changed

- IPv6-паритет XDP: blacklist, UDP rate-limit, prefix-статистика, whitelist.
- Expiry банов переведён на монотонные часы; просроченные префиксные баны
  удаляет userspace-reaper.
- Тесты вынесены из `src/` в `tests/` (правило «тесты отдельно от кода»).

### Fixed

- XDP: длина TCP-payload по `ip->tot_len` (Ethernet-паддинг), VLAN/QinQ до L3,
  фрагменты по blacklist, чтение map до `bpf_map_delete_elem` (UAF), `.rodata`
  раскладка и имена карт в загрузчике.
- Data path: backoff на `accept()`, корректный shutdown, глобальный бюджет,
  rate-limit до PoW, таймауты connect/handshake/relay.
- Blacklist: CIDR-баны диапазонами, нормализация IPv4-mapped, TOCTOU,
  атомарный `replace_redis`.
- Manager: auth bypass, утечки и зависания, найденные ревью.

### Security

- `API_PASSWORD` ≥ 16 символов и не `changeme`; `JWT_SECRET` ≥ 32 непробельных
  байт; audience-валидация.
- `syn_challenge_enabled` требует собственный секрет, placeholder отклоняется.
- Compose без публичных Redis/ClickHouse и без дефолтных паролей; пустой
  `CORS_ORIGIN` → cross-origin запрещён.

---

## [0.2.0] — 2026-07-20

- Первый публичный релиз: 6-слойный Minecraft-стек (XDP → PoW → Rust core →
  Velocity → Paper agent → Traffic Intel), Java-плагины и dashboard.
