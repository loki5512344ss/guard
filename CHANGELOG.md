# Changelog

Все значимые изменения проекта. Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [Semantic Versioning](https://semver.org/lang/ru/).

---

## [Unreleased]

### Added

- `scripts/xdp_challenge_test.sh` и фаза `chal` в `xdp_ci.sh`: живой клиент за conntrack
  INVALID DROP проходит, повторное соединение без нового challenge, спуф не верифицируется,
  поддельный RST засчитывается как failed. На старом коде фаза падает.
- XDP: RST-challenge для нативного IPv6 — карты `challenge_pending6`/`challenge_verified6`
  со 128-битными ключами, общая с IPv4 логика SYN/RST. SYN за IPv6 extension-заголовками (и
  IPv4-mapped IPv6 с ними) при включённом challenge дропается, как IPv4 с опциями.
  `xdp_challenge_test.sh` проверяет v6: живой клиент за ip6tables INVALID DROP, спуф, forged RST.
- Документация: матрица «протокол → PoW / RST-challenge» в configuration.md, раздел про
  challenge и его метрики в runbook. Ошибка `pow.enabled` + Minecraft подсказывает RST-challenge.
- Minecraft: строгий автомат handshake→login/status (дубли handshake/login-start, login до
  handshake, плохой hostname/next_state/версия/ник → тихое закрытие); лимиты кадра по фазе до
  буферизации (handshake 2048, login-start 5120, status request 64, настраиваются в
  `[protocol.minecraft]`); таблица версий протокола, `min/max_protocol_version` и
  `deny_protocol_versions`; метрики `rampart_mc_handshake_total{result,reason}` и
  `rampart_mc_protocol_version_total{version}`.
- CLI: `rampart-cli blacklist add --for 1h30m` принимает человекочитаемые длительности (`30s`,
  `5m`, `1h30m`, `2d`), голое число отвергается с подсказкой; `blacklist list` показывает
  оставшееся время.
- API: `POST /api/v1/blacklist` принимает абсолютный `expires_at` (unix-секунды) вместо
  `duration_secs`; ответ содержит `expires_at`.
- Тесты: ABI-раскладка Rust-зеркал BPF-структур, порядок байт IPv6-ключей, валидация CIDR,
  суммирование per-CPU счётчиков.
- `scripts/xdp_ci.sh` — единая точка входа XDP-проверок на реальном ядре (`RESULT … PASS|FAIL|SKIP`,
  честный SKIP без прав/инструментов, `--require`), CI-job `xdp-kernel`. Smoke получил фазу
  recovery (`ip link set dev <if> xdp off` после `kill -9`).
- Баны по порту: `Blacklist::add_port` / `is_blocked_on` (userspace, локально для узла, XDP-ABI
  не менялся); gateway проверяет бан с учётом локального порта соединения.
- Диагностика XDP определяет права по `CapEff`, а не по uid: root в контейнере без
  CAP_BPF/CAP_NET_ADMIN больше не считается «privileged», hint подсказывает `--cap-add`.
- `scripts/xdp_stress.sh` — нагрузочный прогон SYN-флуда в netns (pps, дропы, CPU, живой клиент).
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

- `chrono` заменён на `time` (новый модуль `timeutil`): RUSTSEC-2026-0543 помечает `chrono` как
  неподдерживаемый, `cargo deny` падал. Формат на проводе тот же (RFC 3339, но UTC теперь с
  суффиксом `Z`, а не `+00:00`).
- `[profile.release]`: `lto = "thin"`, `codegen-units = 1`. Релизный бинарь с
  `protocol-http` уменьшился с 12.3 МБ до 9.7 МБ (−21%); `http_parser/evaluate`
  в criterion — 314 нс → 278 нс (−12%), остальные бенчмарки в пределах шума.
- CI: экшены обновлены до node24-версий, раннер закреплён на `ubuntu-24.04`.

### Fixed

- XDP RST-challenge не пропускал живых клиентов за stateful-фаерволом (`ufw`, NAT-роутер,
  любой conntrack с `ct state invalid drop`): ack challenge-SYN-ACK брался из всего 32-битного
  пространства, conntrack клиента помечал такой SYN-ACK как INVALID и выбрасывал до TCP-стека.
  Теперь ack = `ISS+1−k` (`1 ≤ k ≤ 2^15`, из секрета и ISN клиента) — внутри окна conntrack,
  но по-прежнему неприемлем для TCP (`SEG.ACK ≤ ISS`). Живой клиент проходит за ~15 мс.
- Стенды XDP на veth теряли challenge-SYN-ACK: `XDP_TX` на veth доходит до пира, только если
  у пира native XDP-программа. `xdp_stress.sh` и новый тест вешают pass-программу на пира;
  WARN «известный пробел» в `xdp_stress.sh SOURCES=random` заменён на проверку verified.
- Minecraft: `rampart_mc_protocol_version_total` не считал версии, отклонённые политикой
  (deny/min/max), — метрика теряла именно те версии, которые режутся. Тест
  `denied_version_is_rejected_and_version_label_is_bounded` проходил только при удачном
  порядке параллельных тестов (на 2 CPU стабильно падал).
- **XDP: бан и whitelist для IPv4-mapped IPv6 CIDR не работали** (`::ffff:a.b.c.d/N` попадал
  в IPv6-trie, где IPv4-пакет его не находил). Теперь `canonical_cidr` сворачивает такие
  префиксы в IPv4; userspace-таблица CIDR делает то же, маски через `checked_shl`.
- Строгая валидация целей бана и портов в CLI/API: пробелы по краям (раньше обрезались,
  теперь 400), мусор после адреса, `/0`, префикс > 32/128. Ошибка слишком большой
  `duration_secs` теперь «ban duration must not exceed one year».
- **XDP: IPv6 с extension-заголовком обходил весь фильтр.** Любой заголовок hop-by-hop,
  routing, destination options или AH (стек ядра их обрабатывает) давал `XDP_PASS` до
  whitelist/blacklist/throttle/порт-гейта. Теперь цепочка (до 4 заголовков) разбирается до
  реального L4; более длинная цепочка и протоколы вне TCP/UDP проходят проверку blacklist.
- **XDP: забаненный IPv4-источник проходил ICMP/GRE/ESP и т. п.** — `XDP_PASS` стоял до
  чтения списков. Теперь blacklist применяется ко всем протоколам, чистый трафик по-прежнему
  проходит. Также отбрасывается IPv4-пакет с `version != 4`.
- XDP: для IPv4-mapped IPv6 длина TCP-payload считалась как `40 + payload_len` (всегда
  срезалась до конца кадра, то есть учитывала паддинг); теперь `payload_len` минус
  extension-заголовки.
- **XDP: verifier на ядре 5.15 отвергал программу** (`invalid indirect read from stack`):
  неявный паддинг `struct throttle_entry` не обнулялся clang 14 — теперь явное поле `pad`
  (размер 16 и ABI прежние). Найдено прогоном на реальной KVM-ноде.
- **XDP-программа оставалась на интерфейсе после остановки edge**: detach шёл в фоновом
  потоке после 5-секундного sleep, процесс выходил раньше. Теперь detach синхронный в `run`.
- Метрики `rampart_xdp_*` всегда были нулевыми: `stats_map` — `percpu_array`, читалась
  обычным `lookup`. Теперь `lookup_percpu` с суммой по CPU.
- `RUST_LOG` не мог поднять детализацию `rampart` выше `info` (принудительная директива
  перебивала переменную окружения).
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
