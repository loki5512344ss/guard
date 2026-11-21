# Разбор внешних проектов (ref/, ноябрь 2026)

> Актуально: v0.5. Это источник идей для [roadmap](../roadmap/README.md): каждая принятая
> идея превращена в задачу там, здесь — что смотрели, под какой лицензией и что отвергли.
> Разбор делался читающими агентами: поверхностно (по ~10 файлов на проект), поэтому
> утверждения вида «у нас этого нет» проверяются по коду при взятии задачи в работу.

## Лицензии и правила

| Проект | Лицензия | Что можно |
|--------|----------|-----------|
| ebpfsentinel | AGPL | только идеи, код не копируем |
| Infrarust | AGPL | только идеи, код не копируем |
| IronShield | SSPL | только идеи, код не копируем |
| sonar | GPL | только идеи, код не копируем |
| XDP-Firewall | MIT | изучать ближе; при переносе кода — атрибуция |
| Minecraft-XDP-eBPF | BSD-3 | изучать ближе; при переносе — уведомление |
| couic | Apache-2.0 / MIT | изучать ближе; при переносе — атрибуция и NOTICE |

## Что взято (задача в roadmap)

| Идея | Источник | Задача |
|------|----------|--------|
| Непрерывная сложность PoW, сложность от риска, подписанный токен, WASM-решатель | IronShield | `v0.5-pow-*`, `v0.6-pow-pass-token`, `v0.6-wasm-solver` |
| Аудит XDP: ловушки IPv4/IPv6, порядок бан/bypass, `/0`, fail-closed при заполнении карт, раскладка структур | XDP-Firewall, Minecraft-XDP-eBPF, ebpfsentinel | `v0.5-xdp-filter-audit` |
| Гигиена Minecraft handshake/login, версии протокола, метрики, лимиты по логинам | sonar, Infrarust | `v0.5-minecraft-handshake-hygiene` |
| Теги банов, именованные наборы, batch-обновление карт, читаемые длительности, scoped-токены | couic, ebpfsentinel | `v0.5-control-plane-bans` |
| Пакеты deb/rpm, man-страницы, идемпотентный релиз, pinned actions | couic, Minecraft-XDP-eBPF | `v0.5-packaging-release` |
| SYN cookies из XDP, drop голого ACK, `bpf_timer`, bps-лимиты, точная проверка фрейма в XDP | ebpfsentinel, Minecraft-XDP-eBPF, XDP-Firewall | `v0.6-xdp-advanced-mitigations` |
| `explain <ip>` через `BPF_PROG_TEST_RUN`, стоимость программы, open-loop генератор нагрузки | ebpfsentinel, Infrarust | `v0.6-xdp-observability-tools` |
| Hitless-замена программы (`BPF_LINK_UPDATE`), атомарный reload конфигурации | ebpfsentinel, Infrarust, XDP-Firewall | `v0.6-hitless-reload` |
| Запуск без root, sandbox-директивы systemd, сброс capabilities после attach | couic, ebpfsentinel | `v0.6-least-privilege-runtime` |
| Датированные результаты замеров, политика skip, память карт на CPU | ebpfsentinel | `v0.5-xdp-hardening-followups` |

## Отвергнуто

- **Переписать XDP-часть на Rust/aya** (couic, Minecraft-XDP-eBPF): BPF-код остаётся C,
  aya ничего не даёт поверх libbpf-rs; потеряем loader, диагностику и харнесс.
- **Линейный проход по правилам в горячем пути** (XDP-Firewall): сами авторы пишут, что не
  масштабируется; у нас константные lookup по картам.
- **LRU-хеш как карта банов с удалением в пути пакета**: может вытеснить действующий бан;
  у нас LPM + срок + userspace-reaper.
- **Peer-to-peer синхронизация узлов** (couic): у нас Redis pub/sub, второй механизм —
  лишняя поверхность атаки.
- **Проверки гравитации/коллизий/капча в limbo** (sonar): требуют изображать
  Minecraft-сервер; Rampart прозрачный прокси и не читает зашифрованный трафик.
- **Широкая продуктовая поверхность ebpfsentinel** (IDS, DLP, NAT, LB, QoS, LSM, k8s),
  gRPC и генерируемый OpenAPI с 90+ BATS-наборами: вне объёма DDoS-фильтра.
- **Полный proxy-функционал Infrarust** (limbo, auth, Velocity/BungeeGuard, менеджер
  серверов), WASM-плагины (откроем только если плагины станут сторонними).
