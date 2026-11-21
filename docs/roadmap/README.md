# Roadmap — Rampart

> Индекс планов по версиям. `TODO.md` в корне — только статус и ссылки сюда;
> детали каждой задачи живут в отдельном файле этой папки.

---

## 1. Правила

1. **Одна задача = один файл.** Имя: `<version>-<topic>.md`, kebab-case, без дат.
2. **Файл создаётся, когда задача попадает в план**, а не когда её начинают.
   Пока задача не начата, достаточно цели, объёма и критериев приёмки.
3. **Статус меняется в двух местах одновременно:** в шапке файла задачи и в
   таблице `TODO.md`. Расхождение = баг документации.
4. **Завершённая задача** получает `Status: done`, ссылку на коммит(ы) и остаётся
   в папке до релиза; после релиза её содержимое переносится в
   [CHANGELOG.md](../../CHANGELOG.md), а файл удаляется.
5. **Не плоди версии.** Если задача не влезает в текущий milestone, она едет в
   `icebox-*.md`, а не в «v0.7».
6. **Планы не врут.** Команды и пути в плане проверяются по коду в том же PR.

## 2. Статусы

| Статус | Значение |
|--------|----------|
| `idea` | сформулирована, не оценена |
| `planned` | есть цель, объём и критерии приёмки, можно брать |
| `design` | идёт обсуждение дизайна (brainstorming) |
| `ready` | дизайн утверждён, есть пошаговый план |
| `in-progress` | реализуется |
| `blocked` | ждёт внешнего решения или зависимости |
| `done` | готова, влита, отражена в CHANGELOG |
| `dropped` | решено не делать; причина в файле |

## 3. Milestones

| Версия | Тема | Критерий выхода |
|--------|------|-----------------|
| v0.4 | Надёжность и воспроизводимость | XDP проверяется в CI, старт даёт честный вердикт об окружении, нет self-lockout |
| v0.5 | Продуктовые фичи | RST-challenge доведён до GA, внешние списки и API пригодны для интеграций, GeoIP/ASN, gRPC |
| v0.6 | Исследования | решения из backlog с доказанной пользой; каждая фича начинается с бенчмарка/прототипа |
| icebox | Отложено | без даты; берётся только при явном запросе |

## 4. v0.4 — надёжность

| Задача | Приоритет | Статус | План |
|--------|-----------|--------|------|
| XDP netns+veth harness в CI | P0 | done | [v0.4-xdp-ci-harness.md](v0.4-xdp-ci-harness.md) |
| Startup-диагностика окружения | P1 | done | [v0.4-startup-diagnostics.md](v0.4-startup-diagnostics.md) |
| Anti-lockout и баны по порту | P1 | done | [v0.4-anti-lockout.md](v0.4-anti-lockout.md) |

## 5. v0.5 — продуктовые фичи

| Задача | Приоритет | Статус | План |
|--------|-----------|--------|------|
| RST-challenge: довести до GA | P0 | planned | [v0.5-rst-challenge-ga.md](v0.5-rst-challenge-ga.md) |
| Pinned maps + OpenAPI | P1 | idea | [v0.5-pinned-maps-openapi.md](v0.5-pinned-maps-openapi.md) |
| GeoIP/ASN reputation | P1 | idea | [v0.5-geoip-asn.md](v0.5-geoip-asn.md) |
| gRPC protocol plugin | P2 | idea | [v0.5-grpc-plugin.md](v0.5-grpc-plugin.md) |
| XDP: IPv6-паритет для L4 | P1 | idea | [v0.5-xdp-ipv6-parity.md](v0.5-xdp-ipv6-parity.md) |
| Аудит XDP-фильтра и тесты без root | P1 | in-progress | [v0.5-xdp-filter-audit.md](v0.5-xdp-filter-audit.md) |
| Minecraft: гигиена handshake/login | P1 | idea | [v0.5-minecraft-handshake-hygiene.md](v0.5-minecraft-handshake-hygiene.md) |
| Управление банами: теги, наборы, API | P2 | idea | [v0.5-control-plane-bans.md](v0.5-control-plane-bans.md) |
| Пакеты и релизный процесс | P2 | idea | [v0.5-packaging-release.md](v0.5-packaging-release.md) |
| Хвосты XDP-харнесса и эксплуатации | P1 | idea | [v0.5-xdp-hardening-followups.md](v0.5-xdp-hardening-followups.md) |
| PoW: непрерывная сложность | P2 | idea | [v0.5-pow-continuous-difficulty.md](v0.5-pow-continuous-difficulty.md) |
| PoW: сложность от риска источника | P2 | idea | [v0.5-pow-risk-based-difficulty.md](v0.5-pow-risk-based-difficulty.md) |

## 6. v0.6 — исследования

| Задача | Приоритет | Статус | План |
|--------|-----------|--------|------|
| HTTP поверх XDP (BPF hook) | P1 | idea | [v0.6-http-over-xdp.md](v0.6-http-over-xdp.md) |
| Bloom filter для blacklist | P3 | idea | [v0.6-bloom-filter.md](v0.6-bloom-filter.md) |
| io_uring runtime | P3 | idea | [v0.6-io-uring.md](v0.6-io-uring.md) |
| ML anomaly detection | P3 | idea | [v0.6-ml-anomaly.md](v0.6-ml-anomaly.md) |
| BGP Anycast | P3 | idea | [v0.6-bgp-anycast.md](v0.6-bgp-anycast.md) |
| XDP: продвинутые меры (исследование) | P3 | idea | [v0.6-xdp-advanced-mitigations.md](v0.6-xdp-advanced-mitigations.md) |
| Диагностика пути пакета и измерения | P3 | idea | [v0.6-xdp-observability-tools.md](v0.6-xdp-observability-tools.md) |
| Горячая перезагрузка | P3 | idea | [v0.6-hitless-reload.md](v0.6-hitless-reload.md) |
| Запуск edge без root | P2 | idea | [v0.6-least-privilege-runtime.md](v0.6-least-privilege-runtime.md) |
| Горячий путь: бенчмарк-first | P3 | idea | [v0.6-hot-path-perf.md](v0.6-hot-path-perf.md) |
| PoW: подписанный pass-токен | P2 | idea | [v0.6-pow-pass-token.md](v0.6-pow-pass-token.md) |
| WASM-решатель PoW | P3 | idea | [v0.6-wasm-solver.md](v0.6-wasm-solver.md) |

## 7. Icebox

| Задача | Почему отложена | План |
|--------|-----------------|------|
| Minecraft Velocity forwarding | нужен только если MC-сегмент остаётся целевым | [icebox-minecraft-velocity.md](icebox-minecraft-velocity.md) |

---

*Версия: 1.0 | Ноябрь 2026*
