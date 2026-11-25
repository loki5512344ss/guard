# Rampart — TODO

> Этот файл — только статус и ссылки. Планы задач живут в [docs/roadmap/](docs/roadmap/README.md),
> история изменений — в [CHANGELOG.md](CHANGELOG.md), правила разработки —
> в [docs/development.md](docs/development.md), устройство системы —
> в [docs/architecture.md](docs/architecture.md).

---

## 1. Сейчас

| | |
|---|---|
| Версия | `0.3.0-dev` |
| Milestone | **v0.5 — продуктовые фичи** |
| CI | зелёный: fmt, clippy, тесты, deny, Docker, module-size, secrets, docs-links; XDP-фазы `pkt`, `smoke`, `chal` на VDS (5.15) |
| Предыдущий | v0.4 — все задачи закрыты, ждёт тега релиза |

## 2. Активные задачи (v0.5)

| Задача | Приоритет | Статус | План |
|--------|-----------|--------|------|
| RST-challenge: довести до GA | P0 | in-progress | [v0.5-rst-challenge-ga.md](docs/roadmap/v0.5-rst-challenge-ga.md) |
| Аудит XDP-фильтра и тесты без root | P1 | in-progress | [v0.5-xdp-filter-audit.md](docs/roadmap/v0.5-xdp-filter-audit.md) |
| Minecraft: гигиена handshake/login | P1 | in-progress | [v0.5-minecraft-handshake-hygiene.md](docs/roadmap/v0.5-minecraft-handshake-hygiene.md) |
| Управление банами: теги, наборы, API | P2 | in-progress | [v0.5-control-plane-bans.md](docs/roadmap/v0.5-control-plane-bans.md) |

Остальные задачи v0.5 (`idea`) и статусы — в [docs/roadmap/README.md](docs/roadmap/README.md);
при изменении статуса правятся оба места (файл задачи и эта таблица).

## 3. Дальше

| Версия | Содержание | Индекс |
|--------|------------|--------|
| v0.5 | pinned maps + OpenAPI, GeoIP/ASN, gRPC, IPv6-паритет XDP, PoW | [docs/roadmap/README.md#5-v05--продуктовые-фичи](docs/roadmap/README.md#5-v05--продуктовые-фичи) |
| v0.6 | HTTP-over-XDP, Bloom, io_uring, ML, BGP | [docs/roadmap/README.md#6-v06--исследования](docs/roadmap/README.md#6-v06--исследования) |
| icebox | Minecraft Velocity forwarding | [icebox-minecraft-velocity.md](docs/roadmap/icebox-minecraft-velocity.md) |

## 4. Открытые решения

| Вопрос | Статус | Где |
|--------|--------|-----|
| JWT-роли (RBAC) | поле `role` удалено как мёртвое; RBAC — только при втором потребителе | CHANGELOG Unreleased |

---

*Версия: 7.0 | Ноябрь 2026*
