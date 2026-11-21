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
| Milestone | **v0.4 — надёжность и воспроизводимость** |
| CI | зелёный: fmt, clippy, тесты, deny, Docker, module-size, secrets, docs-links |
| Следующий релиз | v0.4: все три задачи закрыты; остался первый прогон job `xdp-kernel` на GitHub |

## 2. Активные задачи (v0.4)

| Задача | Приоритет | Статус | План |
|--------|-----------|--------|------|
| XDP netns+veth harness в CI | P0 | done | [v0.4-xdp-ci-harness.md](docs/roadmap/v0.4-xdp-ci-harness.md) |
| Startup-диагностика окружения | P1 | done | [v0.4-startup-diagnostics.md](docs/roadmap/v0.4-startup-diagnostics.md) |
| Anti-lockout и баны по порту | P1 | done | [v0.4-anti-lockout.md](docs/roadmap/v0.4-anti-lockout.md) |

Статусы и правила ведутся в [docs/roadmap/README.md](docs/roadmap/README.md);
при изменении статуса правятся оба места (файл задачи и эта таблица).

## 3. Дальше

| Версия | Содержание | Индекс |
|--------|------------|--------|
| v0.5 | RST-challenge GA, pinned maps + OpenAPI, GeoIP/ASN, gRPC | [docs/roadmap/README.md#5-v05--продуктовые-фичи](docs/roadmap/README.md#5-v05--продуктовые-фичи) |
| v0.6 | HTTP-over-XDP, Bloom, io_uring, ML, BGP | [docs/roadmap/README.md#6-v06--исследования](docs/roadmap/README.md#6-v06--исследования) |
| icebox | Minecraft Velocity forwarding | [icebox-minecraft-velocity.md](docs/roadmap/icebox-minecraft-velocity.md) |

## 4. Открытые решения

| Вопрос | Статус | Где |
|--------|--------|-----|
| JWT-роли (RBAC) | поле `role` удалено как мёртвое; RBAC — только при втором потребителе | CHANGELOG Unreleased |
| Rider: self-hosted runner для XDP | решается в дизайне v0.4-xdp-ci-harness | [план](docs/roadmap/v0.4-xdp-ci-harness.md) |

---

*Версия: 6.0 | Ноябрь 2026*
