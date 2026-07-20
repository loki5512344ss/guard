# Rampart - Research & Deep Dives

> Это исследовательская документация. Здесь живут глубокие разборы технологий,
> эксперименты и идеи для версий v0.4+.
>
> Для текущей архитектуры (v0.1-v0.3) смотри `ARCHITECTURE.md` в корне репо.

---

## Структура

| Файл | Что внутри | Актуально с |
|---|---|---|
| [architecture.md](./architecture.md) | Общая архитектура, компоненты, схемы C4 | v0.1 |
| [ddos.md](./ddos.md) | Векторы атак L3/L4/L7, методы защиты, AI-боты | v0.1 |
| [ebpf.md](./ebpf.md) | XDP/eBPF фильтр, BPF maps, ringbuf, verifier | v0.4 |
| [rust-performance.md](./rust-performance.md) | Zero-copy, io_uring, SO_REUSEPORT, NUMA, profiling | v0.3 |
| [io_uring.md](./io_uring.md) | **Объединено с rust-performance.md** | v0.4 |
| [haproxy.md](./haproxy.md) | HAProxy конфиг, mTLS, замена на Rust LB | v0.2 |
| [envoy.md](./envoy.md) | EWMA балансировка, Circuit Breaker, xDS API | v0.5 |
| [observability.md](./observability.md) | Prometheus, OpenTelemetry, ClickHouse, Parca | v0.3 |
| [minecraft-protocol.md](./minecraft-protocol.md) | Handshake парсинг, VarInt, Forge, fingerprinting | v0.1 |
| [anti-bot.md](./anti-bot.md) | Sonar, challenge системы, AI-обходы, fingerprint | v0.2 |
| [benchmark.md](./benchmark.md) | Инструменты, методология, ожидаемые результаты | v0.3 |
| [security.md](./security.md) | STRIDE, mTLS, Zero Trust, supply chain | v0.2 |
| [networking.md](./networking.md) | WireGuard, BGP Anycast, QUIC, MTU | v0.3 |
| [papers.md](./papers.md) | Ссылки на статьи, RFC, проекты для изучения | - |

---

## Как читать

```
Хочу написать первую версию (v0.1)
  → architecture.md + minecraft-protocol.md + ddos.md

Хочу добавить защиту от ботов
  → anti-bot.md

Хочу выжать максимум производительности
  → rust-performance.md + io_uring.md + ebpf.md

Хочу настроить мониторинг
  → observability.md

Хочу понять безопасность системы
  → security.md + networking.md
```

---

### Операционные документы (корень docs/)

| Файл | Описание |
|---|---|
| [deployment.md](../deployment.md) | Пошаговый деплой |
| [configuration.md](../configuration.md) | Примеры конфигов |
| [vds_compatibility.md](../vds_compatibility.md) | Таблица провайдеров |
| [disaster_recovery.md](../disaster_recovery.md) | Failover сценарии |
| [runbook.md](../runbook.md) | Инструкции для админа |
| [api.md](../api.md) | REST API спецификация |
| [testing.md](../testing.md) | Методология тестирования |
| [troubleshooting.md](../troubleshooting.md) | FAQ |
| [migration.md](../migration.md) | Обновление версий |

---

*Версия: 0.5-research | Июль 2026*
