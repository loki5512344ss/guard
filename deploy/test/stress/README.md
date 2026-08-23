# Стресс-тест Rampart на VDS (без Redis/ClickHouse)

Проверяет edge-ноду (слои 1–3) на реальном VDS. Не требует Redis, ClickHouse или внешних сервисов — только бинарь `rampart` и stub-бэкенд (socat echo) в одном контейнере.

## Топология

```
┌─────────────── host VDS ───────────────┐
│  docker bridge 172.30.0.0/24           │
│                                        │
│  rampart-edge (172.30.0.2)             │
│    ├─ rampart      :25565 (bind 0.0.0.0)│
│    ├─ socat echo   :25566 (127.0.0.1)  │  ← stub бэкенд
│    └─ metrics      :9090               │
│                                        │
│  rampart-attacker (172.30.0.3)         │
│    └─ 100 source IP (172.30.0.101-200) │  ← flood.py / hping3
└────────────────────────────────────────┘
```

- Метрики на хосте: `curl http://127.0.0.1:9090/metrics`
- Edge слушает на хосте: `127.0.0.1:25565`

## Быстрый старт

```bash
# 1. На VDS: клонировать репозиторий, собрать бинарь
git clone https://github.com/loki5512344/rampart.git && cd rampart
cargo build --release --bin rampart

# 2. Запустить весь цикл (setup + 4 фазы)
#    run-stress.sh сам найдёт бинарь (target/release), а папку — по себе (переменная DIR опциональна)
cd deploy/test/stress
bash run-stress.sh
```

> Для запуска из другого места задай `DIR` (по умолчанию — папка скрипта).

## Фазы

| Фаза | Конфиг | Что делает | Проверяет |
|------|--------|-----------|-----------|
| A | `edge-high.toml` (лимиты 100k) | TCP connect flood со 100 IP | сырую пропускную способность L4 |
| B | `edge-defense.toml` (дефолтные лимиты) | та же атака | rate limit + reputation ban, доступность легитимных клиентов |
| C | — | SYN flood hping3 (rand-source) | поведение без XDP (обрабатывает kernel) |
| D | `edge-high.toml` | 300 keepalive-коннектов | удержание активных соединений |

Во время фаз A и B параллельно подключается `legit.py` (generic TCP-клиенты), меряющий RTT — доказывает, что реальные клиенты проходят во время атаки.

## Атаки

`flood.py` открывает чистые TCP-соединения (connect / slowloris / keepalive режимы) со случайных source IP. Никакой протокольной маскировки нет: на уровне L3/L4 флуд неотличим от легитимного трафика. Различие даёт только per-IP rate limit и репутация.

## Метрики для сбора

```bash
curl -s http://127.0.0.1:9090/metrics | grep -E 'rampart_(connections_total|rate_limit_hits|attack_status)'
```
