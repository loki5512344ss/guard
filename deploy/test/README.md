# Локальное тестирование Rampart

Запускаем всё в Docker на одной машине, без выхода в интернет.

## Сеть

Все контейнеры в одной bridge-сети `rampart-test`:

```
attacker ──┐
           ├── rampart-edge ── backend (TCP echo stub)
legit ─────┘   (XDP отключён в тестах,
                используется userspace-only режим)
```

## Быстрый старт

```bash
# 1. Сборка + сеть + backend + edge + attacker
bash deploy/test/run_test.sh
```

Скрипт поднимает:
- `backend` — TCP echo-заглушка на 25566;
- `rampart` — edge-нода с конфигом `config.test.toml`;
- `attacker` — контейнер с python3 для запуска `stress/flood.py`.

## Сценарии тестирования

### 1. TCP connection flood (CPS)
```bash
docker exec attacker python3 /flood.py --target rampart --port 25565 \
  --mode connect --duration 30 --threads 50
```
Ожидание: rate-limiter блокирует превышение лимита коннектов с одного IP.
Метрика: `rampart_rate_limit_hits` растёт.

### 2. Slowloris (медленные соединения)
```bash
docker exec attacker python3 /flood.py --target rampart --port 25565 \
  --mode slowloris --duration 30 --threads 200
```
Ожидание: таймаут чтения (`limits.handshake_timeout_secs`) закрывает соединения.
Метрика: `rampart_connections_total{result="blocked"}` растёт.

### 3. SYN flood (raw, требует hping3 или отдельный контейнер)
```bash
hping3 -S --flood -p 25565 <EDGE_IP>
```
Ожидание: обрабатывается kernel'ом; при включённом XDP — дропается в ядре.

## Легитимный клиент

Во время атаки параллельно проверяем, что обычные клиенты проходят:

```bash
python3 deploy/test/stress/legit.py --target localhost --port 25565
```

## Метрики

Все метрики на http://localhost:9090/metrics:

```
rampart_connections_total{result="allowed|blocked"}
rampart_rate_limit_hits
rampart_pow_challenges_total{result="passed|failed|skipped"}
rampart_pow_current_difficulty
rampart_attack_status
```

ClickHouse (опционально): http://localhost:8123 — долгосрочное хранение событий.
Grafana: http://localhost:3000 (admin/admin) — дашборды из `deploy/grafana/`.
