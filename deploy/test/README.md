# Локальное тестирование Rampart

Запускаем всё в Docker на одной машине, без выхода в интернет.

## Сеть

Все контейнеры в одной bridge-сети `rampart-test`:

```
attacker ──┐
           ├── rampart-edge ── backend
           │   (XDP отключён в тестах,
           │    используется userspace-only режим)
           │
mclient ───┘  (Minecraft клиент для теста легитимных коннектов)
```

## Быстрый старт

```bash
# 1. Сеть
docker network create rampart-test

# 2. Backend (Minecraft сервер или заглушка)
docker run -d --name backend --network rampart-test itzg/minecraft-server

# 3. Rampart edge
docker run -d --name rampart --network rampart-test \
  -e RAMPART_CONFIG=/etc/rampart/config.toml \
  -v ./config.test.toml:/etc/rampart/config.toml \
  rampart-core

# 4. Аттакер (MHDDoS)
docker run -d --name attacker --network rampart-test \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  python:3.11 bash -c "while true; do sleep 10; done"

# 5. Легитимный клиент (mclient.py)
docker run -d --name mclient --network rampart-test \
  python:3.11 python mclient.py --target rampart:25565
```

## Сценарии тестирования

### 1. SYN flood
```bash
docker exec attacker python3 /ref/MHDDoS/start.py SYN 172.x.x.x:25565 60 100
```
Ожидание: Rampart XDP дропает SYN-пакеты после превышения throttle.
Метрика: `rampart_xdp_syn_throttle` растёт, CPU < 30%.

### 2. TCP connection flood (CPS)
```bash
docker exec attacker python3 /ref/MHDDoS/start.py CPS 172.x.x.x:25565 60 100
```
Ожидание: Rampart rate-limiter блокирует >50 conn/s с одного IP.
Метрика: `rampart_rate_limit_hits` растёт.

### 3. Minecraft handshake flood
```bash
docker exec attacker python3 /ref/MHDDoS/start.py MINECRAFT 172.x.x.x:25565 60 100
```
Ожидание: Layer 2 PoW требует решения хэш-задачи.
Метрика: `rampart_pow_challenges_total{result="failed"}` растёт.

### 4. Сложный ботнет (MHDDoS MCBOT)
```bash
docker exec attacker python3 /ref/MHDDoS/start.py MCBOT 172.x.x.x:25565 60 50
```
Ожидание: Physics check детектирует неестественное движение.
Требует: PhysicsCheckListener активен.

### 5. DNS amplification
```bash
docker exec attacker python3 /ref/MHDDoS/start.py DNS 172.x.x.x:53 60 100
```
Ожидание: XDP дропает UDP не на порты 25565-25575.
Метрика: `rampart_xdp_dropped` растёт.

### 6. Slowloris (L7)
```bash
docker exec attacker python3 /ref/MHDDoS/start.py SLOW http://172.x.x.x:9090 60 100
```
Ожидание: Таймаут чтения закрывает соединение.
Метрика: `rampart_connections_total{result="blocked"}` растёт.

### 7. HTTP flood через cloudscraper (имитация CFB)
```bash
docker exec attacker python3 /ref/MHDDoS/start.py CFB http://172.x.x.x:9090 60 100
```
Ожидание: L7 rate-limiter блокирует >100 req/s с одного IP.
Метрика: `rampart_rate_limit_hits` растёт.

## Легитимный тест (mclient.py)

Тест должен проходить: Rampart пропускает нормальный Minecraft handshake.

```bash
python3 deploy/test/mclient.py --target rampart:25565 --username test_player
```
Ожидание: HMAC verified, соединение проксируется на backend.

## Метрики

Все метрики на http://localhost:9090/metrics:

```
rampart_xdp_total
rampart_xdp_passed
rampart_xdp_dropped
rampart_xdp_syn_throttle
rampart_xdp_verified
rampart_connections_total{result="allowed|blocked"}
rampart_rate_limit_hits{action="hit"}
rampart_pow_challenges_total{result="passed|failed|skipped"}
rampart_pow_current_difficulty
```

Grafana: http://localhost:3000 (admin/admin)
ClickHouse: http://localhost:8123 (для долгосрочных метрик)
