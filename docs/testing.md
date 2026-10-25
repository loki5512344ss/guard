# Testing - Rampart

> Как тестировать: unit, integration, нагрузочное, DDoS simulation.

---

## 1. Unit и integration тесты (Rust)

```bash
cargo test                    # все тесты
cargo test --test config_parse
cargo test -- --nocapture     # с выводом
```

Существующие наборы (tests/):

| Тест | Что покрывает |
|------|---------------|
| `config_parse` | Парсинг и валидация единого конфига (src/config) |
| `filter_logic` | Blacklist, rate limit, geo-фильтры |
| `pow_roundtrip` | Выдача/решение/проверка PoW challenge |
| `protocol_registry` | Реестр протокольных плагинов |

---

## 2. Статический анализ

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

XDP: smoke-check компиляции BPF-программы:

```bash
clang -O2 -g -target bpf -c xdp/core/universal_filter.c -o /tmp/universal_filter.o
```

---

## 3. Локальный integration-стенд (Docker)

```bash
bash deploy/test/run_test.sh
```

Поднимает backend-stub (TCP echo), edge (`rampart` с config.test.toml) и
attacker-контейнер. Сценарии — в [deploy/test/README.md](../deploy/test/README.md).

---

## 4. Нагрузочное тестирование

### Много-IP TCP flood на VDS (edge-only)

`deploy/test/stress/` — полный цикл без Redis/ClickHouse: edge-контейнер с
stub-бэкендом (socat echo) + attacker-контейнер со 100 source IP.
`flood.py` шлёт чистые TCP-соединения (connect / slowloris / keepalive),
во время флуда параллельно подключаются generic TCP-клиенты (`legit.py`),
замеряющие RTT.

```bash
git clone https://github.com/loki5512344ss/guard.git && cd guard
cargo build --release --bin rampart
cd deploy/test/stress && bash run-stress.sh
```

Фазы: A — сырая пропускная способность (лимиты сняты), B — защита (per-IP rate
limit + reputation bans), C — SYN flood hping3, D — активные соединения.

### tcpkali / hping3

```bash
tcpkali --connections 1000 --connect-rate 5000 --duration 60s EDGE_IP:25565
hping3 -S --flood -p 25565 --rand-source EDGE_IP   # только на свои серверы!
```

---

## 5. Метрики для проверки во время теста

```bash
curl -s http://localhost:9090/metrics | grep rampart_
# rampart_connections_total{result="allowed|blocked"}
# rampart_rate_limit_hits
# rampart_pow_challenges_total{result=...}
# rampart_attack_status
```

---

*Версия: 2.0 | Август 2026*
