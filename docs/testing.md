# Testing - Rampart

> Как тестировать: unit, integration, нагрузочное, DDoS simulation.

---

## 1. Unit тесты (Rust)

```bash
# Все тесты
cargo test

# Конкретный модуль
cargo test handshake
cargo test hmac
cargo test rate_limiter

# С выводом
cargo test -- --nocapture

# С профилированием
cargo test --release
```

### Что тестировать

| Модуль | Happy path | Error cases |
|--------|-----------|-------------|
| VarInt parser | обычный, короткий | overflow, incomplete, >5 байт |
| MC Handshake | vanilla, forge, hmac | truncated, invalid utf8, wrong packet id |
| HMAC sign/verify | правильный secret | wrong secret, empty hostname, timing |
| Rate limiter | under limit, reset | over limit, burst, concurrent |
| Blacklist | add/check/remove | expired entry, duplicate add |

### Пример: VarInt

```rust
#[test]
fn test_varint_normal() {
    let buf = vec![0x00];
    assert_eq!(read_varint(&buf, 0).unwrap(), (0, 1));
}

#[test]
fn test_varint_max() {
    let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07];
    assert_eq!(read_varint(&buf, 0).unwrap(), (i32::MAX, 5));
}

#[test]
fn test_varint_overflow() {
    let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]; // > 5 байт
    assert!(matches!(read_varint(&buf, 0), Err(VarIntError::TooBig)));
}

#[test]
fn test_varint_incomplete() {
    let buf = vec![0x80]; // ждём ещё байты
    assert!(matches!(read_varint(&buf, 0), Err(VarIntError::Incomplete)));
}
```

---

## 2. Интеграционные тесты

```bash
# Требуют: docker compose up (redis, clickhouse)
cargo test --test integration
```

### Что тестируем

```rust
#[tokio::test]
async fn test_full_flow() {
    // 1. Запускаем edge ноду (test config)
    // 2. Подключаемся Minecraft клиентом (через tokio::net::TcpStream)
    // 3. Шлём валидный handshake
    // 4. Проверяем что HMAC добавлен
    // 5. Проверяем что трафик проксирован до backend
}

#[tokio::test]
async fn test_blacklist_sync() {
    // 1. Добавляем IP в блэклист через Redis
    // 2. Проверяем что edge нода его подхватила
    // 3. Пытаемся подключиться с забаненного IP
    // 4. Проверяем что соединение отклонено
}
```

---

## 3. Fuzzing

```rust
// tests/fuzz/handshake.rs
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Должен крашиться на любой вход
    let _ = McHandshake::parse(data);
});
```

```bash
cargo install cargo-fuzz
cargo fuzz run handshake_parser
```

---

## 4. Нагрузочное тестирование

### Базовый тест (tcpkali)

```bash
# Установка
cargo install tcpkali

# 50k новых соединений
tcpkali \
  --connections 1000 \
  --connect-rate 5000 \
  --duration 60s \
  EDGE_IP:25565

# 500 активных соединений с трафиком
tcpkali \
  --connections 500 \
  --connect-rate 100 \
  --duration 120s \
  --message-rate 1 \
  --message "$(xxd mc_handshake.bin)" \
  EDGE_IP:25565
```

### SYN flood (hping3)

```bash
# Только на свои серверы!
hping3 -S --flood -p 25565 EDGE_IP

# С рандомным src IP
hping3 -S --flood -p 25565 --rand-source EDGE_IP
```

### Реальные Minecraft боты (SoulFire)

```bash
java -jar SoulFire.jar \
  --target play.example.com:25565 \
  --amount 200 \
  --join-delay 50 \
  --protocol-version 765
```

---

## 5. DDoS simulation

```bash
# Сценарий 1: SYN flood
# Ожидание: XDP дропает, CPU < 30%
hping3 -S --flood -p 25565 EDGE_IP

# Сценарий 2: Handshake flood
# Ожидание: rate limit блокирует, CPU < 60%
for i in $(seq 1 1000); do
  (echo -n "$MC_HANDSHAKE" | nc -w1 EDGE_IP 25565) &
done

# Сценарий 3: Slowloris
# Ожидание: timeout 5 сек, соединение закрывается
while true; do
  echo -n -e '\x01' | nc -w 10 EDGE_IP 25565
done

# Сценарий 4: Fragmented handshake
# Ожидание: буферизация, успешный парсинг
# (отправляем handshake по 1 байту с задержкой 100ms)
```

### Готовый много-IP стресс-тест на VDS (edge-only)

`deploy/test/stress/` — полный цикл без Redis/Velocity/Paper: edge-контейнер с stub-бэкендом
(socat echo) + attacker-контейнер со 100 source IP. Атака **маскируется под обычный трафик**
(валидные handshake со случайными hostname), во время флуда параллельно заходят легитимные
клиенты (`legit.py`), замеряющие RTT.

```bash
# На VDS
git clone https://github.com/loki5512344/rampart.git && cd rampart
cargo build --release --bin rampart-core
cp target/release/rampart-core deploy/test/stress/edge-ctx/rampart-core
cd deploy/test/stress && bash run-stress.sh
```

Фазы: A — сырая пропускная способность (лимиты 100k), B — защита (дефолт 5 pps/IP),
C — SYN flood, D — активные соединения. Результаты прогона 2026-08-04 —
в [load-test-report.md](research/load-test-report.md).

---

## 6. CI Pipeline

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check

  integration:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --test integration

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fuzz run handshake_parser -- -runs=100000

  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo bench
```

---

## 7. Метрики качества

```bash
# Покрытие кода
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
open tarpaulin-report.html

# Цели:
#   core/handshake.rs:  > 95%
#   core/hmac.rs:       > 90%
#   core/rate_limit:    > 85%
#   xdp/:               тесты в изолированной среде
```

---

*Версия: 1.0 | Июль 2026*
