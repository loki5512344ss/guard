# Testing - Rampart

> Как тестировать: unit, integration, нагрузочное, DDoS simulation.

---

## 1. Unit и integration тесты (Rust)

```bash
cargo test                    # все тесты
cargo test --test config_parse
cargo test -- --nocapture     # с выводом
```

Существующие наборы (39 файлов в `tests/`):

| Группа | Тесты |
|--------|-------|
| Конфиг и запуск | `config_parse`, `app_shutdown` |
| Фильтры и лимиты | `filter_logic`, `connection_limits`, `proxy_identity` |
| Протоколы | `protocol_registry`, `protocol_registry_contract`, `http_protocol`, `protocol_http_parser`, `protocol_http_handler`, `proxy_v2_parser` |
| PoW и challenge | `pow_roundtrip`, `pow_difficulty` |
| Детекция | `subnet_detection`, `traffic_hook`, `traffic_intel`, `traffic_prefix_stats`, `traffic_profile_alert`, `traffic_profile_profiler` |
| Manager API | `manager_api`, `manager_auth`, `manager_heartbeat`, `manager_security` |
| Хранилища | `redis_backoff`, `clickhouse_writer` |
| TUI | `tui_metrics`, `tui_prometheus` |
| XDP | `xdp_attach_smoke`, `xdp_ban_clock`, `xdp_ban_keys`, `xdp_ban_v6`, `xdp_diagnostics`, `xdp_events`, `xdp_globals`, `xdp_loader`, `xdp_object_maps`, `xdp_services`, `xdp_whitelist_keys` |
| End-to-end | `edge_e2e` |

---

## 2. Статический анализ

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

E2E-сценарии живут в `tests/edge_e2e.rs`: реальный TCP-клиент через продакшн-accept-loop и
pipeline до upstream на loopback (обычный HTTP, PoW с решённым и неверным nonce, rate-limit,
blacklist). Root и внешняя сеть не нужны, каждый тест укладывается в 5 с:

```bash
cargo test --all-features --test edge_e2e
```

XDP: smoke-check компиляции BPF-программы:

```bash
mkdir -p target/xdp
clang -O2 -g -target bpf -I"/usr/include/$(gcc -print-multiarch)" \
  -c xdp/core/universal_filter.c -o target/xdp/universal_filter.o
```

Функциональные проверки на реальном ядре (нужен root: CAP_BPF + CAP_NET_ADMIN,
`bpftool`, `clang`, `python3`):

```bash
sudo bash scripts/xdp_ipv6_smoke.sh
```

Поднимает netns + veth, грузит программу через verifier и проверяет: бан IPv6 и IPv4
(включая короткие UDP-датаграммы), снятие бана, whitelist поверх активного бана, истечение
TTL по монотонным часам и `udp_policy = "rate-limit"` для IPv6 (политика патчится в
`.rodata` до загрузки).

```bash
sudo bash scripts/xdp_pkt_test.sh
```

Проверяет то, что veth-смок поймать не может по построению: Ethernet-паддинг (длина
TCP-payload по `ip->tot_len`), VLAN/QinQ-теги и фрагменты — забаненный источник не должен
проходить ни тегированным, ни фрагментированным.

`scripts/xdp_netns_smoke.sh` дополнительно гоняет реальный бинарь `rampart` end-to-end
(требует `hping3`): `BIN=./target/release/rampart sudo -E bash scripts/xdp_netns_smoke.sh`.
Origin поднимается внутри netns, поэтому хостовой файрвол (`ufw`, `INPUT DROP`) не мешает.
Проверяет verifier, attach, проксирование, события ringbuf, auto-ban, истечение SYN-бана
(60 с, поэтому прогон занимает ~1.5 минуты) и реальный detach после SIGTERM.

Нагрузочный прогон в том же изолированном netns:

```bash
BIN=./target/release/rampart DURATION=20 SOURCES=single INTERVAL_US=200 sudo -E bash scripts/xdp_stress.sh
SOURCES=random sudo -E ...   # спуфленные источники: защищает RST-challenge, а не throttle
```

Печатает pps, дропы XDP, RST-challenge, загрузку CPU и долю успешных запросов
легитимного клиента во время флуда.

Известные пробелы: `xdp_ipv6_smoke.sh` на ядре 5.15 не проходит (патч `.rodata` из
bpftool и NDP в стенде); в режиме `SOURCES=random` живой клиент пока не проходит
RST-challenge — это работа v0.5. Если `bpftool` на хосте — обёртка без пакета под
текущее ядро (Ubuntu), подставьте реальный бинарь из `/usr/lib/linux-tools-*/`.

Единая точка входа: `sudo -E bash scripts/xdp_ci.sh` (`BIN=…` — пропустить сборку,
`--require` — SKIP считать ошибкой, `--with-ipv6` — добавить `xdp_ipv6_smoke.sh`). Скрипт
печатает строки `RESULT <фаза> PASS|FAIL|SKIP`; без root, netns, ядра ≥ 5.10 или рабочего
`bpftool` он честно пишет `SKIP: <причина>`, а не зелёный результат. В CI это job
`xdp-kernel`; SKIP превращается в `::warning`. Проверено: возврат бага с паддингом
`throttle_entry` роняет прогон (`invalid indirect read from stack`, exit 1).

---

## 3. Fuzzing

Внешние парсеры (HTTP request-head и PROXY protocol v2) фаззятся через `cargo-fuzz`.
Нужен nightly-тулчейн и установленный `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

# короткий прогон (60 с на цель), как в CI-смоуке
make fuzz

# длительная кампания локально
cargo +nightly fuzz run http_head fuzz/seeds/http_head -- -max_total_time=600
cargo +nightly fuzz run proxy_v2 -- -max_total_time=600
```

Найденный краш сохраняется в `fuzz/artifacts/<target>/`; воспроизведение —
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`. Цели лежат в
`fuzz/fuzz_targets/`, сиды — в `fuzz/seeds/` (каталоги `corpus/`, `artifacts/`
в git не попадают).

Инварианты, которые проверяют цели: парсер не паникует на произвольных байтах,
`scan_head` не выходит за буфер, `parse_v2_header` не потребляет больше
переданного и не принимает заголовок выше лимита, семейство адреса совпадает с
байтом family.

---

## 4. Бенчмарки горячего пути

Микробенчмарки (criterion) для того, что выполняется на каждое соединение:

```bash
cargo bench --all-features --bench hot_paths
# HTML-отчёт: target/criterion/report/index.html
```

Замеряются: `RateLimiter::check`, exact/CIDR/miss lookup в `Blacklist`, `SubnetDetector::evaluate`
на окне из 256 префиксов и разбор HTTP request-head. Сравнивай медианы до/после изменения на
одной машине; абсолютные числа зависят от CPU. Порядок величин на dev-машине (2 vCPU,
релизный профиль с `lto = "thin"`):

| Бенчмарк | Медиана |
|----------|---------|
| `rate_limiter/check` | ~120 ns |
| `blacklist/is_blocked_exact` | ~80 ns |
| `blacklist/is_blocked_cidr` | ~230 ns |
| `blacklist/is_blocked_miss` | ~230 ns |
| `subnet_detector/evaluate_256` | ~2.8 µs |
| `http_parser/evaluate` | ~280 ns |

Для сравнения с сохранённым прогоном: `cargo bench --all-features --bench hot_paths --
--save-baseline before` до изменения, затем `--baseline before` после; criterion покажет
дельту и её значимость.

---

## 5. Локальный integration-стенд (Docker)

```bash
bash deploy/test/run_test.sh
```

Поднимает backend-stub (TCP echo), edge (`rampart` с config.test.toml) и
attacker-контейнер. Сценарии — в [deploy/test/README.md](../deploy/test/README.md).

---

## 6. Нагрузочное тестирование

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

## 7. Метрики для проверки во время теста

```bash
curl -s http://localhost:9090/metrics | grep rampart_
# rampart_connections_total{result="allowed|blocked"}
# rampart_rate_limit_hits
# rampart_pow_challenges_total{result=...}
# rampart_attack_status
```

---

*Версия: 3.0 | Ноябрь 2026*
