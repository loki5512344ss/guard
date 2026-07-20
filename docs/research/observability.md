# Observability - Метрики, Трейсинг, Логи

> Актуально: v0.3+

---

## Стек

```
Метрики:   Prometheus → VictoriaMetrics (долгосрочное хранение)
Трейсинг:  OpenTelemetry → Grafana Tempo
Логи:      трейсинг → Loki
Дашборды:  Grafana
Атаки:     ClickHouse (аналитика за месяцы)
Профайлинг: Parca (continuous)
Debug:     tokio-console (async tasks)
```

---

## Что собираем с каждого компонента

### Edge нода (Rust) → порт 9090

```
rampart_connections_total{node, result}   - total/blocked/allowed
rampart_active_connections{node}
rampart_bytes_proxied_total{node, dir}    - in/out
rampart_handshake_parse_errors_total{node, reason}
rampart_rate_limit_hits_total{node}
rampart_blacklist_size{node}
rampart_xdp_drops_total{node, reason}    - если XDP включён

# Гистограммы (важны для P99)
rampart_handshake_duration_seconds{node}
rampart_proxy_latency_seconds{node}
rampart_hmac_verify_duration_seconds{node}
```

### Velocity нода (Java) → порт 9091

```
velocity_players_online
velocity_domain_check_failures_total{reason}
velocity_hmac_check_failures_total
velocity_server_registry_size{type}       - hub/survival/skyblock
velocity_balancer_decisions_total{strategy, server_type}
velocity_redis_latency_seconds            - гистограмма
```

### Game сервер (Paper агент) → порт 9092

```
paper_tps{server, interval}              - 1m/5m/15m
paper_mspt{server}                       - мс на тик
paper_players_online{server}
paper_chunks_loaded{server}
paper_entities_total{server}
paper_memory_used_bytes{server}
paper_memory_max_bytes{server}
paper_gc_pause_seconds{server}           - GC паузы
```

---

## Prometheus конфиг с авто-дискавери

```yaml
# prometheus.yml
scrape_configs:

  - job_name: 'rampart-edge'
    static_configs:
      - targets: ['10.0.100.1:9090', '10.0.100.2:9090']

  - job_name: 'rampart-velocity'
    static_configs:
      - targets: ['10.0.0.2:9091', '10.0.0.3:9091']

  # Game серверы - авто-дискавери (Manager генерирует файл из Redis)
  - job_name: 'paper-servers'
    file_sd_configs:
      - files: ['/etc/prometheus/game_servers.json']
        refresh_interval: 30s

  - job_name: 'haproxy'
    static_configs:
      - targets: ['10.0.0.1:8404']
```

### Авто-генерация game_servers.json

```rust
// Manager генерирует файл каждые 30 сек
async fn generate_sd_file(redis: &Redis) {
    let servers: Vec<serde_json::Value> = redis
        .hgetall("rampart:servers").await
        .values()
        .map(|raw| {
            let s: ServerEntry = serde_json::from_str(raw).unwrap();
            serde_json::json!({
                "targets": [format!("{}:9092", s.ip)],
                "labels": { "server": s.name, "type": s.server_type }
            })
        })
        .collect();

    std::fs::write(
        "/etc/prometheus/game_servers.json",
        serde_json::to_string_pretty(&servers).unwrap()
    ).unwrap();
}
```

---

## Alerting правила

```yaml
# alerts.yml
groups:
  - name: rampart-critical
    rules:

      - alert: DDoSAttack
        expr: |
          rate(rampart_connections_total{result="blocked"}[1m])
          / rate(rampart_connections_total[1m]) > 0.8
        for: 30s
        annotations:
          summary: "DDoS атака на {{ $labels.node }}"

      - alert: EdgeNodeDown
        expr: up{job="rampart-edge"} == 0
        for: 10s
        annotations:
          summary: "Edge нода {{ $labels.instance }} недоступна"

      - alert: VelocityNodeDown
        expr: up{job="rampart-velocity"} == 0
        for: 15s

      - alert: LowTPS
        expr: paper_tps{interval="1m"} < 15
        for: 2m
        annotations:
          summary: "Низкий TPS на {{ $labels.server }}: {{ $value }}"

      - alert: HighMSPT
        expr: paper_mspt > 45
        for: 1m
        annotations:
          summary: "Высокий MSPT: {{ $value }}ms на {{ $labels.server }}"
```

### Алерт в Discord

```yaml
# alertmanager.yml
receivers:
  - name: discord
    webhook_configs:
      - url: "${DISCORD_WEBHOOK}"
        send_resolved: true
        http_config:
          headers:
            Content-Type: application/json
        title: '{{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          **{{ .Annotations.summary }}**
          {{ end }}
```

---

## Push vs Pull

**Проблема:** Edge ноды - дешёвые VDS по всему миру, часто за NAT, с динамическими IP. Prometheus pull (scrape) не сработает если нода за NAT или firewall.

**Решение:**

```
Edge ноды → vmagent (push через remote_write) или OTel Collector
  Причина: edge за NAT, динамические IP, firewall блокирует входящие

Manager / Velocity / HAProxy → Prometheus pull (статичные IP внутри WG сети)
```

### Схема

```
                    ┌──────────────┐
                    │  VictoriaMetrics  │
                    │  (remote_write)  │
                    └───────┬──────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
      vmagent          Prometheus      Prometheus
    (edge-eu-1)      (manager)       (velocity)
    push              pull            pull
```

### Конфиг vmagent для edge ноды

```yaml
# /etc/vmagent.yml
remote_write:
  - url: "https://victoria.rampart.internal/api/v1/write"

scrape_configs:
  - job_name: 'rampart-edge'
    static_configs:
      - targets: ['127.0.0.1:9090']  # localhost - не требует доступа извне
```

---

## OpenTelemetry - distributed tracing

```rust
// src/telemetry.rs

use opentelemetry_otlp::WithExportConfig;
use tracing_opentelemetry::OpenTelemetryLayer;

pub fn init(service: &str, otlp_endpoint: &str) {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint)
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .unwrap();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(OpenTelemetryLayer::new(tracer))
        .init();
}

// Использование - автоматически создаёт spans
#[tracing::instrument(skip(stream, config))]
pub async fn handle_connection(stream: TcpStream, config: Arc<Config>) {
    let handshake = parse_handshake(&stream).await;  // child span
    filter_request(&handshake).await;                // child span
    proxy_to_backend(stream).await;                  // child span
}
```

---

## ClickHouse - attack log

### Почему не PostgreSQL

```
SELECT count() WHERE country='CN' AND ts > now()-24h

PostgreSQL: ~2 сек на 100M строк
ClickHouse: ~50 мс на 100M строк
Сжатие:     PostgreSQL ~3:1, ClickHouse ~10:1
```

### Схема

```sql
CREATE TABLE rampart.blocked (
    ts          DateTime CODEC(Delta, ZSTD),
    edge        LowCardinality(String),
    src_ip      IPv4,
    src_asn     UInt32,
    src_country LowCardinality(FixedString(2)),
    reason      LowCardinality(String),
    proto_ver   Int32,
    hostname    String CODEC(ZSTD)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, edge, src_ip)
TTL ts + INTERVAL 90 DAY;

-- Materialized View для агрегатов (не пересчитываем каждый раз)
CREATE MATERIALIZED VIEW rampart.blocked_by_country_mv
ENGINE = SummingMergeTree()
ORDER BY (toDate(ts), src_country)
AS SELECT toDate(ts) as date, src_country, count() as hits
   FROM rampart.blocked GROUP BY date, src_country;
```

### Батч запись из Rust

```rust
// Не пишем на каждый пакет - накапливаем и сбрасываем раз в секунду
pub struct ClickHouseWriter {
    client: clickhouse::Client,
    buffer: Mutex<Vec<BlockedEvent>>,
}

impl ClickHouseWriter {
    pub async fn flush(&self) {
        let records = { self.buffer.lock().await.drain(..).collect::<Vec<_>>() };
        if records.is_empty() { return; }

        let mut insert = self.client.insert("rampart.blocked").unwrap();
        for r in &records { insert.write(r).await.unwrap(); }
        insert.end().await.unwrap();
    }
}
```

---

## Parca - continuous profiling

```yaml
# docker-compose.yml дополнение
  parca:
    image: ghcr.io/parca-dev/parca:latest
    ports:
      - "7070:7070"
    volumes:
      - ./parca.yaml:/etc/parca/parca.yaml

# parca.yaml
object_storage:
  bucket:
    type: FILESYSTEM
    config:
      directory: /tmp/parca

scrape_configs:
  - job_name: 'rampart-edge'
    scrape_interval: 10s
    targets:
      - targets: ['10.0.100.1:7071']  # pprof endpoint
```

```rust
// Включаем pprof endpoint в edge ноде
use pprof::ProfilerGuard;
// GET /debug/pprof/profile → CPU flame graph
// GET /debug/pprof/heap    → heap allocation graph
```

---

## tokio-console - debug async tasks

```bash
# Запуск edge с поддержкой tokio-console
TOKIO_CONSOLE_BIND=10.0.100.1:6669 \
RUST_LOG=tokio=trace \
./rampart-edge

# Подключение (на своей машине)
tokio-console http://10.0.100.1:6669
# Видишь все async tasks, их состояние, сколько они poll'ятся
```
