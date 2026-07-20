# Envoy - EWMA, Circuit Breaker, xDS API

> Актуально: v0.5+  
> Envoy как референс для алгоритмов балансировки.

---

## EWMA балансировщик (как в Envoy)

### Почему LEAST_CONN недостаточно

```
Проблема:
  Сервер A: 50 игроков, TPS 20 (быстрый)
  Сервер B: 48 игроков, TPS 12 (лагающий)
  LEAST_CONN выберет B → плохо

EWMA учитывает реальное время ответа:
  Сервер A: быстро → высокий score → больше игроков
  Сервер B: медленно → низкий score → меньше игроков
```

### Формула

```
effective_load = rtt_ewma × (active_requests + 1)
rtt_ewma_new   = α × rtt_ewma_old + (1 - α) × rtt_sample
α = 0.95 (decay, параметр сглаживания)
```

### Реализация

```rust
// balancer/ewma.rs

use std::sync::atomic::{AtomicU64, Ordering};

pub struct EwmaBackend {
    pub name: String,
    rtt_ewma_us: AtomicU64,    // EWMA в микросекундах
    active: AtomicU64,
}

impl EwmaBackend {
    pub fn new(name: String) -> Self {
        Self {
            name,
            rtt_ewma_us: AtomicU64::new(1000), // стартовое значение 1мс
            active: AtomicU64::new(0),
        }
    }

    pub fn record_rtt(&self, rtt: Duration) {
        let sample = rtt.as_micros() as u64;
        let old = self.rtt_ewma_us.load(Ordering::Relaxed);
        // EWMA: 95% старое + 5% новое измерение
        let new = (old * 95 + sample * 5) / 100;
        self.rtt_ewma_us.store(new, Ordering::Relaxed);
    }

    pub fn effective_load(&self) -> u64 {
        let rtt = self.rtt_ewma_us.load(Ordering::Relaxed);
        let active = self.active.load(Ordering::Relaxed);
        rtt.saturating_mul(active + 1)
    }

    pub fn acquire(&self) { self.active.fetch_add(1, Ordering::Relaxed); }
    pub fn release(&self) { self.active.fetch_sub(1, Ordering::Relaxed); }
}

pub struct EwmaBalancer {
    backends: Vec<Arc<EwmaBackend>>,
}

impl EwmaBalancer {
    pub fn select(&self) -> Option<Arc<EwmaBackend>> {
        self.backends.iter()
            .min_by_key(|b| b.effective_load())
            .cloned()
    }
}
```

---

## Circuit Breaker

```
CLOSED → нормальная работа, трафик идёт
  ↓ TPS < 12 или timeout > 3 сек подряд (N раз)
OPEN → сервер выведен из ротации
  ↓ через 30 сек (recovery timeout)
HALF_OPEN → пробный трафик (1 соединение)
  ↓ успешно → CLOSED
  ↓ снова ошибка → OPEN (увеличиваем timeout × 2)
```

```rust
// balancer/circuit_breaker.rs

pub enum State {
    Closed,
    Open { tripped_at: Instant, timeout: Duration },
    HalfOpen,
}

pub struct CircuitBreaker {
    state: State,
    failure_count: u32,
    failure_threshold: u32,  // сколько ошибок до OPEN
}

impl CircuitBreaker {
    pub fn should_route(&mut self) -> bool {
        match &self.state {
            State::Closed => true,

            State::Open { tripped_at, timeout } => {
                if tripped_at.elapsed() >= *timeout {
                    self.state = State::HalfOpen;
                    true
                } else {
                    false
                }
            }

            State::HalfOpen => true,
        }
    }

    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = State::Closed;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        if self.failure_count >= self.failure_threshold {
            let timeout = match &self.state {
                State::Open { timeout, .. } => *timeout * 2, // exponential backoff
                _ => Duration::from_secs(30),
            };
            self.state = State::Open {
                tripped_at: Instant::now(),
                timeout: timeout.min(Duration::from_secs(300)), // max 5 мин
            };
        }
    }
}
```

---

## Health Scoring

```rust
pub fn calculate_health_score(server: &ServerEntry) -> f64 {
    let tps_score = (server.tps / 20.0).min(1.0);           // 0..1
    let player_score = 1.0 - (server.online as f64 / server.max_players as f64);
    let mspt_score = (1.0 - server.mspt / 50.0).max(0.0);   // 50ms MSPT = 0 score
    let ram_score = 1.0 - (server.ram_used as f64 / server.ram_max as f64);

    // Взвешенная сумма
    tps_score * 0.40
    + player_score * 0.30
    + mspt_score * 0.20
    + ram_score * 0.10
}

// Балансировщик выбирает по score вместо LEAST_CONN
pub fn select_by_score(servers: &[ServerEntry]) -> Option<&ServerEntry> {
    servers.iter()
        .filter(|s| calculate_health_score(s) > 0.3) // минимальный порог
        .max_by(|a, b| {
            calculate_health_score(a)
                .partial_cmp(&calculate_health_score(b))
                .unwrap()
        })
}
```

---

## Consistent Hashing (друзья на одном Hub)

```rust
// Игроки с одной группой попадают на один Hub
// При добавлении новых Hubs - минимальная миграция игроков

use std::collections::BTreeMap;

pub struct ConsistentHash {
    ring: BTreeMap<u64, String>, // hash → server_name
    vnodes: u32,  // виртуальные ноды (больше = равномернее)
}

impl ConsistentHash {
    pub fn new(vnodes: u32) -> Self {
        Self { ring: BTreeMap::new(), vnodes }
    }

    pub fn add_server(&mut self, name: &str) {
        for i in 0..self.vnodes {
            let key = hash(&format!("{}-{}", name, i));
            self.ring.insert(key, name.to_string());
        }
    }

    pub fn get_server(&self, player_uuid: &Uuid) -> Option<&str> {
        if self.ring.is_empty() { return None; }
        let hash = hash(&player_uuid.to_string());
        // Идём по кольцу вправо от hash
        self.ring.range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, name)| name.as_str())
    }
}

// Применение: для хабов, где важно чтобы друзья были рядом
// Для game серверов - EWMA (важна нагрузка, не стабильность)
```

---

## xDS API (Envoy паттерн для динамической конфигурации)

> Актуально v0.6+ - если нод станет 100+

xDS - протокол от Envoy/Istio для динамической доставки конфигурации нодам. Вместо того чтобы каждая нода поллила Redis - Manager пушит изменения через gRPC stream.

```
Manager (xDS сервер)
  ↓ gRPC stream (двунаправленный)
Edge ноды / LB ноды (xDS клиенты)

При изменении конфига (новый сервер, новое правило):
  Manager → push → все ноды получают обновление мгновенно
  Нет поллинга, нет задержки
```
