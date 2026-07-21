# DDoS — Векторы атак и защита

> Актуально: v0.2+

---

## Как трафик проходит защиту

```
Атакующий (ботнет)
    |
    v
┌──────────────────┐
│  XDP/eBPF        │  L3/L4: TCP state machine, SYN throttle,
│  (ядро)          │  IP blacklist, invalid TCP flags, UDP drop
│                  │  CPU < 30%, пропускная способность ~10M pps
└────────┬─────────┘
         v (чистый TCP, прошёл state machine)
┌──────────────────┐
│  PoW Challenge   │  SHA256 hashcash, dynamic difficulty
│  (Rust)          │  Анти-handshake-flood: CPU затраты на боте
└────────┬─────────┘
         v (валидный PoW)
┌──────────────────┐
│  Rust Core       │  L7: handshake parse, HMAC, rate limit,
│  (userspace)     │  death code auto-ban, blacklist
│                  │  CPU < 50%, пропускная способность ~85k conn/s
└────────┬─────────┘
         v (валидный MC handshake + HMAC)
┌──────────────────┐
│  Velocity        │  Domain whitelist, HMAC verify,
│  (Java)          │  Физика (falling + vehicle), CAPTCHA
│                  │  TPS-aware load balancer, circuit breaker
└────────┬─────────┘
         v (верифицированный игрок)
┌──────────────────┐
│  Game Server     │  Чистый трафик, без DDoS нагрузки
└──────────────────┘
```

Каждый слой отрабатывает и дропает до перехода к следующему.
XDP — L3/L4, PoW — anti-handshake-flood, Rust — L7, Velocity — верификация.

---

## L3/L4 атаки (объёмные)

| Атака | Механизм | Защита | Слой |
|-------|----------|--------|------|
| **UDP Flood** | Миллионы UDP пакетов | MC = TCP, UDP дроп | XDP |
| **SYN Flood** | Миллионы TCP SYN без ACK | SYN throttle per-IP + SYN cookies | XDP + sysctl |
| **ACK Flood** | Пакеты с ACK без SYN | TCP state machine (ACK без SYN → вне state → дроп) | XDP |
| **ICMP Flood** | Ping flood | `icmp_echo_ignore_all=1` | sysctl |
| **Amplification** | DNS/NTP усиление | Фильтрация у провайдера | Upstream |
| **Invalid flags** | SYN+FIN, SYN+RST, URG | `detect_tcp_bypass()` | XDP |
| **IP Spoof** | Поддельный src IP | uRPF + conntrack seq check | XDP |
| **Fragmented** | Разбитые TCP пакеты | Дроп first fragment с MF | XDP |
| **RST flood** | Миллионы RST | Игнорировать RST без matching state | XDP |
| **FIN flood** | Миллионы FIN | FIN без matching state → дроп | XDP |

### sysctl для L3/L4

```bash
# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ICMP
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Буферы
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
```

---

## L7 атаки (Minecraft-специфичные)

### Handshake Flood
Боты коннектятся тысячами, шлют валидный handshake, дропают.

```
Детект: connections/sec с одного IP > threshold
Защита: PoW Challenge (Layer 2) + rate limit (Layer 3)
  PoW difficulty повышается при CPS > 50/100/500
  Rate limit: token bucket 5 conn/IP/sec, burst 10

Уязвимость других решений: Sonar/LimboFilter/AtomGuard
  не имеют PoW — handshake flood упирается только в
  rate limit, который обходится через ботнет
```

### Bot Join Flood
Тысячи фейковых логинов с разных IP, каждый с разных IP.

```
Детект: CPS глобально > threshold (учитываем baseline 168h)
Защита: PoW (дорого для бота) + falling check (нужна MC физика)
  + verified DB (прошедшие не проверяются снова)

Уязвимость AtomGuard:
  SynFloodDetector.effectiveCPS = 0 при < 15 unique IP
  → атака 14 IP с 100 conn/s каждый = не детектится
Фикс: не обнулять, per-IP fallback
```

### Ping Flood (Status Request)
Тысячи пакетов с next_state=1 (статус, не логин).

```
Детект: status requests/sec > threshold
Защита: отдельный rate limit для статуса (next_state=1)
  max 2 status/IP/10sec, burst 5
```

### Slow Loris (MC вариант)
Открывают TCP, отправляют handshake по 1 байту — занимают слоты.

```
Детект: время на полный handshake > 5 сек
Защита: tokio::timeout на чтение handshake
  Rust: tokio::time::timeout(Duration::from_secs(5), read_handshake())
```

### Fake Forge Flood
Бесконечный поток Forge handshake с мусорными mod list.

```
Детект: mod list > 500 модов или > 4096 байт
Защита: max_hostname = 4096, max_mods = 500, bounds check на VarInt
```

### VarInt Overflow
Специально сформированные VarInt для integer overflow.

```
Детект: VarInt > 5 байт (по MC протоколу)
Защита: строгий bounds check, паника = DROP, не crash
  Result<T, Error>, не unwrap()
```

---

## AI-боты (2026)

### Что обходится

| Решение | Обход |
|---------|-------|
| **Sonar gravity** | AI симулирует MC физику |
| **Sonar vehicle** | AI шлёт правильные пакеты лодки |
| **LimboFilter falling** | AI вычисляет parabola `(0.98^t-1)*3.92` |
| **Map CAPTCHA (3-4 символа)** | OCR/ML (Sonar #531) |
| **Timing check** | AI имитирует human distribution |

### Что работает

```
✓ PoW (SHA256)        вычислительная стоимость, GPU не асится
✓ HMAC                криптография, ключ на edge ноде
✓ Многослойность      6 слоёв вместо 1
✓ Dynamic difficulty  при атаке повышаем PoW до 12+
✓ ASN reputation      датацентры = повышенная строгость
```

---

## Circuit Breaker

```
CLOSED (нормально)
  ↓ TPS < 12 или timeout > 3 сек → OPEN
OPEN (сервер выведен из ротации)
  ↓ через 30 сек → HALF_OPEN (пробный трафик)
HALF_OPEN
  ↓ успешно → CLOSED
  ↓ снова плохо → OPEN
```

```rust
pub enum CircuitState { Closed, Open(Instant), HalfOpen }

impl CircuitBreaker {
    pub fn should_route(&mut self, server: &ServerEntry) -> bool {
        match &self.state {
            CircuitState::Closed => {
                if server.tps < 12.0 { self.trip(); false }
                else { true }
            }
            CircuitState::Open(tripped_at) => {
                if tripped_at.elapsed() > Duration::from_secs(30) {
                    self.state = CircuitState::HalfOpen;
                    true
                } else { false }
            }
            CircuitState::HalfOpen => true,
        }
    }
}
```

---

## ASN Reputation

```rust
pub enum AsnCategory {
    Residential,  // обычный провайдер → 1.0 rate limit
    Datacenter,   // Hetzner/AWS/OVH → 0.2 rate limit
    Mobile,       // мобильный NAT → 0.5 (но не блокировать!)
    Tor,          // Tor exit → 0.05
    Vpn,          // известный VPN → настраивается
    Unknown,      // новый IP → 0.5
}

fn rate_multiplier(cat: &AsnCategory) -> f64 {
    match cat {
        AsnCategory::Residential => 1.0,
        AsnCategory::Mobile      => 0.5,
        AsnCategory::Datacenter  => 0.2,
        AsnCategory::Vpn         => 0.3,
        AsnCategory::Tor         => 0.05,
        AsnCategory::Unknown     => 0.5,
    }
}
```

> ⚠️ Мобильные NAT: один IP = много игроков. Не блокировать, только снижать лимит.

---

## Timing Analysis

```rust
pub struct TimingAnalyzer {
    response_times: Vec<f64>,   // ms
}

impl TimingAnalyzer {
    pub fn is_bot(&self, response_ms: f64) -> f64 {
        // Слишком быстро → скрипт
        if response_ms < 200.0 { return 0.9; }

        // Слишком ровно → паттерн
        if self.response_times.len() >= 5 {
            let variance = self.variance();
            if variance < 10.0 { return 0.85; }
        }

        // Нормальное распределение → человек
        0.1
    }

    fn variance(&self) -> f64 {
        let mean = self.response_times.iter().sum::<f64>()
            / self.response_times.len() as f64;
        self.response_times.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / self.response_times.len() as f64
    }
}
```
