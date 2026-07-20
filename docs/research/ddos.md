# DDoS - Векторы атак и защита

> Актуально: v0.1+
> Это лучший раздел документации - глубокий разбор всех известных векторов.

---

## Как трафик проходит через защиту

```
Атакующий (ботнет)
    |
    v
┌──────────────────┐
│  1. NIC / XDP    │  L3/L4: SYN flood, UDP drop, IP blacklist
│  (kernel, C)     │  CPU < 30%, дроп до 10M pps
└────────┬─────────┘
         v (чистый TCP)
┌──────────────────┐
│  2. Rust Core    │  L7: парсинг handshake, HMAC, rate limit
│  (userspace)     │  death code auto-ban, blacklist check
└────────┬─────────┘
         v (валидный MC клиент)
┌──────────────────┐
│  3. Load         │  Round-robin, circuit breaker
│  Balancer/Proxy  │  TPS < 12 = server out
└────────┬─────────┘
         v
┌──────────────────┐
│  4. Game Server  │  Чистый трафик, без DDoS нагрузки
│  (Velocity/Hub)  │
└──────────────────┘
```

Каждый слой отрабатывает и дропает до перехода к следующему.
XDP отсекает L3/L4 флуд, Rust - L7 атаки на протокол MC.

---

## L3/L4 атаки (объёмные)

| Атака | Механизм | Защита | Слой |
|---|---|---|---|
| **UDP Flood** | Миллионы UDP пакетов | MC = TCP, UDP дропается на уровне NIC | XDP |
| **SYN Flood** | Миллионы TCP SYN без ACK | SYN cookies в ядре Linux | XDP + sysctl |
| **ACK Flood** | Пакеты с ACK без SYN | Stateful connection tracking | XDP |
| **ICMP Flood** | Ping flood | Отключить ICMP ответы | sysctl |
| **Amplification** | DNS/NTP усиление | Фильтрация у провайдера (UDP) | Upstream |
| **Invalid flags** | TCP с мусорными флагами | XDP дроп по флагам | XDP |
| **IP Spoof** | Поддельный src IP | BPF map проверка + uRPF | XDP |

### sysctl для L3/L4 защиты

```bash
# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ICMP
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Общие буферы
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
Защита: rate limit (token bucket) в Rust
Параметры: max 5 conn/IP/сек, burst 10
```

### Bot Join Flood
Тысячи фейковых логинов с разных IP.

```
Детект: LoginStart без предшествующего challenge
Защита: Sonar antibot (физика на limbo) + custom challenge
Параметры: очередь 100 одновременных верификаций
```

### Ping Flood (Status Request)
Тысячи пакетов с next_state=1 (не логин, просто пинг).

```
Детект: status requests/сек > threshold с IP
Защита: отдельный rate limit для status (next_state=1)
Параметры: max 2 status/IP/10сек
```

### Slow Loris (MC вариант)
Открывают TCP, шлют handshake по 1 байту каждые несколько секунд - занимают слоты.

```
Детект: время на handshake > 5 сек
Защита: connection timeout (5 сек на получение полного handshake)
Rust: tokio::time::timeout(Duration::from_secs(5), read_handshake())
```

### Fragmented Handshake
Handshake пакет разбит на несколько TCP сегментов - ломает парсеры.

```
Детект: невозможно, это нормальный TCP
Защита: robust парсер с reassembly буфером
        читаем до N байт пока не получим полный пакет
        timeout если слишком долго
```

### Fake Forge Flood
Бесконечный поток Forge handshake с мусорными mod list - ломает парсер.

```
Детект: mod list длиннее разумного (> 500 модов)
Защита: max_hostname_length = 4096, дроп при превышении
        парсер с явными bounds check на каждый VarInt
```

### VarInt Overflow
Специально сформированные VarInt которые вызывают integer overflow.

```
Детект: VarInt > 5 байт (по MC протоколу)
Защита: строгий bounds check, паника = DROP не crash

// Правильный парсер с защитой
fn read_varint(buf: &[u8]) -> Result<(i32, usize), Error> {
    let mut value: i32 = 0;
    let mut position = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if i >= 5 { return Err(Error::VarIntTooBig); } // MAX 5 байт
        value |= ((byte & 0x7F) as i32) << position;
        if (byte & 0x80) == 0 { return Ok((value, i + 1)); }
        position += 7;
    }
    Err(Error::Incomplete)
}
```

---

## AI-боты (2026)

### Проблема

Современные attack frameworks используют AI и базы CAPTCHA решений:
- Боты проходят физику Sonar (реализован настоящий MC движок)
- Боты решают математические задачи в чате
- Боты кликают на блоки по описанию
- LimboFilter полностью обходится

### Что всё ещё работает

```
✓ HMAC верификация - только через наш edge (криптография)
✓ Rate limit на edge - физически ограничивает скорость
✓ ASN блокировка - датацентры не могут быть "жилыми" IP
✓ Репутационная система - долго строить репутацию
✓ Кастомный challenge - нет готового обхода
✓ Timing analysis - боты отвечают слишком быстро или паттернами
```

### Кастомный challenge - идеи которые сложно автоматизировать

```
1. Timing-based: игрок должен ответить МЕЖДУ 2 и 8 секундами
   (слишком быстро = бот, слишком медленно = AFK скрипт)

2. Контекстный вопрос: вопрос зависит от случайного события
   на сервере в последние 5 минут (бот не знает контекст)

3. Изменяющаяся механика: challenge меняется каждые 6 часов
   (атакующий должен постоянно обновлять обход)

4. Map-based CAPTCHA: картинка рендерится на карте в инвентаре
   случайным шрифтом из пула 50+ шрифтов

5. Поведенческий анализ: первые 30 сек на хабе - смотрим
   на паттерны движения, мыши, взаимодействий
```

### Timing Analysis

```rust
// Боты часто отвечают с константной задержкой
// Реальные игроки - с нормальным распределением

pub struct TimingAnalyzer {
    response_times: Vec<Duration>,
}

impl TimingAnalyzer {
    pub fn is_bot_timing(&self, response_time: Duration) -> f64 {
        let ms = response_time.as_millis() as f64;

        // Слишком быстро - скрипт
        if ms < 200.0 { return 0.9; }

        // Слишком ровно - паттерн (variance < 10ms за 5 измерений)
        if self.response_times.len() >= 5 {
            let variance = self.calculate_variance();
            if variance < 10.0 { return 0.85; }
        }

        // Нормальное распределение - человек
        0.1
    }
}
```

---

## Circuit Breaker для перегруженных серверов

```
CLOSED (нормально)
  ↓ TPS < 12 или timeout > 3 сек → OPEN
OPEN (сервер выведен)
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
                    true // пробуем
                } else { false }
            }
            CircuitState::HalfOpen => true,
        }
    }
}
```

---

## ASN Reputation

Разные лимиты для разных типов сетей:

```rust
pub enum AsnReputation {
    Residential,     // обычный провайдер → стандартные лимиты
    Datacenter,      // AWS/OVH/Hetzner → строгие лимиты
    Mobile,          // мобильные сети → средние лимиты (NAT!)
    Tor,             // Tor exit node → максимальная строгость
    Vpn,             // известный VPN → настраивается
    Unknown,
}

// rate limit множитель по типу ASN
fn rate_limit_multiplier(rep: &AsnReputation) -> f64 {
    match rep {
        AsnReputation::Residential => 1.0,
        AsnReputation::Mobile      => 0.5, // NAT - много игроков с 1 IP
        AsnReputation::Datacenter  => 0.2,
        AsnReputation::Vpn         => 0.3,
        AsnReputation::Tor         => 0.05,
        AsnReputation::Unknown     => 0.5,
    }
}
```

> ⚠️ Мобильные сети используют NAT - один IP = много реальных игроков.  
> Не блокируй мобильные ASN полностью, только снижай лимит.
