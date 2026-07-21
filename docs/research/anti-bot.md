# Anti-Bot стратегия

> Актуально: v0.2+

---

## 6 слоёв антибот защиты

```
┌──────────────────────────────────────────────────────────────────┐
│  Слой 1: XDP/eBPF                    дроп L3/L4 на уровне ядра │
│  ─────────────────────────────────────                              │
│  TCP state machine: SYN → SYN-ACK → ожидание MC handshake         │
│  SYN throttle: N SYNs/IP/сек → временный бан                      │
│  Invalid flags: SYN+FIN, SYN+RST, URG → дроп                     │
│  UDP: дроп (MC работает только по TCP)                           │
│                                                                   │
│  Бот не может: открыть >N TCP соединений/сек с одного IP         │
├──────────────────────────────────────────────────────────────────┤
│  Слой 2: PoW Challenge                  анти-handshake-flood     │
│  ─────────────────────────────────────                              │
│  Перед HMAC handshake клиент решает SHA256 hashcash:              │
│  1. Edge шлёт {challenge, difficulty, allowedHex, timestamp}      │
│  2. Клиент ищет nonce: SHA256(challenge + nonce) начинается с    │
│     difficulty символов из allowedHex                              │
│  3. Edge верифицирует, challenge одноразовый (timestamp + nonce)  │
│  4. Dynamic difficulty: 12 при атаке, 4 в спокойное время        │
│                                                                   │
│  Бот не может: открывать >50 handshake/сек (PoW жрёт CPU)        │
│  Nonce replay невозможен: challenge + timestamp уникальны         │
├──────────────────────────────────────────────────────────────────┤
│  Слой 3: Rust Core                       L7 проверки             │
│  ─────────────────────────────────────                              │
│  Rate limit: N conn/IP/сек (token bucket)                         │
│  Death code: 8 паттернов малициозных пакетов → автобан           │
│  Blacklist: global + per-IP, Redis sync                          │
│  ASN reputation: датацентры → строже, residential → мягче         │
│  Timeout: 5 сек на полный handshake (anti-Slow Loris)            │
│                                                                   │
│  Бот не может: слать >5 conn/сек, слать мусор в пакетах          │
├──────────────────────────────────────────────────────────────────┤
│  Слой 4: Velocity                        верификация игроков     │
│  ─────────────────────────────────────                              │
│  Domain whitelist: блок прямых IP, разрешены только наши домены  │
│  HMAC verify: hostname содержит \0shield\0<sig>                  │
│  Falling check: spawn Y=512, 128 тиков физики падения            │
│  Protocol check: Transaction, SetHeldItem, ArmAnimation          │
│  Vehicle check: Boat + Minecart gravity + paddle packets          │
│  CAPTCHA: map item или PoW                                        │
│                                                                   │
│  Бот не может: зайти без HMAC, пройти физику без симуляции MC   │
├──────────────────────────────────────────────────────────────────┤
│  Слой 5: Traffic Intelligence              аналитика            │
│  ─────────────────────────────────────                              │
│  168-hour профиль: baseline соединений по часам и дням недели    │
│  EWMA adaptive thresholds: аномалии относительно baseline        │
│  Z-Score: 3σ от среднего → алерт                                 │
│  Reputation: score -100..+100, влияет на rate limit множитель    │
│  Attack detection: CPS > threshold → режим атаки                 │
│                                                                   │
│  Бот не может: атаковать незаметно — дёргает threshold           │
├──────────────────────────────────────────────────────────────────┤
│  Слой 6: Verified DB (Redis)              кэш верификации        │
│  ─────────────────────────────────────                              │
│  HMAC-SHA256 fingerprint: SHA256(secret, username, IP)            │
│  TTL: 24 часа без активности, продлевается при каждом входе     │
│  Skip: верифицированные проходят слои 2-4 мгновенно             │
│                                                                   │
│  Бот не может: подделать fingerprint (HMAC, не hashCode)         │
└──────────────────────────────────────────────────────────────────┘
```

## Путь игрока через защиту

```
Новый игрок
    |
    v
┌──────────────────┐
│  XDP/eBPF        │  TCP handshake processing
│  Ядро Linux      │  Прошёл SYN throttle + state machine
└────────┬─────────┘
         v (TCP соединение установлено)
┌──────────────────┐
│  PoW Challenge   │  SHA256 hashcash
│  Rust            │  Dynamic difficulty, одноразовый challenge
└────────┬─────────┘
         v (PoW решён)
┌──────────────────┐
│  Rust Core       │  Rate limit, Death code, Blacklist
│  userspace       │  HMAC sign hostname
└────────┬─────────┘
         v (валидный MC handshake + HMAC)
┌──────────────────┐
│  Velocity        │  Domain whitelist, HMAC verify
│  Java            │  Falling check → Protocol check
│                  │  → Vehicle check → CAPTCHA
└────────┬─────────┘
         v (верифицирован)
┌──────────────────┐
│  Hub / Game      │  Игрок на сервере
│  Server          │
└──────────────────┘
```

## Защита от AI-ботов (2026)

### Проблема
Современные attack frameworks обходят существующие anti-bot решения:

| Решение | Обход |
|---------|-------|
| **Sonar gravity check** | AI симулирует MC физику |
| **LimboFilter falling** | Робот считает parabola |
| **Map CAPTCHA (Sonar)** | OCR решает 3-4 символа |
| **Математические задачи** | AI решает за <100ms |
| **Timing check** | AI имитирует human timing |

### Что работает против AI

```
✓ PoW (Layer 2):        вычислительная стоимость, GPU не помогает
                        достаточно (SHA256 не memory-hard)
✓ HMAC (Layer 3+4):     криптография, не обходится без ключа
✓ ASN reputation:       датацентры = боты
✓ Dynamic difficulty:   при атаке повышаем PoW сложность
✓ Многослойность:       нужно обойти 6 слоёв, а не 1
```

## Fingerprinting (исправленный)

```rust
// В отличие от Sonar (использующего hashCode + сдвиги без соли),
// Rampart использует HMAC-SHA256 с ротацией ключа:

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_fingerprint(secret: &[u8], username: &str, ip: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC key");
    mac.update(username.as_bytes());
    mac.update(b"\0");
    mac.update(ip.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

// Свойства:
// - Нет коллизий (SHA256)
// - Нет подделки (HMAC, не hash code)
// - Нет обратной инженерии (secret на edge ноде)
// - Ротация ключа каждые 24ч
// - Разные secret для разных слоёв (XDP_key, PoW_key, HMAC_key)
```

## Verified Player Cache

```rust
// После прохождения всех слоёв — fingerprint в Redis:
//
// Ключ:    rampart:verified:{sha256_fingerprint}
// Значение: { ip, username, verified_at, last_seen, ttl }
// TTL:     24h (продлевается при каждом входе)
//
// При повторном входе:
// 1. Вычисляем fingerprint
// 2. Проверяем Redis
// 3. Если есть и IP совпадает → слои 2-4 пропускаются
// 4. Если IP изменился → проходим верификацию заново

pub fn is_verified(redis: &Client, username: &str, ip: &str) -> bool {
    let fp = compute_fingerprint(&get_secret(), username, ip);
    let key = format!("rampart:verified:{}", fp);

    match redis.get::<String>(&key) {
        Ok(Some(data)) => {
            let entry: VerifiedEntry = serde_json::from_str(&data).ok()?;
            if entry.ip == ip {
                // Продлеваем TTL
                let _ = redis.expire(&key, 86400);
                return true;
            }
        }
        _ => {}
    }
    false
}
```

## PoW Challenge (Layer 2)

```rust
// Hashcash-style proof of work
// Адаптировано из PowGo: +timestamp, +per-request challenge, dynamic difficulty

pub struct Challenge {
    pub token: [u8; 16],        // случайный per-request
    pub timestamp: u64,          // unix ms
    pub difficulty: u8,          // 4-12, динамический
    pub allowed_hex: &'static str, // "012def" по умолчанию
}

pub struct Solution {
    pub token: [u8; 16],
    pub nonce: u64,
}

pub fn verify(challenge: &Challenge, solution: &Solution) -> bool {
    // 1. Timestamp validity (max 30 seconds old)
    let age = current_timestamp_ms() - challenge.timestamp;
    if age > 30_000 { return false; }

    // 2. Token match
    if challenge.token != solution.token { return false; }

    // 3. Hash verification
    let mut data = [0u8; 32];
    data[..16].copy_from_slice(&challenge.token);
    data[16..24].copy_from_slice(&solution.nonce.to_le_bytes());

    let hash = sha256(&data);
    let hex = hex::encode(hash);
    for i in 0..challenge.difficulty as usize {
        let c = hex.as_bytes()[i] as char;
        if !challenge.allowed_hex.contains(c) {
            return false;
        }
    }
    true
}

// Dynamic difficulty adjustment
pub fn get_difficulty(cps: u64, attack_mode: bool) -> u8 {
    match (cps, attack_mode) {
        (_, true) | (cps, _) if cps > 500 => 12,
        (cps, _) if cps > 100 => 10,
        (cps, _) if cps > 50  => 8,
        _ => 4,
    }
}
```

## Матрица атак MHDDoS vs Rampart

Анализ [MHDDoS](https://github.com/MatrixTM/MHDDoS.git) — самый популярный DDoS тул на Python (25k+ stars).

| Метод атаки | Тип | Как работает | Блокируется слоем | Примечание |
|-------------|-----|-------------|-------------------|-----------|
| **SYN** | L4 RAW | SYN flood с подделкой source IP | Layer 1 (XDP SYN throttle) | Если XDP отключён — iptables SYN cookie |
| **TCP** | L4 | randbytes(1024) в TCP сокет | Layer 1 (conntrack) | Аномальный трафик, мало данных |
| **UDP** | L4 | randbytes(1024) через UDP | Layer 1 (UDP drop) | MC только TCP, UDP дропается |
| **CPS** | L4 | Открыть/закрыть TCP | Layer 1 (SYN throttle) + Layer 3 (rate limit) | 50+ conn/s → block |
| **CONNECTION** | L4 | Держать TCP открытым | Layer 1 (idle timeout) + Layer 3 (conntrack) | 30s idle → evict |
| **MINECRAFT** | L4 | Handshake + ping флуд | Layer 2 (PoW) + Layer 3 (rate limit) | PoW требует CPU |
| **MCBOT** | L4/L7 | Полная эмуляция игрока (login → чат) | Layer 4 (Physics) + Layer 6 (reputation) | Самый опасный для MC |
| **ICMP** | L4 RAW | ICMP echo flood | Layer 1 (ICMP rate-limit) | На уровне ядра |
| **DNS/NTP/MEM** | L4 AMP | Amplification через рефлекторы | Layer 1 (UDP drop) | UDP не на MC порты |
| **GET/POST/HEAD** | L7 | HTTP флуд | Layer 3 (rate limit) | 100 req/s → block |
| **CFB** | L7 | HTTP через cloudscraper (обходит CF) | Layer 3 (rate limit per IP) | Прокси не спасают — Rampart видит реальный IP |
| **SLOW** | L7 | Slowloris: медленные заголовки | Layer 3 (read timeout 10s) | Таймаут закрывает |
| **BOT** | L7 | Имитация Googlebot | Layer 6 (168h профиль) | Аномалия в час-слоте |
| **BOMB** | L7 | HTTP/2 через SOCKS5 прокси | Layer 6 (EWMA thresholds) | PPS аномалия |
| **DGB** | L7 | Обход DDoS-Guard | Layer 3 (HMAC verify) | После HMAC — невалидная подпись |
| **APACHE** | L7 | Range-атака (CVE-2011-3192) | Layer 3 (packet inspect) | Малый HTTP трафик |

### Сводка
- **Layer 1 (XDP)** блокирует: SYN, UDP, ICMP, AMP, TCP flood
- **Layer 2 (PoW)** блокирует: MINECRAFT handshake flood
- **Layer 3 (Core)** блокирует: CPS, CONNECTION, HTTP flood, SLOW, APACHE
- **Layer 4 (Physics)** блокирует: MCBOT (неестественное движение)
- **Layer 6 (Traffic Intel)** блокирует: BOT, BOMB, аномалии по 168h профилю
- **Не покрыто полностью:** CFB через 10k+ уникальных IP (нужна репутация Layer 6)

## Известные проблемы в других решениях

| Проблема | Где найдено | Наше решение |
|----------|-------------|--------------|
| **Fingerprint = hashCode + сдвиги, без соли** | Sonar | HMAC-SHA256 с ротацией ключа |
| **CAPTCHA проходима AI (3-4 символа, map colors)** | Sonar #531 | PoW вместо/поверх CAPTCHA |
| **4x re-verification race** | Sonar #611 | Idempotent finish, atomic state |
| **KeepAlive ID plaintext** | Sonar | Challenge-response с HMAC |
| **QuietDecoderException как control flow** | Sonar | Result<T, E> без исключений |
| **checkY() fast-forward** | LimboFilter | Строгий шаг: 1 tick за вызов |
| **ignoredTicks не сбрасывается** | LimboFilter | Сброс на валидном move |
| **Memory leak MapData** | LimboFilter #118 | Weak refs, explicit cleanup |
| **Isolation Forest мёртвый код** | AtomGuard | Реально используем или убираем |
| **EWMA variance double-smoothing** | AtomGuard | Правильная формула |
| **Race в pipeline checks.clear/addAll** | AtomGuard | Copy-on-write |
| **SynFloodDetector при <15 IP отключается** | AtomGuard | Per-IP fallback |
| **AntiBot plugin пустой** | Infrarust | Реализован с первого коммита |
| **Rate limit disabled by default** | Infrarust | Enabled по умолчанию |
| **TCP handshake deadlock (pure ACK drop)** | MC-XDP-eBPF | Не дропать pure ACK |
| **Stale state on RST/FIN** | MC-XDP-eBPF | Удалять entry на RST |
| **Nonce replay** | PowGo | Per-request challenge + timestamp |
| **Static difficulty** | PowGo | Dynamic по CPS |
