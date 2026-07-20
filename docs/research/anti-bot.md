# Anti-Bot - Sonar, Challenge системы, Fingerprinting

> Актуально: v0.2+

## Путь игрока через защиту

```
Новый игрок
    |
    v
┌──────────────────┐
│  Edge нода       │  Rate limit, Blacklist, Death code
│  Rust            │  Невалидные пакеты → бан IP
└────────┬─────────┘
         v (валидный handshake)
┌──────────────────┐
│  Velocity        │  DomainCheck, HmacCheck
│  Java            │  Неизвестный домен → блок
└────────┬─────────┘
         v (подписанный HMAC)
┌──────────────────┐
│  Sonar Limbo     │  Гравитация, Vehicle, TCP timing
│  Java            │  Не прошёл → блок IP на N мин
└────────┬─────────┘
         v (прошёл физику)
┌──────────────────┐
│  Custom          │  Timing challenge, Map CAPTCHA
│  Challenge       │  Не прошёл → блок IP
└────────┬─────────┘
         v
┌──────────────────┐
│  Hub / Game      │  Игрок на сервере
│  Server          │  Поведенческий анализ первые 30 сек
└──────────────────┘
```

Каждый слой может заблокировать игрока.
Verified DB на Redis - прошёл один раз, не проверяется снова (TTL 24h).

---

## Слои защиты от ботов

```
[1] XDP rate limit         - ограничивает скорость SYN flood
[2] Rust rate limit        - ограничивает connections/сек per IP
[3] HMAC verification      - только через наш edge (криптография)
[4] ASN reputation         - датацентровые IP = строже
[5] Sonar 3.0 (Limbo)     - физическая проверка
[6] Custom challenge       - кастомная механика (нет готового обхода)
[7] Behavioral analysis    - паттерны поведения на хабе
```

---

## Sonar 3.0 - базовый слой (июль 2026)

GitHub: `jonesdevelopment/sonar`  
Версия: 3.x, релиз 12 июля 2026  
Поддержка: Velocity 3.4-3.5.x, MC 1.8-26.2

### Как работает

```
Игрок → Velocity → Sonar перехватывает
  ↓
Отправляет на Limbo (лёгкий фейковый сервер)
  ↓
Проверки на Limbo:
  ├─ Гравитация: игрок должен падать вниз
  ├─ Vehicle: правильные пакеты при взаимодействии с лодкой
  ├─ TCP timing: не слишком быстрые ответы
  └─ Очередь: физически ограничивает число одновременных верификаций
  ↓
Прошёл → IP в verified DB → следующие подключения проходят мгновенно
```

### Конфиг

```yaml
# sonar/config.yml
general:
  max-online-per-ip: 3
  min-players-for-attack: 8       # при N+ новых conn/сек → режим атаки

verification:
  timing:
    first-packet: 3500            # мс на первый пакет
    movement: 10000               # мс на проверку физики
  gravity:
    enabled: true
    captcha-on-fail: true
  vehicle:
    enabled: true

database:
  type: MYSQL                     # или POSTGRESQL, H2
  host: "10.0.0.1"
  database: "sonar"
  expiration: 5                   # verified IP живёт N дней
```

---

## Кастомный challenge (поверх Sonar)

### Почему нужен кастомный

```
Sonar открытый → атакующий читает код → пишет обход
Кастомный → нет готового обхода → атакующий тратит время
Меняем механику регулярно → обход устаревает
```

### Идеи challenge (от простого к сложному)

#### 1. Timing challenge
```java
// Игрок должен ответить МЕЖДУ 2 и 8 секундами
// Боты отвечают мгновенно или с постоянной задержкой

long sent = System.currentTimeMillis();
// ...ждём ответ...
long elapsed = System.currentTimeMillis() - sent;

if (elapsed < 2000) {
    // Слишком быстро - скрипт
    fail("Ответ слишком быстрый");
} else if (elapsed > 8000) {
    // AFK/медленный скрипт
    fail("Время вышло");
} else {
    pass();
}
```

#### 2. Map CAPTCHA
```java
// Рендерим картинку на карте Minecraft
// Случайный шрифт из пула 50+ шрифтов
// Игрок вводит код в чате

MapRenderer renderer = new CaptchaMapRenderer(challenge.getCode());
ItemStack map = new ItemStack(Material.FILLED_MAP);
map.setItemMeta(mapMeta);
player.getInventory().setItemInMainHand(map);
player.sendMessage("§eВведи код с карты в чат:");
```

#### 3. Поведенческий анализ (первые 30 сек на хабе)
```java
// Смотрим на паттерны движения
// Реальный игрок: случайные повороты, ускорения, паузы
// Бот: линейное движение или полная неподвижность

@EventHandler
public void onPlayerMove(PlayerMoveEvent e) {
    BehaviorProfile profile = profiles.get(e.getPlayer().getUniqueId());
    profile.recordMovement(e.getTo());

    if (profile.getSamples() >= 50) {
        double score = profile.calculateBotProbability();
        if (score > 0.85) {
            triggerChallenge(e.getPlayer());
        }
    }
}
```

#### 4. Контекстный вопрос
```java
// Вопрос зависит от случайного события на сервере
// Бот не знает контекст

String[] events = {"Последний вошедший игрок", "Текущее время на сервере"};
// "Как зовут последнего игрока который зашёл перед тобой?"
// Бот не знает → провал
```

---

## Репутационная система IP

```rust
// Каждый IP получает score от -100 до +100
// Хранится в Redis с TTL

pub struct IpReputation {
    score: i32,
    last_updated: u64,
}

impl IpReputation {
    pub fn apply_event(&mut self, event: ReputationEvent) {
        let delta = match event {
            ReputationEvent::SuccessfulLogin    => +10,
            ReputationEvent::HourWithoutIssues  => +5,
            ReputationEvent::RateLimitHit       => -20,
            ReputationEvent::InvalidPacket      => -30,
            ReputationEvent::BotChallengeFailed => -50,
            ReputationEvent::BotChallengePass   => +15,
        };
        self.score = (self.score + delta).clamp(-100, 100);
    }

    pub fn get_rate_multiplier(&self) -> f64 {
        match self.score {
            s if s >= 80  => 2.0,   // доверенный - больше лимит
            s if s >= 0   => 1.0,   // нормальный
            s if s >= -30 => 0.5,   // подозрительный
            s if s >= -60 => 0.2,   // проблемный
            _             => 0.05,  // почти в бане
        }
    }
}
```

---

## Bloom Filter для блэклиста

```rust
// Для очень больших блэклистов (миллионы IP)
// Bloom filter: 1% false positive, но 100x меньше памяти

// HashSet<u32> на 1M IP: ~32 MB
// Bloom filter на 1M IP:  ~2 MB при p=0.01

use bloomfilter::Bloom;

pub struct FastBlacklist {
    bloom: Bloom<u32>,       // быстрая предпроверка (может дать false positive)
    exact: DashMap<u32, BanEntry>, // точная проверка (только если bloom сказал "да")
}

impl FastBlacklist {
    pub fn is_blocked(&self, ip: u32) -> bool {
        // Если bloom говорит "нет" - точно не в блэклисте (нет false negative)
        if !self.bloom.check(&ip) { return false; }
        // Bloom говорит "возможно да" - проверяем точно
        self.exact.contains_key(&ip)
    }
}
```

---

## VPN / Proxy детекция

```rust
pub struct VpnDetector {
    // MaxMind GeoLite2-ASN + список известных VPN/proxy ASN
    asn_reader: maxminddb::Reader<Vec<u8>>,
    vpn_asns: HashSet<u32>,
    datacenter_keywords: Vec<Regex>,
}

impl VpnDetector {
    pub fn classify(&self, ip: IpAddr) -> IpCategory {
        let Ok(record) = self.asn_reader.lookup::<Asn>(ip) else {
            return IpCategory::Unknown;
        };

        if let Some(asn) = record.autonomous_system_number {
            if self.vpn_asns.contains(&asn) {
                return IpCategory::VPN;
            }
        }

        if let Some(org) = record.autonomous_system_organization {
            if self.datacenter_keywords.iter().any(|r| r.is_match(org)) {
                return IpCategory::Datacenter;
            }
        }

        IpCategory::Residential
    }
}
```

> Список VPN ASN: https://github.com/X4BNet/lists_vpn (обновляется еженедельно)  
> MaxMind GeoLite2-ASN: бесплатно при регистрации на maxmind.com
