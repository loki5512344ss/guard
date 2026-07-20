# Minecraft Protocol - Парсинг, VarInt, Fingerprinting

> Актуально: v0.1+  
> Основа всей фильтрации - знание протокола.

---

## Handshake пакет (0x00) - структура

```
┌──────────────────────────────────────────────────────┐
│ VarInt  │ Packet Length                              │
├──────────────────────────────────────────────────────┤
│ VarInt  │ Packet ID = 0x00                           │
├──────────────────────────────────────────────────────┤
│ VarInt  │ Protocol Version                           │
│         │  765 = 1.20.4, 769 = 1.21.4, 766 = 26.1  │
├──────────────────────────────────────────────────────┤
│ String  │ Server Address (hostname)                  │
│         │  VarInt (length) + UTF-8 bytes             │
├──────────────────────────────────────────────────────┤
│ UShort  │ Server Port (big-endian, 2 bytes)          │
├──────────────────────────────────────────────────────┤
│ VarInt  │ Next State: 1 = Status, 2 = Login         │
└──────────────────────────────────────────────────────┘
```

---

## VarInt - строгий парсер с bounds check

```rust
// minecraft/varint.rs

#[derive(Debug)]
pub enum VarIntError {
    Incomplete,      // данных меньше чем нужно
    TooBig,          // VarInt > 5 байт (не по спецификации)
    Overflow,        // значение выходит за i32
}

pub fn read_varint(buf: &[u8], start: usize) -> Result<(i32, usize), VarIntError> {
    let mut value: i32 = 0;
    let mut shift = 0;

    for (i, &byte) in buf[start..].iter().enumerate() {
        if i >= 5 {
            // MC VarInt максимум 5 байт - всё что больше: атака
            return Err(VarIntError::TooBig);
        }

        let segment = (byte & 0x7F) as i32;

        // Проверяем overflow до сдвига
        if shift >= 32 || (shift == 28 && segment > 0x0F) {
            return Err(VarIntError::Overflow);
        }

        value |= segment << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            return Ok((value, start + i + 1));
        }
    }

    Err(VarIntError::Incomplete)
}

// VarString = VarInt (length) + UTF-8 bytes
pub fn read_string(buf: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let (len, after_len) = read_varint(buf, start)?;

    if len < 0 || len > 32767 {
        return Err(ParseError::StringTooLong);
    }

    let end = after_len + len as usize;
    if end > buf.len() {
        return Err(ParseError::Incomplete);
    }

    let s = std::str::from_utf8(&buf[after_len..end])
        .map_err(|_| ParseError::InvalidUtf8)?
        .to_string();

    Ok((s, end))
}
```

---

## Полный парсер handshake

```rust
// minecraft/handshake.rs

#[derive(Debug)]
pub struct McHandshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: NextState,
}

#[derive(Debug, PartialEq)]
pub enum NextState {
    Status,  // 1 - ping
    Login,   // 2 - игрок заходит
    Unknown(i32),
}

impl McHandshake {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let mut pos = 0;

        // Packet length (игнорируем значение, просто двигаемся дальше)
        let (_, after_len) = read_varint(buf, pos)?;
        pos = after_len;

        // Packet ID - должен быть 0x00
        let (packet_id, after_id) = read_varint(buf, pos)?;
        pos = after_id;
        if packet_id != 0x00 {
            return Err(ParseError::NotHandshake(packet_id));
        }

        // Protocol version (не валидируем - не хардкодим версии)
        let (protocol_version, after_pv) = read_varint(buf, pos)?;
        pos = after_pv;

        // Server address
        let (server_address, after_addr) = read_string(buf, pos)?;
        pos = after_addr;

        // Защита от слишком длинного hostname
        if server_address.len() > 255 {
            return Err(ParseError::HostnameTooLong);
        }

        // Server port (big-endian u16)
        if pos + 2 > buf.len() {
            return Err(ParseError::Incomplete);
        }
        let server_port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        // Next state
        let (next_state_raw, _) = read_varint(buf, pos)?;
        let next_state = match next_state_raw {
            1 => NextState::Status,
            2 => NextState::Login,
            n => NextState::Unknown(n),
        };

        Ok(McHandshake {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }

    pub fn is_login(&self) -> bool {
        self.next_state == NextState::Login
    }
}
```

---

## Hostname суффиксы - Forge, FabricProxy, HMAC

```
Обычный клиент:     "play.server.com"
Forge (старый):     "play.server.com\0FML\0"
NeoForge/Forge:     "play.server.com\0FML2\0"
FabricProxy-Lite:   "play.server.com\0" + base64(data)
Наш HMAC:           "play.server.com\0shield\0<hex_hmac>"

Комбинации:
Forge + HMAC:       "play.server.com\0FML2\0\0shield\0<hex_hmac>"
```

### Правильный порядок разбора

```rust
// ВАЖНО: сначала убираем FML суффикс, потом проверяем HMAC
// Если делать наоборот - HMAC подпись не совпадёт

pub struct ParsedHostname {
    pub domain: String,           // "play.server.com"
    pub forge_marker: Option<String>, // "FML2" если Forge
    pub hmac: Option<String>,     // hex HMAC если прошли через edge
}

pub fn parse_hostname(raw: &str) -> ParsedHostname {
    let parts: Vec<&str> = raw.split('\0').collect();

    // Ищем "shield" среди частей
    let shield_pos = parts.iter().position(|&p| p == "shield");

    // Forge маркер - обычно вторая часть
    let forge_marker = parts.get(1)
        .filter(|&&p| p == "FML" || p == "FML2" || p == "FML3")
        .map(|&s| s.to_string());

    ParsedHostname {
        domain: parts[0].to_string(),
        forge_marker,
        hmac: shield_pos.and_then(|i| parts.get(i + 1)).map(|s| s.to_string()),
    }
}
```

---

## Client Fingerprinting

### По handshake

```rust
pub enum ClientType {
    Vanilla,
    NeoForge,    // \0FML2\0
    Forge,       // \0FML\0
    FabricProxy, // специфичный base64 суффикс
    Bot,         // подозрительные паттерны
    Unknown,
}

pub fn fingerprint_from_handshake(h: &McHandshake) -> ClientType {
    let addr = &h.server_address;

    if addr.contains("\0FML2\0") { return ClientType::NeoForge; }
    if addr.contains("\0FML\0")  { return ClientType::Forge; }

    // Очень старый или нестандартный protocol_version
    if h.protocol_version < 47 || h.protocol_version > 10000 {
        return ClientType::Bot;
    }

    ClientType::Unknown
}
```

### По plugin channels (после Login)

```rust
// Lunar, Badlion, Feather регистрируют свои каналы через
// LoginPluginRequest / PluginChannels пакет

pub fn fingerprint_from_channels(channels: &[String]) -> Option<ClientType> {
    for ch in channels {
        if ch.starts_with("lunarclient:")  { return Some(ClientType::LunarClient); }
        if ch.starts_with("badlion:")     { return Some(ClientType::BadlionClient); }
        if ch.starts_with("feather:")     { return Some(ClientType::FeatherClient); }
        if ch.starts_with("pvplounge:")   { return Some(ClientType::PvPLounge); }
    }
    None
}
```

---

## Важные нюансы протокола

```
1. Один TCP коннект = один игрок. MC не мультиплексирует.

2. После Handshake(next_state=2) → LoginStart пакет
   Если LoginStart не пришёл за 5 сек → это бот. DROP.

3. Protocol version не хардкодить.
   Mojang с 2025 использует новую схему (26.1, 26.2...).
   Принимаем любой валидный VarInt в диапазоне 0..10000.

4. Hostname может прийти TCP-фрагментированным (несколько сегментов).
   Парсер должен уметь работать с неполными данными - читать пока
   не получим полный пакет или timeout.

5. Status ping (next_state=1) - не требует авторизации.
   Боты часто используют для разведки (онлайн, версия сервера).
   Rate limit status отдельно от login.

6. MC 1.20.2+ использует Configuration phase между Login и Play.
   Velocity обрабатывает автоматически - нам не важно для edge.
```

---

## Совместимость версий (июль 2026)

| Версия MC | Protocol version | Схема |
|---|---|---|
| 1.20.4 | 765 | Старая |
| 1.21.1 | 767 | Старая |
| 1.21.4 | 769 | Старая |
| 26.1   | 8xx | Новая (Mojang) |
| 26.2   | 8xx | Новая (Mojang) |

Velocity 3.4+ поддерживает обе схемы прозрачно.  
Sonar 3.x поддерживает 1.8 - 26.2.
