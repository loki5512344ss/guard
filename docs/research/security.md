# Security - STRIDE, mTLS, Zero Trust, Supply Chain

> Актуально: v0.2+

---

## STRIDE Threat Model

| Угроза | Конкретно | Защита |
|---|---|---|
| **S**poofing | Атакующий подделывает IP edge ноды | mTLS (сертификат не подделать) + WireGuard |
| **T**ampering | Подмена HMAC в hostname | HMAC-SHA256 + constant-time compare |
| **R**epudiation | Нет доказательств кто добавил IP в блэклист | Аудит лог (user, ts, action, IP) в ClickHouse |
| **I**nfo Disclosure | Утечка реального IP backend | Всё за WireGuard + iptables DROP |
| **D**oS | Перегрузка edge ноды | XDP + rate limit + challenge |
| **E**scalation | Доступ к Manager API без авторизации | JWT + mTLS + IP whitelist + rate limit |

---

## Zero Trust - принципы

```
1. Никому не доверяй по умолчанию - даже внутри WireGuard сети
2. Проверяй каждый компонент - mTLS между всеми сервисами
3. Минимальные привилегии - каждый компонент видит только нужное
4. Логируй всё - аудит лог каждого действия

Применение в Rampart:
  Edge нода → HAProxy/LB:  mTLS (сертификат edge ноды)
  LB → Velocity:           mTLS (сертификат LB)
  Velocity → Redis:        пароль + только WireGuard IP
  Manager API:             JWT + mTLS + IP whitelist
```

---

## mTLS - схема сертификатов

```
Root CA (rampart-ca)
  ├── Intermediate CA (edge-ca)
  │     ├── edge-eu-1.crt
  │     ├── edge-us-1.crt
  │     └── edge-as-1.crt
  ├── Intermediate CA (infra-ca)
  │     ├── haproxy.crt
  │     ├── velocity-1.crt ... velocity-20.crt
  │     ├── manager.crt
  │     └── dashboard.crt
  └── Intermediate CA (game-ca)
        ├── hub-1.crt ... hub-100.crt
        └── (game серверам не нужен mTLS - они за Velocity)
```

### Генерация через CLI

```bash
# Инициализация PKI (один раз)
rampart pki init \
  --root-ca rampart-ca \
  --output /etc/rampart/pki/

# Выпуск сертификата для новой edge ноды
rampart pki issue \
  --ca edge-ca \
  --name edge-us-2 \
  --ip 10.0.100.5 \
  --san "edge-us-2.rampart.internal" \
  --output /etc/rampart/pki/edge-us-2/

# Ротация (раз в год, автоматически через cron)
rampart pki rotate --role edge --days-before-expiry 30
```

### Реализация в Rust (rustls)

```rust
// tls.rs

use rustls::{ServerConfig, ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub fn server_config(cert: &str, key: &str, ca: &str) -> Arc<ServerConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add(load_cert(ca)).unwrap();

    Arc::new(ServerConfig::builder()
        // Требуем клиентский сертификат (mutual)
        .with_client_cert_verifier(
            WebPkiClientVerifier::builder(Arc::new(root_store))
                .build().unwrap()
        )
        .with_single_cert(load_certs(cert), load_key(key))
        .unwrap())
}

pub fn client_config(cert: &str, key: &str, ca: &str) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add(load_cert(ca)).unwrap();

    Arc::new(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(load_certs(cert), load_key(key))
        .unwrap())
}
```

---

## HMAC - правильная реализация

```rust
// hmac/signer.rs

use hmac::{Hmac, Mac};
use sha2::Sha256;
// ВАЖНО: subtle для constant-time сравнения (защита от timing атак)
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(hostname: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(hostname.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify(hostname: &str, provided_sig: &str, secret: &[u8]) -> bool {
    let expected = sign(hostname, secret);
    // constant_time_eq - время сравнения не зависит от содержимого
    // Без этого атакующий может угадать HMAC по времени ответа
    expected.as_bytes().ct_eq(provided_sig.as_bytes()).into()
}

// Добавляем к hostname: "play.server.com\0shield\0<hex_hmac>"
pub fn sign_hostname(raw: &str, secret: &[u8]) -> String {
    // Берём только domain часть (без Forge суффиксов)
    let domain = raw.split('\0').next().unwrap_or(raw);
    let sig = sign(domain, secret);
    format!("{}\0shield\0{}", raw, sig)  // сохраняем Forge суффикс
}
```

---

## Аудит лог

```rust
// Каждое административное действие записывается

#[derive(Serialize, Deserialize, Clickhouse)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    pub user: String,       // кто сделал
    pub action: String,     // "blacklist.add" / "server.remove" / "config.change"
    pub target: String,     // "1.2.3.4" / "survival_47"
    pub details: String,    // JSON с деталями
    pub src_ip: String,     // откуда был запрос
    pub success: bool,
}

// Вставляем в ClickHouse (не в Redis - нужна долгосрочная история)
pub async fn audit(entry: AuditEntry) {
    clickhouse_client
        .insert("rampart.audit_log")
        .write(&entry)
        .await
        .ok(); // не прерываем основной флоу если аудит упал
}
```

---

## Защита Redis

```bash
# redis.conf
bind 10.0.0.1            # только WireGuard IP (не 0.0.0.0!)
requirepass "LONG_RANDOM_PASSWORD_HERE"
protected-mode yes
rename-command FLUSHALL ""   # запрещаем опасные команды
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_RESTRICTED_CMD"

# Firewall - дополнительный слой
iptables -A INPUT -p tcp --dport 6379 -s 10.0.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP
```

---

## Supply Chain Security (v0.5+)

```yaml
# .github/workflows/supply-chain.yml

  cargo-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install cargo-audit
      - run: cargo audit              # проверяем CVE в зависимостях

  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - uses: EmbarkStudios/cargo-deny-action@v1
        with:
          command: check all          # лицензии, дублирования, CVE

  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: anchore/sbom-action@v0  # генерируем SBOM
        with:
          format: spdx-json

  sign-release:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            ghcr.io/yourname/rampart-core:${{ github.sha }}
```

### Совместимость лицензий

```
Наш код: MIT или Apache-2.0

Ключевые зависимости:
  tokio:      MIT ✅
  rustls:     MIT/Apache ✅
  libbpf-rs:  LGPL-2.1 ✅ (динамическая линковка)
  libbpf-sys: LGPL-2.1 ✅
  XDP C код:  GPL-2.0 ✅ (kernel module, отдельная сборка)

Потенциальная проблема:
  XDP .c файлы компилируются в eBPF bytecode и загружаются в ядро.
  Сам .c файл под GPL - это нормально для kernel interaction.
  Rust loader (userspace) - MIT, не загрязняется GPL.
```

---

## Утечка реального IP - чеклист

```
☐ DNS история очищена (проверь через SecurityTrails, Shodan)
☐ Reverse DNS не раскрывает хостинг
☐ Старые firewall правила удалены
☐ game серверы не пингуют внешние ресурсы со своего IP
  (обновления плагинов, curl запросы - через proxy или не извне)
☐ Email заголовки (если сервер шлёт письма) - проверить что не раскрывают IP
☐ Error pages, краш репорты - не выводить IP
☐ MC команды типа /ip - отключить или ограничить
☐ Доступ членов команды - минимальный, только нужные люди знают IP
☐ Pterodactyl/панель управления - закрыта за VPN или IP whitelist
```
