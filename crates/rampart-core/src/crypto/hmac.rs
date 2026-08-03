use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn derive_key(secret: &[u8], bucket: u64) -> Vec<u8> {
    let msg = format!("rampart-key-{bucket}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Подписывает hostname-поле: `domain\0shield\0<ts>\0<sig>`.
///
/// `sig` = HMAC-SHA256(derived_key, "domain|ts"), где
/// `derived_key` = HMAC-SHA256(master_secret, "rampart-key-{bucket}"), bucket = ts / rotation_secs.
pub fn sign_hostname(raw: &str, secret: &[u8], rotation_secs: u64) -> String {
    let rotation_secs = rotation_secs.max(1);
    let domain = raw.split('\0').next().unwrap_or(raw);
    let ts = now_secs();
    let bucket = ts / rotation_secs;
    let key = derive_key(secret, bucket);
    let sig = hmac_hex(&key, format!("{domain}|{ts}").as_bytes());
    format!("{domain}\0shield\0{ts}\0{sig}")
}

/// Проверяет подпись hostname-поля по спецификации.
///
/// Парсит `domain\0shield\0<ts>\0<sig>`, проверяет `0 <= now - ts <= ttl_secs` и
/// сравнивает сигнатуру constant-time для bucket из `{ts_bucket, ts_bucket - 1}`.
pub fn verify_hostname(raw: &str, secret: &[u8], rotation_secs: u64, ttl_secs: u64) -> bool {
    let rotation_secs = rotation_secs.max(1);
    let mut parts = raw.split('\0');
    let (Some(domain), Some(tag), Some(ts_str), Some(sig)) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if tag != "shield" || parts.next().is_some() {
        return false;
    }
    let ts: u64 = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = now_secs();
    if now < ts || now - ts > ttl_secs {
        return false;
    }
    if sig.len() != 64 {
        return false;
    }
    let bucket = ts / rotation_secs;
    for candidate in [bucket, bucket.saturating_sub(1)] {
        let key = derive_key(secret, candidate);
        let expected = hmac_hex(&key, format!("{domain}|{ts}").as_bytes());
        if expected.as_bytes().ct_eq(sig.as_bytes()).into() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test_secret_32_bytes_long_here!!";

    fn build_signed(secret: &[u8], domain: &str, ts: u64, rotation_secs: u64) -> String {
        let bucket = ts / rotation_secs.max(1);
        let key = derive_key(secret, bucket);
        let sig = hmac_hex(&key, format!("{domain}|{ts}").as_bytes());
        format!("{domain}\0shield\0{ts}\0{sig}")
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signed = sign_hostname("play.example.com", SECRET, 3600);
        assert!(verify_hostname(&signed, SECRET, 3600, 60));
    }

    #[test]
    fn test_sign_format() {
        let signed = sign_hostname("play.example.com\0ignored", SECRET, 3600);
        let parts: Vec<&str> = signed.split('\0').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "play.example.com");
        assert_eq!(parts[1], "shield");
        assert_eq!(parts[3].len(), 64);
        assert!(parts[3].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_tampered_domain() {
        let signed = sign_hostname("play.example.com", SECRET, 3600);
        let tampered = signed.replace("play.example.com", "play.example.co");
        assert!(!verify_hostname(&tampered, SECRET, 3600, 60));
    }

    #[test]
    fn test_verify_wrong_secret() {
        let signed = sign_hostname("play.example.com", SECRET, 3600);
        let wrong = b"wrong_secret_32_bytes_long_here!!!";
        assert!(!verify_hostname(&signed, wrong, 3600, 60));
    }

    #[test]
    fn test_verify_expired_ts() {
        let old_ts = now_secs().saturating_sub(120);
        let signed = build_signed(SECRET, "play.example.com", old_ts, 3600);
        assert!(!verify_hostname(&signed, SECRET, 3600, 60));
    }

    #[test]
    fn test_verify_accepts_previous_bucket() {
        let rotation = 10u64;
        let now = now_secs();
        let prev_bucket_ts = (now / rotation).saturating_sub(1) * rotation + 5;
        let signed = build_signed(SECRET, "play.example.com", prev_bucket_ts, rotation);
        assert!(verify_hostname(&signed, SECRET, rotation, 60));
    }

    #[test]
    fn test_verify_rejects_tampered_ts() {
        let ts = now_secs();
        let signed = build_signed(SECRET, "play.example.com", ts, 3600);
        let parts: Vec<&str> = signed.split('\0').collect();
        let tampered = format!("{}\0{}\0{}\0{}", parts[0], parts[1], ts.saturating_sub(1), parts[3]);
        assert!(!verify_hostname(&tampered, SECRET, 3600, 60));
    }

    #[test]
    fn test_verify_garbage_input() {
        assert!(!verify_hostname("", SECRET, 3600, 60));
        assert!(!verify_hostname("no-separators", SECRET, 3600, 60));
        assert!(!verify_hostname("a\0shield\0bad\0short", SECRET, 3600, 60));
    }
}
