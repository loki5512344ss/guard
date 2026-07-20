use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(hostname: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(hostname.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify(hostname: &str, provided_sig: &str, secret: &[u8]) -> bool {
    let expected = sign(hostname, secret);
    expected.as_bytes().ct_eq(provided_sig.as_bytes()).into()
}

pub fn sign_hostname(raw: &str, secret: &[u8]) -> String {
    let domain = raw.split('\0').next().unwrap_or(raw);
    let sig = sign(domain, secret);
    format!("{raw}\0shield\0{sig}")
}

pub fn parse_hostname(raw: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = raw.split('\0').collect();
    let domain = parts[0].to_string();
    let hmac = parts
        .iter()
        .position(|&p| p == "shield")
        .and_then(|i| parts.get(i + 1))
        .map(|s| s.to_string());
    (domain, hmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let secret = b"test_secret_32_bytes_long_here!!";
        let hostname = "play.example.com";
        let sig = sign(hostname, secret);
        assert!(verify(hostname, &sig, secret));
    }

    #[test]
    fn test_verify_wrong_secret() {
        let secret = b"test_secret_32_bytes_long_here!!";
        let wrong = b"wrong_secret_32_bytes_long_here!!!";
        let hostname = "play.example.com";
        let sig = sign(hostname, wrong);
        assert!(!verify(hostname, &sig, secret));
    }

    #[test]
    fn test_sign_hostname_suffix() {
        let secret = b"test_secret";
        let result = sign_hostname("play.example.com", secret);
        assert!(result.starts_with("play.example.com\0shield\0"));
        let sig = result.split("\0shield\0").nth(1).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_verify_constant_time() {
        let secret = b"test_secret_32_bytes_long_here!!";
        let hostname = "play.example.com";
        let sig = sign(hostname, secret);
        assert!(!verify("play.example.co", &sig, secret));
        assert!(verify(hostname, &sig, secret));
    }
}
