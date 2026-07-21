use sha2::{Digest, Sha256};

const ALLOWED: &[u8] = b"0123";

pub fn solve(challenge: &str, difficulty: u8) -> Option<String> {
    let d = difficulty as usize;
    for nonce in 0..u64::MAX {
        let nonce_str = nonce.to_string();
        let input = format!("{challenge}{nonce_str}");
        let hash = Sha256::digest(input.as_bytes());
        let hex_hash = hex::encode(hash);
        if hex_hash.as_bytes().iter().take(d).all(|c| ALLOWED.contains(c)) {
            return Some(nonce_str);
        }
    }
    None
}
