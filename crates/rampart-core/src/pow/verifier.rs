use crate::pow::challenge::Challenge;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ALLOWED: [u8; 4] = *b"0123";

pub fn verify(challenge: &mut Challenge, nonce: &str) -> bool {
    if challenge.used {
        return false;
    }
    if challenge.is_expired() {
        return false;
    }
    if nonce.len() > 64 {
        return false;
    }

    let input = format!("{}{}", challenge.challenge_string(), nonce);
    let hash = Sha256::digest(input.as_bytes());
    let hex_hash = hex::encode(hash);
    let d = challenge.difficulty as usize;
    let ok = hex_hash.as_bytes().iter().take(d).all(|c| {
        let r = c.ct_eq(&ALLOWED[0]) | c.ct_eq(&ALLOWED[1]) | c.ct_eq(&ALLOWED[2]) | c.ct_eq(&ALLOWED[3]);
        r.unwrap_u8() == 1
    });
    if !ok {
        return false;
    }
    challenge.used = true;
    true
}
