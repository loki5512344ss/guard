//! Универсальный SHA-256 hashcash: генерация challenge, решатель,
//! верификатор и адаптивная сложность.

use crate::metrics;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CHALLENGE_TTL_SECS: u64 = 30;
const MAX_NONCE_LEN: usize = 64;
const ALLOWED_HEX_PREFIX: [u8; 4] = *b"0123";

/// Активная PoW-задача, выданная одному соединению.
pub struct Challenge {
    token: [u8; 32],
    created_at: Instant,
    difficulty: u8,
    used: bool,
}

impl Challenge {
    #[must_use]
    pub fn generate(difficulty: u8) -> Self {
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        Self {
            token,
            created_at: Instant::now(),
            difficulty,
            used: false,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= CHALLENGE_TTL_SECS
    }

    #[must_use]
    pub fn challenge_string(&self) -> String {
        hex::encode(self.token)
    }

    /// Проверяет nonce и помечает challenge использованным при успехе.
    #[must_use]
    pub fn verify(&mut self, nonce: &str) -> bool {
        if self.used || self.is_expired() || nonce.len() > MAX_NONCE_LEN {
            return false;
        }

        let input = format!("{}{nonce}", self.challenge_string());
        let hash = Sha256::digest(input.as_bytes());
        let hex_hash = hex::encode(hash);
        let d = self.difficulty as usize;
        let ok = hex_hash.as_bytes().iter().take(d).all(|c| {
            let r = c.ct_eq(&ALLOWED_HEX_PREFIX[0])
                | c.ct_eq(&ALLOWED_HEX_PREFIX[1])
                | c.ct_eq(&ALLOWED_HEX_PREFIX[2])
                | c.ct_eq(&ALLOWED_HEX_PREFIX[3]);
            r.unwrap_u8() == 1
        });
        if ok {
            self.used = true;
        }
        ok
    }
}

/// Переборный решатель hashcash (для клиентов и тестов).
#[must_use]
pub fn solve(challenge: &str, difficulty: u8) -> Option<String> {
    let d = difficulty as usize;
    for nonce in 0..u64::MAX {
        let nonce_str = nonce.to_string();
        let input = format!("{challenge}{nonce_str}");
        let hash = Sha256::digest(input.as_bytes());
        let hex_hash = hex::encode(hash);
        if hex_hash
            .as_bytes()
            .iter()
            .take(d)
            .all(|c| ALLOWED_HEX_PREFIX.contains(c))
        {
            return Some(nonce_str);
        }
    }
    None
}

/// Адаптирует сложность PoW к текущему темпу подключений.
pub struct DifficultyAdjuster {
    window: VecDeque<Instant>,
    min: u8,
    max: u8,
    current: u8,
}

impl Default for DifficultyAdjuster {
    fn default() -> Self {
        Self::new(4, 10)
    }
}

impl DifficultyAdjuster {
    #[must_use]
    pub fn new(min: u8, max: u8) -> Self {
        Self {
            window: VecDeque::new(),
            min: min.max(4),
            max: max.min(10),
            current: min.max(4),
        }
    }

    pub fn record_connection(&mut self) {
        let now = Instant::now();
        self.window.push_back(now);
        while let Some(&t) = self.window.front() {
            if now.duration_since(t).as_secs() >= 1 {
                self.window.pop_front();
            } else {
                break;
            }
        }
        let new_diff = self.compute_difficulty();
        if self.current != new_diff {
            tracing::info!(
                old = self.current,
                new = new_diff,
                window = self.window.len(),
                "pow: difficulty adjusted"
            );
            self.current = new_diff;
            metrics::POW_CURRENT_DIFFICULTY.set(self.current as i64);
        }
    }

    #[must_use]
    pub fn current_difficulty(&self) -> u8 {
        metrics::POW_CURRENT_DIFFICULTY.set(self.current as i64);
        self.current
    }

    fn compute_difficulty(&self) -> u8 {
        match self.window.len() {
            cps if cps > 500 => self.max.max(self.min),
            cps if cps > 200 => 8,
            cps if cps > 50 => 6,
            _ => self.min,
        }
    }
}

/// Проводит текстовый PoW-gate в потоке: выдаёт challenge и проверяет ответ.
///
/// # Errors
/// Возвращает ошибку только при сбое ввода-вывода; неверное решение — `Ok(false)`.
pub async fn enforce(stream: &mut TcpStream, peer_ip: IpAddr, difficulty: u8) -> anyhow::Result<bool> {
    if difficulty == 0 {
        tracing::debug!("pow: difficulty 0, skipping for {peer_ip}");
        return Ok(true);
    }

    let mut challenge = Challenge::generate(difficulty);
    let line = format!("{}\n", challenge.challenge_string());
    stream.write_all(line.as_bytes()).await?;

    let mut buf = [0u8; MAX_NONCE_LEN + 1];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await??;
    if n == 0 {
        tracing::debug!("pow: no response from {peer_ip}");
        return Ok(false);
    }

    let nonce = std::str::from_utf8(&buf[..n.min(MAX_NONCE_LEN)]).unwrap_or("").trim();
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
        tracing::debug!("pow: invalid nonce from {peer_ip}");
        return Ok(false);
    }

    let valid = challenge.verify(nonce);
    tracing::debug!(
        "pow: verification {} for {peer_ip}",
        if valid { "passed" } else { "failed" }
    );
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify_roundtrip() {
        let mut challenge = Challenge::generate(2);
        let nonce = solve(&challenge.challenge_string(), 2).expect("solver should find a nonce");
        assert!(challenge.verify(&nonce), "verifier must accept solver output");
    }

    #[test]
    fn verify_rejects_wrong_nonce() {
        let mut challenge = Challenge::generate(4);
        let challenge_str = challenge.challenge_string();

        // Подбираем nonce, который независимо рассчитанный SHA-256
        // заведомо отклоняет — тест детерминирован.
        let mut wrong_nonce = None;
        for i in 0..10_000u32 {
            let candidate = format!("bad-{i}");
            let hex_hash = hex::encode(Sha256::digest(format!("{challenge_str}{candidate}").as_bytes()));
            if !hex_hash
                .as_bytes()
                .iter()
                .take(4)
                .all(|c| ALLOWED_HEX_PREFIX.contains(c))
            {
                wrong_nonce = Some(candidate);
                break;
            }
        }
        let wrong_nonce = wrong_nonce.expect("a failing nonce must exist among candidates");
        assert!(!challenge.verify(&wrong_nonce));
    }

    #[test]
    fn verify_rejects_replay() {
        let mut challenge = Challenge::generate(2);
        let nonce = solve(&challenge.challenge_string(), 2).expect("solved");
        assert!(challenge.verify(&nonce));
        assert!(!challenge.verify(&nonce), "challenge must be single-use");
    }

    #[test]
    fn verify_rejects_oversized_nonce() {
        let mut challenge = Challenge::generate(2);
        let big_nonce = "0".repeat(MAX_NONCE_LEN + 1);
        assert!(!challenge.verify(&big_nonce));
    }

    #[test]
    fn adjuster_raises_difficulty_under_load() {
        let mut adjuster = DifficultyAdjuster::new(4, 10);
        for _ in 0..600 {
            adjuster.record_connection();
        }
        assert_eq!(adjuster.current_difficulty(), 10);
    }

    #[test]
    fn adjuster_stays_minimal_when_idle() {
        let mut adjuster = DifficultyAdjuster::new(4, 10);
        adjuster.record_connection();
        assert_eq!(adjuster.current_difficulty(), 4);
    }
}
