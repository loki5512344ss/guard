use rand::RngCore;
use std::time::Instant;

pub struct Challenge {
    pub token: [u8; 32],
    pub created_at: Instant,
    pub difficulty: u8,
    pub used: bool,
}

impl Challenge {
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

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= 30
    }

    pub fn challenge_string(&self) -> String {
        hex::encode(self.token)
    }
}
