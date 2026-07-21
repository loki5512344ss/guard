use crate::metrics;
use std::collections::VecDeque;
use std::time::Instant;

pub struct DifficultyAdjuster {
    window: VecDeque<Instant>,
    min: u8,
    max: u8,
    current: u8,
}

impl DifficultyAdjuster {
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

    pub fn current_difficulty(&self) -> u8 {
        metrics::POW_CURRENT_DIFFICULTY.set(self.current as i64);
        self.current
    }

    fn compute_difficulty(&self) -> u8 {
        let cps = self.window.len();
        if cps > 500 {
            self.max.max(self.min)
        } else if cps > 200 {
            8
        } else if cps > 50 {
            6
        } else {
            self.min
        }
    }
}

impl Default for DifficultyAdjuster {
    fn default() -> Self {
        Self::new(4, 16)
    }
}
