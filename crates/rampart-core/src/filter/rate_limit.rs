use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets: Arc<DashMap<u32, Bucket>>,
    max_tokens: f64,
    refill_rate: f64,
    _refill_interval: Duration,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            max_tokens: burst,
            refill_rate: rate_per_sec,
            _refill_interval: Duration::from_secs(1),
        }
    }

    pub fn check(&self, ip: u32) -> bool {
        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.max_tokens,
            last_refill: Instant::now(),
        });

        let now = Instant::now();
        let elapsed = now.duration_since(entry.last_refill);
        let refill = elapsed.as_secs_f64() * self.refill_rate;
        entry.tokens = (entry.tokens + refill).min(self.max_tokens);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_under() {
        let limiter = RateLimiter::new(10.0, 10.0);
        assert!(limiter.check(1));
    }

    #[test]
    fn test_rate_limit_over() {
        let limiter = RateLimiter::new(1.0, 1.0);
        assert!(limiter.check(1));
        assert!(!limiter.check(1));
    }

    #[test]
    fn test_rate_limit_burst() {
        let limiter = RateLimiter::new(1.0, 5.0);
        for _ in 0..5 {
            assert!(limiter.check(2));
        }
        assert!(!limiter.check(2));
    }

    #[test]
    fn test_rate_limit_refill() {
        let limiter = RateLimiter::new(100.0, 1.0);
        assert!(limiter.check(3));
        assert!(!limiter.check(3));
        std::thread::sleep(Duration::from_millis(20));
        assert!(limiter.check(3));
    }
}
