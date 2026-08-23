use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_BUCKETS: usize = 1_000_000;
const EVICTION_IDLE: Duration = Duration::from_secs(600);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_access: Instant,
}

pub struct RateLimiter {
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    max_tokens: f64,
    refill_rate: f64,
    _refill_interval: Duration,
    epoch: Instant,
    last_sweep_elapsed: AtomicU64,
    eviction_idle: Duration,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self::with_eviction(rate_per_sec, burst, EVICTION_IDLE)
    }

    fn with_eviction(rate_per_sec: f64, burst: f64, eviction_idle: Duration) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            max_tokens: burst,
            refill_rate: rate_per_sec,
            _refill_interval: Duration::from_secs(1),
            epoch: Instant::now(),
            last_sweep_elapsed: AtomicU64::new(0),
            eviction_idle,
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.max_tokens,
            last_refill: now,
            last_access: now,
        });

        let elapsed = now.duration_since(entry.last_refill);
        let refill = elapsed.as_secs_f64() * self.refill_rate;
        entry.tokens = (entry.tokens + refill).min(self.max_tokens);
        entry.last_refill = now;
        entry.last_access = now;

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

    /// Эвиктит простаивающие бакеты. Запускается, когда бакетов больше
    /// MAX_BUCKETS либо по расписанию (раз в SWEEP_INTERVAL).
    pub fn sweep(&self) {
        let now = Instant::now();
        let elapsed_secs = now.duration_since(self.epoch).as_secs();
        let last = self.last_sweep_elapsed.load(Ordering::Relaxed);
        let due = last == 0 || elapsed_secs.saturating_sub(last) >= SWEEP_INTERVAL.as_secs();
        let over_cap = self.buckets.len() > MAX_BUCKETS;
        if !over_cap && !due {
            return;
        }
        self.buckets
            .retain(|_, b| now.duration_since(b.last_access) < self.eviction_idle);
        self.last_sweep_elapsed.store(elapsed_secs, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[test]
    fn test_rate_limit_under() {
        let limiter = RateLimiter::new(10.0, 10.0);
        assert!(limiter.check(test_ip(1)));
    }

    #[test]
    fn test_rate_limit_over() {
        let limiter = RateLimiter::new(1.0, 1.0);
        assert!(limiter.check(test_ip(1)));
        assert!(!limiter.check(test_ip(1)));
    }

    #[test]
    fn test_rate_limit_burst() {
        let limiter = RateLimiter::new(1.0, 5.0);
        for _ in 0..5 {
            assert!(limiter.check(test_ip(2)));
        }
        assert!(!limiter.check(test_ip(2)));
    }

    #[test]
    fn test_rate_limit_refill() {
        let limiter = RateLimiter::new(100.0, 1.0);
        assert!(limiter.check(test_ip(3)));
        assert!(!limiter.check(test_ip(3)));
        std::thread::sleep(Duration::from_millis(20));
        assert!(limiter.check(test_ip(3)));
    }

    #[test]
    fn test_sweep_removes_idle_keeps_active() {
        let limiter = RateLimiter::with_eviction(1.0, 10.0, Duration::from_millis(20));
        limiter.check(test_ip(1));
        limiter.check(test_ip(2));
        std::thread::sleep(Duration::from_millis(50));
        limiter.check(test_ip(2));
        limiter.sweep();
        assert_eq!(limiter.len(), 1);
        assert!(!limiter.buckets.contains_key(&test_ip(1)));
        assert!(limiter.buckets.contains_key(&test_ip(2)));
    }

    #[test]
    fn test_sweep_does_not_remove_active() {
        let limiter = RateLimiter::with_eviction(1.0, 10.0, Duration::from_millis(50));
        limiter.check(test_ip(1));
        limiter.sweep();
        assert_eq!(limiter.len(), 1);
        assert!(limiter.buckets.contains_key(&test_ip(1)));
    }
}
