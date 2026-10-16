use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Caps simultaneous in-flight connections per source IP.
pub struct ConnectionLimiter {
    counts: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
    limit: usize,
}

impl ConnectionLimiter {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            counts: Arc::new(DashMap::new()),
            limit: limit.max(1),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        let entry = self.counts.entry(ip).or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        let count = Arc::clone(entry.value());
        let current = count.fetch_add(1, Ordering::AcqRel);
        drop(entry);
        if current >= self.limit {
            count.fetch_sub(1, Ordering::AcqRel);
            self.remove_if_idle(ip, &count);
            return None;
        }
        Some(ConnectionPermit {
            ip,
            count,
            counts: Arc::clone(&self.counts),
        })
    }

    fn remove_if_idle(&self, ip: IpAddr, count: &Arc<AtomicUsize>) {
        self.counts.remove_if(&ip, |_, current| {
            Arc::ptr_eq(current, count) && current.load(Ordering::Acquire) == 0
        });
    }
}

pub struct ConnectionPermit {
    ip: IpAddr,
    count: Arc<AtomicUsize>,
    counts: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.counts.remove_if(&self.ip, |_, current| {
                Arc::ptr_eq(current, &self.count) && current.load(Ordering::Acquire) == 0
            });
        }
    }
}
