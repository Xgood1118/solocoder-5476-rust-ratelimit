use super::{AlgorithmConfig, RateLimitResult, RateLimiter};
use dashmap::DashMap;
use std::time::Duration;

const SLOT_MS: u64 = 100;

pub struct SlidingWindowRateLimiter {
    config: AlgorithmConfig,
    slots: DashMap<String, RingBuffer>,
}

struct RingBuffer {
    counts: Vec<u64>,
    last_slot: u64,
    total_count: u64,
    size: usize,
}

impl RingBuffer {
    fn new(size: usize) -> Self {
        Self {
            counts: vec![0; size],
            last_slot: 0,
            total_count: 0,
            size,
        }
    }

    fn advance(&mut self, now_ms: u64) {
        let now_slot = now_ms / SLOT_MS;

        if self.last_slot == 0 {
            self.last_slot = now_slot;
            return;
        }

        let elapsed = now_slot.saturating_sub(self.last_slot);

        if elapsed == 0 {
            return;
        }

        let size_u64 = self.size as u64;

        if elapsed >= size_u64 {
            self.counts.iter_mut().for_each(|c| *c = 0);
            self.total_count = 0;
            self.last_slot = now_slot;
            return;
        }

        for i in 1..=elapsed {
            let slot_idx = ((self.last_slot + i) % size_u64) as usize;
            self.total_count = self.total_count.saturating_sub(self.counts[slot_idx]);
            self.counts[slot_idx] = 0;
        }

        self.last_slot = now_slot;
    }

    fn add(&mut self, count: u64, now_ms: u64) {
        self.advance(now_ms);
        let slot_idx = (self.last_slot % (self.size as u64)) as usize;
        self.counts[slot_idx] += count;
        self.total_count += count;
    }

    fn get_total(&mut self, now_ms: u64) -> u64 {
        self.advance(now_ms);
        self.total_count
    }
}

impl SlidingWindowRateLimiter {
    pub fn new(config: AlgorithmConfig) -> Self {
        let window_ms = config.window_size.as_millis() as u64;
        let _slot_count = (window_ms / SLOT_MS).max(1) as usize;

        Self {
            config,
            slots: DashMap::new(),
        }
    }

    fn slot_count(&self) -> usize {
        let window_ms = self.config.window_size.as_millis() as u64;
        (window_ms / SLOT_MS).max(1) as usize
    }

    fn get_reset_at(&self, now_ms: u64) -> u64 {
        let window_ms = self.config.window_size.as_millis() as u64;
        let current_slot_start = (now_ms / SLOT_MS) * SLOT_MS;
        current_slot_start + window_ms
    }
}

impl RateLimiter for SlidingWindowRateLimiter {
    fn check(&self, key: &str, count: u64, now_ms: u64) -> RateLimitResult {
        let reset_at = self.get_reset_at(now_ms);
        let slot_count = self.slot_count();

        let mut ring = self
            .slots
            .entry(key.to_string())
            .or_insert_with(|| RingBuffer::new(slot_count));

        let current_total = ring.get_total(now_ms);

        if current_total + count <= self.config.limit {
            ring.add(count, now_ms);
            let remaining = self.config.limit - (current_total + count);
            RateLimitResult {
                allowed: true,
                remaining,
                reset_at,
                retry_after: None,
            }
        } else {
            let retry_after_ms = reset_at.saturating_sub(now_ms);
            RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at,
                retry_after: Some(Duration::from_millis(retry_after_ms.max(SLOT_MS))),
            }
        }
    }

    fn peek(&self, key: &str, now_ms: u64) -> RateLimitResult {
        let reset_at = self.get_reset_at(now_ms);
        let _slot_count = self.slot_count();

        let current_total = self
            .slots
            .get_mut(key)
            .map(|mut r| r.get_total(now_ms))
            .unwrap_or(0);

        let allowed = current_total < self.config.limit;
        let remaining = self.config.limit.saturating_sub(current_total);

        RateLimitResult {
            allowed,
            remaining,
            reset_at,
            retry_after: if allowed {
                None
            } else {
                Some(Duration::from_millis(reset_at.saturating_sub(now_ms).max(SLOT_MS)))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_sliding_window_basic() {
        let config = AlgorithmConfig::sliding_window(10, Duration::from_secs(1));
        let limiter = SlidingWindowRateLimiter::new(config);
        let now = 1000000;

        for i in 0..10 {
            let result = limiter.check("test", 1, now + i * 50);
            assert!(result.allowed, "request {} should be allowed", i);
        }

        let result = limiter.check("test", 1, now + 500);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[test]
    fn test_sliding_window_rollover() {
        let config = AlgorithmConfig::sliding_window(10, Duration::from_secs(1));
        let limiter = SlidingWindowRateLimiter::new(config);
        let now = 1000000;

        for i in 0..10 {
            limiter.check("test", 1, now + i * 50);
        }

        let result = limiter.check("test", 1, now + 1500);
        assert!(result.allowed);
    }
}
