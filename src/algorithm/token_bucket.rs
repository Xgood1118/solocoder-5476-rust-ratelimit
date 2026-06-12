use super::{AlgorithmConfig, RateLimitResult, RateLimiter};
use dashmap::DashMap;
use std::time::Duration;

pub struct TokenBucketRateLimiter {
    config: AlgorithmConfig,
    buckets: DashMap<String, BucketState>,
    started_at_ms: u64,
}

struct BucketState {
    tokens: f64,
    last_refill_ms: u64,
}

impl TokenBucketRateLimiter {
    pub fn new(config: AlgorithmConfig) -> Self {
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            config,
            buckets: DashMap::new(),
            started_at_ms,
        }
    }

    fn capacity_at(&self, now_ms: u64) -> f64 {
        let capacity = self.config.capacity.unwrap_or(self.config.limit) as f64;
        let rate = self.config.rate.unwrap_or(self.config.limit) as f64;

        if let Some(warmup) = self.config.warmup_period {
            let warmup_ms = warmup.as_millis() as u64;
            let elapsed = now_ms.saturating_sub(self.started_at_ms);

            if elapsed < warmup_ms {
                let progress = elapsed as f64 / warmup_ms as f64;
                let target_rate = rate * progress;
                let target_capacity = capacity * progress;
                let _ = target_rate;
                return target_capacity;
            }
        }

        capacity
    }

    fn rate_at(&self, now_ms: u64) -> f64 {
        let rate = self.config.rate.unwrap_or(self.config.limit) as f64;

        if let Some(warmup) = self.config.warmup_period {
            let warmup_ms = warmup.as_millis() as u64;
            let elapsed = now_ms.saturating_sub(self.started_at_ms);

            if elapsed < warmup_ms {
                let progress = elapsed as f64 / warmup_ms as f64;
                return rate * progress;
            }
        }

        rate
    }

    fn refill(&self, state: &mut BucketState, now_ms: u64) {
        if state.last_refill_ms == 0 {
            state.last_refill_ms = now_ms;
            return;
        }

        let elapsed_ms = now_ms.saturating_sub(state.last_refill_ms);
        if elapsed_ms == 0 {
            return;
        }

        let rate_per_ms = self.rate_at(now_ms) / 1000.0;
        let new_tokens = elapsed_ms as f64 * rate_per_ms;
        let capacity = self.capacity_at(now_ms);

        state.tokens = (state.tokens + new_tokens).min(capacity);
        state.last_refill_ms = now_ms;
    }
}

impl RateLimiter for TokenBucketRateLimiter {
    fn check(&self, key: &str, count: u64, now_ms: u64) -> RateLimitResult {
        let count_f = count as f64;
        let capacity = self.capacity_at(now_ms);

        let mut bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| BucketState {
                tokens: capacity,
                last_refill_ms: now_ms,
            });

        self.refill(&mut bucket, now_ms);

        if bucket.tokens >= count_f {
            bucket.tokens -= count_f;
            let remaining = bucket.tokens.floor() as u64;

            let rate = self.rate_at(now_ms);
            let reset_at = if rate > 0.0 {
                let needed = capacity - bucket.tokens;
                let time_to_full_ms = (needed / rate) * 1000.0;
                now_ms.saturating_add(time_to_full_ms as u64)
            } else {
                u64::MAX
            };

            RateLimitResult {
                allowed: true,
                remaining,
                reset_at,
                retry_after: None,
            }
        } else {
            let rate = self.rate_at(now_ms);
            let retry_after_ms = if rate > 0.0 {
                let needed = count_f - bucket.tokens;
                ((needed / rate) * 1000.0).ceil() as u64
            } else {
                u64::MAX
            };

            RateLimitResult {
                allowed: false,
                remaining: bucket.tokens.floor() as u64,
                reset_at: now_ms.saturating_add(retry_after_ms),
                retry_after: Some(Duration::from_millis(retry_after_ms)),
            }
        }
    }

    fn peek(&self, key: &str, now_ms: u64) -> RateLimitResult {
        let capacity = self.capacity_at(now_ms);
        let rate = self.rate_at(now_ms);

        let result = self.buckets.get_mut(key).map(|mut b| {
            if b.last_refill_ms != 0 {
                let elapsed_ms = now_ms.saturating_sub(b.last_refill_ms);
                if elapsed_ms > 0 {
                    let rate_per_ms = rate / 1000.0;
                    let new_tokens = elapsed_ms as f64 * rate_per_ms;
                    b.tokens = (b.tokens + new_tokens).min(capacity);
                    b.last_refill_ms = now_ms;
                }
            }

            let tokens = b.tokens;
            let allowed = tokens >= 1.0;

            let reset_at = if rate > 0.0 {
                let needed = capacity - tokens;
                let time_to_full_ms = (needed / rate) * 1000.0;
                now_ms.saturating_add(time_to_full_ms as u64)
            } else {
                u64::MAX
            };

            (allowed, tokens.floor() as u64, reset_at, rate)
        });

        match result {
            Some((allowed, remaining, reset_at, rate)) => RateLimitResult {
                allowed,
                remaining,
                reset_at,
                retry_after: if allowed {
                    None
                } else if rate > 0.0 {
                    let needed = 1.0 - (remaining as f64);
                    Some(Duration::from_millis(((needed / rate) * 1000.0).ceil() as u64))
                } else {
                    Some(Duration::from_secs(u64::MAX))
                },
            },
            None => RateLimitResult {
                allowed: true,
                remaining: capacity as u64,
                reset_at: now_ms,
                retry_after: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_basic() {
        let config = AlgorithmConfig::token_bucket(10, 10, None);
        let limiter = TokenBucketRateLimiter::new(config);
        let now = 1000000;

        for i in 0..10 {
            let result = limiter.check("test", 1, now);
            assert!(result.allowed, "token {} should be allowed", i);
        }

        let result = limiter.check("test", 1, now);
        assert!(!result.allowed);
    }

    #[test]
    fn test_token_bucket_refill() {
        let config = AlgorithmConfig::token_bucket(10, 10, None);
        let limiter = TokenBucketRateLimiter::new(config);
        let now = 1000000;

        for _ in 0..10 {
            limiter.check("test", 1, now);
        }

        let result = limiter.check("test", 1, now + 1000);
        assert!(result.allowed);
        assert_eq!(result.remaining, 9);
    }

    #[test]
    fn test_token_bucket_warmup() {
        let config = AlgorithmConfig::token_bucket(10, 10, Some(Duration::from_secs(10)));
        let mut limiter = TokenBucketRateLimiter::new(config);
        limiter.started_at_ms = 1000000;

        let result = limiter.check("test", 1, 1000000);
        assert!(!result.allowed);

        let result = limiter.check("test", 1, 1005000);
        assert!(result.allowed);
    }
}
