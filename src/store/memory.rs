use super::{RateLimitStore, StoreError, StoreBackend};
use crate::algorithm::{
    AlgorithmConfig, AlgorithmType, RateLimitResult,
    fixed_window::FixedWindowRateLimiter,
    sliding_window::SlidingWindowRateLimiter,
    token_bucket::TokenBucketRateLimiter,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

struct LimiterEntry {
    limiter: Arc<dyn crate::algorithm::RateLimiter + Send + Sync>,
    config_fingerprint: u64,
}

pub struct MemoryStore {
    limiters: DashMap<String, LimiterEntry>,
}

fn config_fingerprint(config: &AlgorithmConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    std::mem::discriminant(&config.algorithm).hash(&mut hasher);
    config.limit.hash(&mut hasher);
    config.window_size.as_millis().hash(&mut hasher);
    config.rate.hash(&mut hasher);
    config.capacity.hash(&mut hasher);
    if let Some(wp) = config.warmup_period {
        wp.as_millis().hash(&mut hasher);
    }

    hasher.finish()
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            limiters: DashMap::new(),
        }
    }

    fn get_or_create_limiter(
        &self,
        rule_id: &str,
        config: &AlgorithmConfig,
    ) -> Arc<dyn crate::algorithm::RateLimiter + Send + Sync> {
        let fp = config_fingerprint(config);

        if let Some(entry) = self.limiters.get(rule_id) {
            if entry.config_fingerprint == fp {
                return entry.limiter.clone();
            }
        }

        self.limiters.remove(rule_id);

        let limiter: Arc<dyn crate::algorithm::RateLimiter + Send + Sync> = match config.algorithm {
            AlgorithmType::FixedWindow => {
                Arc::new(FixedWindowRateLimiter::new(config.clone()))
            }
            AlgorithmType::SlidingWindow => {
                Arc::new(SlidingWindowRateLimiter::new(config.clone()))
            }
            AlgorithmType::TokenBucket => {
                Arc::new(TokenBucketRateLimiter::new(config.clone()))
            }
        };

        self.limiters.insert(rule_id.to_string(), LimiterEntry {
            limiter: limiter.clone(),
            config_fingerprint: fp,
        });

        limiter
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RateLimitStore for MemoryStore {
    async fn check(
        &self,
        rule_id: &str,
        key: &str,
        count: u64,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        let limiter = self.get_or_create_limiter(rule_id, config);
        limiter.check(key, count, now_ms)
    }

    async fn peek(
        &self,
        rule_id: &str,
        key: &str,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        let limiter = self.get_or_create_limiter(rule_id, config);
        limiter.peek(key, now_ms)
    }

    async fn reset(&self, rule_id: &str, _key: &str) -> Result<(), StoreError> {
        self.limiters.remove(rule_id);
        Ok(())
    }

    async fn health_check(&self) -> bool {
        true
    }

    fn backend_type(&self) -> StoreBackend {
        StoreBackend::Memory
    }
}
