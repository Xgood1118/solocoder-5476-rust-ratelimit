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

pub struct MemoryStore {
    limiters: DashMap<String, Arc<dyn crate::algorithm::RateLimiter + Send + Sync>>,
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
        if let Some(limiter) = self.limiters.get(rule_id) {
            return limiter.clone();
        }

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

        self.limiters.insert(rule_id.to_string(), limiter.clone());
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
