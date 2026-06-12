pub mod memory;
#[cfg(feature = "redis-store")]
pub mod redis_store;

use crate::algorithm::{AlgorithmConfig, RateLimitResult};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum StoreBackend {
    Memory,
    #[cfg(feature = "redis-store")]
    Redis,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn RateLimitStore>,
    backend: StoreBackend,
}

#[async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check(
        &self,
        rule_id: &str,
        key: &str,
        count: u64,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult;

    async fn peek(
        &self,
        rule_id: &str,
        key: &str,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult;

    async fn reset(&self, rule_id: &str, key: &str) -> Result<(), StoreError>;

    async fn health_check(&self) -> bool;

    fn backend_type(&self) -> StoreBackend;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Other(String),
    #[error("connection error: {0}")]
    Connection(String),
}

impl Store {
    pub async fn from_env() -> anyhow::Result<Self> {
        let redis_url = std::env::var("REDIS_URL").ok();

        if let Some(url) = redis_url {
            #[cfg(feature = "redis-store")]
            {
                tracing::info!("using redis store backend: {}", url);
                let redis = redis_store::RedisStore::new(&url).await?;
                return Ok(Self {
                    inner: Arc::new(redis),
                    backend: StoreBackend::Redis,
                });
            }
            #[cfg(not(feature = "redis-store"))]
            {
                tracing::warn!("REDIS_URL set but redis-store feature not enabled, falling back to memory store");
            }
        }

        tracing::info!("using memory store backend");
        Ok(Self {
            inner: Arc::new(memory::MemoryStore::new()),
            backend: StoreBackend::Memory,
        })
    }

    pub async fn check(
        &self,
        rule_id: &str,
        key: &str,
        count: u64,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        self.inner.check(rule_id, key, count, config, now_ms).await
    }

    pub async fn peek(
        &self,
        rule_id: &str,
        key: &str,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        self.inner.peek(rule_id, key, config, now_ms).await
    }

    pub async fn reset(&self, rule_id: &str, key: &str) -> Result<(), StoreError> {
        self.inner.reset(rule_id, key).await
    }

    pub async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    pub fn backend_type(&self) -> StoreBackend {
        self.backend.clone()
    }
}
