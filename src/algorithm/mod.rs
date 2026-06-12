pub mod fixed_window;
pub mod sliding_window;
pub mod token_bucket;

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmType {
    FixedWindow,
    SlidingWindow,
    TokenBucket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmConfig {
    pub algorithm: AlgorithmType,
    pub limit: u64,
    #[serde(with = "duration_seconds")]
    pub window_size: Duration,
    #[serde(default)]
    #[serde(with = "optional_duration_seconds")]
    pub warmup_period: Option<Duration>,
    #[serde(default)]
    pub rate: Option<u64>,
    #[serde(default)]
    pub capacity: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub reset_at: u64,
    pub retry_after: Option<Duration>,
}

pub trait RateLimiter: Send + Sync {
    fn check(&self, key: &str, count: u64, now_ms: u64) -> RateLimitResult;
    fn peek(&self, key: &str, now_ms: u64) -> RateLimitResult;
}

impl AlgorithmConfig {
    pub fn fixed_window(limit: u64, window_size: Duration) -> Self {
        Self {
            algorithm: AlgorithmType::FixedWindow,
            limit,
            window_size,
            warmup_period: None,
            rate: None,
            capacity: None,
        }
    }

    pub fn sliding_window(limit: u64, window_size: Duration) -> Self {
        Self {
            algorithm: AlgorithmType::SlidingWindow,
            limit,
            window_size,
            warmup_period: None,
            rate: None,
            capacity: None,
        }
    }

    pub fn token_bucket(rate: u64, capacity: u64, warmup_period: Option<Duration>) -> Self {
        Self {
            algorithm: AlgorithmType::TokenBucket,
            limit: capacity,
            window_size: Duration::from_secs(1),
            warmup_period,
            rate: Some(rate),
            capacity: Some(capacity),
        }
    }
}

mod duration_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

mod optional_duration_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_some(&d.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<u64>::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}
