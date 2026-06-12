use super::{RateLimitStore, StoreError, StoreBackend};
use crate::algorithm::{AlgorithmConfig, AlgorithmType, RateLimitResult};
use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Client, Script};
use std::time::Duration;

const FIXED_WINDOW_SCRIPT: &str = r#"
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_size = tonumber(ARGV[2])
local count = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local window_start = math.floor(now / window_size) * window_size
local window_key = key .. ":" .. window_start

local current = tonumber(redis.call('GET', window_key) or '0')

if current + count <= limit then
    redis.call('INCRBY', window_key, count)
    redis.call('EXPIRE', window_key, math.ceil(window_size / 1000) + 1)
    return {1, limit - (current + count), window_start + window_size, 0}
else
    local retry_after = window_start + window_size - now
    return {0, 0, window_start + window_size, retry_after}
end
"#;

const TOKEN_BUCKET_SCRIPT: &str = r#"
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local count = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1] or tostring(capacity))
local last_refill = tonumber(data[2] or tostring(now))

if last_refill < now then
    local elapsed = now - last_refill
    local new_tokens = elapsed * rate / 1000.0
    tokens = math.min(capacity, tokens + new_tokens)
    last_refill = now
end

if tokens >= count then
    tokens = tokens - count
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
    redis.call('EXPIRE', key, 3600)
    local reset_at = now + ((capacity - tokens) / rate * 1000)
    return {1, math.floor(tokens), math.floor(reset_at), 0}
else
    local needed = count - tokens
    local retry_after = math.ceil(needed / rate * 1000)
    return {0, math.floor(tokens), now + retry_after, retry_after}
end
"#;

const SLIDING_WINDOW_SCRIPT: &str = r#"
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_size = tonumber(ARGV[2])
local count = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local window_start = now - window_size
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local current = tonumber(redis.call('ZCARD', key) or '0')

if current + count <= limit then
    for i = 1, count do
        redis.call('ZADD', key, now, now .. '-' .. i)
    end
    redis.call('EXPIRE', key, math.ceil(window_size / 1000) + 1)
    local reset_at = now + window_size
    return {1, limit - (current + count), reset_at, 0}
else
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = window_size
    if oldest[2] then
        retry_after = tonumber(oldest[2]) + window_size - now
    end
    return {0, 0, now + retry_after, math.ceil(retry_after)}
end
"#;

pub struct RedisStore {
    client: Client,
    connection: MultiplexedConnection,
    fixed_window_script: Script,
    token_bucket_script: Script,
    sliding_window_script: Script,
}

impl RedisStore {
    pub async fn new(url: &str) -> Result<Self, StoreError> {
        let client = Client::open(url).map_err(|e| StoreError::Connection(e.to_string()))?;
        let connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| StoreError::Connection(e.to_string()))?;

        Ok(Self {
            client,
            connection,
            fixed_window_script: Script::new(FIXED_WINDOW_SCRIPT),
            token_bucket_script: Script::new(TOKEN_BUCKET_SCRIPT),
            sliding_window_script: Script::new(SLIDING_WINDOW_SCRIPT),
        })
    }

    fn prefix_key(rule_id: &str, key: &str) -> String {
        format!("ratelimit:{}:{}", rule_id, key)
    }
}

#[async_trait]
impl RateLimitStore for RedisStore {
    async fn check(
        &self,
        rule_id: &str,
        key: &str,
        count: u64,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        let redis_key = Self::prefix_key(rule_id, key);
        let mut conn = self.connection.clone();

        let result: Result<Vec<i64>, _> = match config.algorithm {
            AlgorithmType::FixedWindow => {
                let window_ms = config.window_size.as_millis() as u64;
                self.fixed_window_script
                    .key(redis_key)
                    .arg(config.limit as i64)
                    .arg(window_ms as i64)
                    .arg(count as i64)
                    .arg(now_ms as i64)
                    .invoke_async(&mut conn)
                    .await
            }
            AlgorithmType::TokenBucket => {
                let rate = config.rate.unwrap_or(config.limit) as i64;
                let capacity = config.capacity.unwrap_or(config.limit) as i64;
                self.token_bucket_script
                    .key(redis_key)
                    .arg(capacity)
                    .arg(rate)
                    .arg(count as i64)
                    .arg(now_ms as i64)
                    .invoke_async(&mut conn)
                    .await
            }
            AlgorithmType::SlidingWindow => {
                let window_ms = config.window_size.as_millis() as u64;
                self.sliding_window_script
                    .key(redis_key)
                    .arg(config.limit as i64)
                    .arg(window_ms as i64)
                    .arg(count as i64)
                    .arg(now_ms as i64)
                    .invoke_async(&mut conn)
                    .await
            }
        };

        match result {
            Ok(values) => {
                let allowed = values[0] == 1;
                let remaining = values[1] as u64;
                let reset_at = values[2] as u64;
                let retry_after_ms = values[3] as u64;

                RateLimitResult {
                    allowed,
                    remaining,
                    reset_at,
                    retry_after: if allowed {
                        None
                    } else {
                        Some(Duration::from_millis(retry_after_ms.max(1)))
                    },
                }
            }
            Err(e) => {
                tracing::error!("redis rate limit check error: {}", e);
                RateLimitResult {
                    allowed: true,
                    remaining: config.limit,
                    reset_at: now_ms + 1000,
                    retry_after: None,
                }
            }
        }
    }

    async fn peek(
        &self,
        rule_id: &str,
        key: &str,
        config: &AlgorithmConfig,
        now_ms: u64,
    ) -> RateLimitResult {
        let redis_key = Self::prefix_key(rule_id, key);
        let mut conn = self.connection.clone();

        match config.algorithm {
            AlgorithmType::FixedWindow => {
                let window_ms = config.window_size.as_millis() as u64;
                let window_start = (now_ms / window_ms) * window_ms;
                let window_key = format!("{}:{}", redis_key, window_start);

                let current: Option<u64> = conn.get(&window_key).await.ok().unwrap_or(None);
                let current = current.unwrap_or(0);

                RateLimitResult {
                    allowed: current < config.limit,
                    remaining: config.limit.saturating_sub(current),
                    reset_at: window_start + window_ms,
                    retry_after: if current >= config.limit {
                        Some(Duration::from_millis(window_start + window_ms - now_ms))
                    } else {
                        None
                    },
                }
            }
            AlgorithmType::TokenBucket => {
                let data: Result<Vec<Option<String>>, _> =
                    redis::cmd("HMGET")
                        .arg(&redis_key)
                        .arg("tokens")
                        .arg("last_refill")
                        .query_async(&mut conn)
                        .await;

                let capacity = config.capacity.unwrap_or(config.limit);
                let rate = config.rate.unwrap_or(config.limit);

                match data {
                    Ok(vals) => {
                        let tokens: f64 = vals.get(0).and_then(|v| v.as_deref()).unwrap_or("0").parse().unwrap_or(capacity as f64);
                        let last_refill: u64 = vals.get(1).and_then(|v| v.as_deref()).unwrap_or("0").parse().unwrap_or(now_ms);

                        let elapsed = now_ms.saturating_sub(last_refill) as f64;
                        let new_tokens = elapsed * rate as f64 / 1000.0;
                        let current_tokens = (tokens + new_tokens).min(capacity as f64);

                        RateLimitResult {
                            allowed: current_tokens >= 1.0,
                            remaining: current_tokens.floor() as u64,
                            reset_at: now_ms + ((capacity as f64 - current_tokens) / rate as f64 * 1000.0) as u64,
                            retry_after: if current_tokens < 1.0 {
                                let needed = 1.0 - current_tokens;
                                Some(Duration::from_millis((needed / rate as f64 * 1000.0).ceil() as u64))
                            } else {
                                None
                            },
                        }
                    }
                    Err(_) => {
                        RateLimitResult {
                            allowed: true,
                            remaining: capacity,
                            reset_at: now_ms,
                            retry_after: None,
                        }
                    }
                }
            }
            AlgorithmType::SlidingWindow => {
                let window_ms = config.window_size.as_millis() as u64;
                let window_start = now_ms - window_ms;

                let _: () = redis::cmd("ZREMRANGEBYSCORE")
                    .arg(&redis_key)
                    .arg("-inf")
                    .arg(window_start)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(());

                let count: Result<u64, _> = redis::cmd("ZCARD")
                    .arg(&redis_key)
                    .query_async(&mut conn)
                    .await;

                let count = count.unwrap_or(0);

                RateLimitResult {
                    allowed: count < config.limit,
                    remaining: config.limit.saturating_sub(count),
                    reset_at: now_ms + window_ms,
                    retry_after: if count >= config.limit {
                        Some(Duration::from_millis(window_ms))
                    } else {
                        None
                    },
                }
            }
        }
    }

    async fn reset(&self, rule_id: &str, key: &str) -> Result<(), StoreError> {
        let redis_key = Self::prefix_key(rule_id, key);
        let mut conn = self.connection.clone();
        let _: () = redis::cmd("DEL")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StoreError::Other(e.to_string()))?;
        Ok(())
    }

    async fn health_check(&self) -> bool {
        let mut conn = self.connection.clone();
        let result: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
        result.is_ok()
    }

    fn backend_type(&self) -> StoreBackend {
        StoreBackend::Redis
    }
}

impl Clone for RedisStore {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            connection: self.connection.clone(),
            fixed_window_script: self.fixed_window_script.clone(),
            token_bucket_script: self.token_bucket_script.clone(),
            sliding_window_script: self.sliding_window_script.clone(),
        }
    }
}
