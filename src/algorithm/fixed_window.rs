use super::{AlgorithmConfig, RateLimitResult, RateLimiter};
use dashmap::DashMap;
use std::time::Duration;

pub struct FixedWindowRateLimiter {
    config: AlgorithmConfig,
    windows: DashMap<String, WindowState>,
}

struct WindowState {
    count: u64,
    window_start: u64,
}

impl FixedWindowRateLimiter {
    pub fn new(config: AlgorithmConfig) -> Self {
        Self {
            config,
            windows: DashMap::new(),
        }
    }

    fn get_window(&self, now_ms: u64) -> u64 {
        let window_ms = self.config.window_size.as_millis() as u64;
        (now_ms / window_ms) * window_ms
    }
}

impl RateLimiter for FixedWindowRateLimiter {
    fn check(&self, key: &str, count: u64, now_ms: u64) -> RateLimitResult {
        let window_start = self.get_window(now_ms);
        let window_ms = self.config.window_size.as_millis() as u64;
        let reset_at = window_start + window_ms;

        let mut entry = self.windows.entry(key.to_string()).or_insert(WindowState {
            count: 0,
            window_start,
        });

        if entry.window_start != window_start {
            entry.count = 0;
            entry.window_start = window_start;
        }

        if entry.count + count <= self.config.limit {
            entry.count += count;
            RateLimitResult {
                allowed: true,
                remaining: self.config.limit - entry.count,
                reset_at,
                retry_after: None,
            }
        } else {
            let retry_after_ms = reset_at - now_ms;
            RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at,
                retry_after: Some(Duration::from_millis(retry_after_ms)),
            }
        }
    }

    fn peek(&self, key: &str, now_ms: u64) -> RateLimitResult {
        let window_start = self.get_window(now_ms);
        let window_ms = self.config.window_size.as_millis() as u64;
        let reset_at = window_start + window_ms;

        let count = self
            .windows
            .get(key)
            .map(|e| if e.window_start == window_start { e.count } else { 0 })
            .unwrap_or(0);

        RateLimitResult {
            allowed: count < self.config.limit,
            remaining: self.config.limit.saturating_sub(count),
            reset_at,
            retry_after: if count >= self.config.limit {
                Some(Duration::from_millis(reset_at - now_ms))
            } else {
                None
            },
        }
    }
}
