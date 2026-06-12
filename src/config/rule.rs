use crate::algorithm::AlgorithmConfig;
use crate::key_extractor::KeyExtractor;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Global,
    PathPrefix,
    IpBlacklist,
    IpWhitelist,
    IpGraylist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    pub enabled: bool,
    pub threshold_multiplier: Option<f64>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u64,
    #[serde(with = "duration_seconds", default = "default_alert_window")]
    pub window: Duration,
    pub webhooks: Vec<WebhookConfig>,
}

fn default_block_threshold() -> u64 {
    100
}

fn default_alert_window() -> Duration {
    Duration::from_secs(300)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    #[serde(rename = "type")]
    pub webhook_type: WebhookType,
    pub url: String,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WebhookType {
    Feishu,
    Dingtalk,
    Slack,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "type", default = "default_rule_type")]
    pub rule_type: RuleType,
    pub enabled: bool,
    pub priority: i32,
    pub algorithm: AlgorithmConfig,
    pub key_extractor: KeyExtractor,
    pub path_prefix: Option<String>,
    pub ip_list: Option<Vec<String>>,
    pub graylist_multiplier: Option<f64>,
    pub group: Option<String>,
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub stats: RuleStats,
}

fn default_rule_type() -> RuleType {
    RuleType::Global
}

#[derive(Debug, Clone, Default)]
pub struct RuleStats {
    pub total_calls: u64,
    pub allowed_calls: u64,
    pub blocked_calls: u64,
    pub last_triggered_at: Option<u64>,
    pub current_window_blocked: u64,
}

impl RuleStats {
    pub fn record(&mut self, allowed: bool, now_ms: u64) {
        self.total_calls += 1;
        self.last_triggered_at = Some(now_ms);
        if allowed {
            self.allowed_calls += 1;
        } else {
            self.blocked_calls += 1;
            self.current_window_blocked += 1;
        }
    }

    pub fn reset_window(&mut self) {
        self.current_window_blocked = 0;
    }
}

impl Rule {
    pub fn is_active(&self, now_ms: u64) -> bool {
        if !self.enabled {
            return false;
        }

        let now = now_ms as i64 * 1_000_000;

        if let Some(start) = self.start_at {
            if (start.timestamp_nanos_opt().unwrap_or(0) as i64) > now {
                return false;
            }
        }

        if let Some(end) = self.end_at {
            if (end.timestamp_nanos_opt().unwrap_or(0) as i64) < now {
                return false;
            }
        }

        true
    }

    pub fn get_effective_limit(&self, group_config: Option<&GroupConfig>) -> u64 {
        let mut limit = self.algorithm.limit;

        if let Some(group) = group_config {
            if let Some(multiplier) = group.threshold_multiplier {
                limit = (limit as f64 * multiplier) as u64;
            }
        }

        limit
    }

    pub fn matches_ip(&self, ip: &str) -> bool {
        match self.rule_type {
            RuleType::IpBlacklist | RuleType::IpWhitelist | RuleType::IpGraylist => {
                self.ip_list.as_ref().map_or(false, |list| {
                    list.iter().any(|pattern| ip_matches(pattern, ip))
                })
            }
            _ => false,
        }
    }

    pub fn matches_path(&self, path: &str) -> bool {
        match self.rule_type {
            RuleType::PathPrefix => self
                .path_prefix
                .as_ref()
                .map_or(false, |prefix| path.starts_with(prefix)),
            _ => false,
        }
    }
}

fn ip_matches(pattern: &str, ip: &str) -> bool {
    if pattern == ip {
        return true;
    }

    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return ip.starts_with(prefix);
    }

    false
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
