use crate::config::{ConfigManager, WebhookConfig, WebhookType};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

#[derive(Clone)]
pub struct AlertManager {
    config_manager: ConfigManager,
    last_alert_times: Arc<RwLock<HashMap<String, u64>>>,
}

impl AlertManager {
    pub fn new(config_manager: ConfigManager) -> Self {
        Self {
            config_manager,
            last_alert_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.run().await;
        });
    }

    async fn run(&self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            interval.tick().await;
            self.check_and_alert().await;
        }
    }

    async fn check_and_alert(&self) {
        let config = self.config_manager.get_config();
        let alert_cfg = match &config.alert {
            Some(a) if a.enabled => a,
            _ => return,
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let window_ms = alert_cfg.window.as_millis() as u64;

        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }

            let stats = self.config_manager.get_stats(&rule.id);
            if let Some(stats) = stats {
                if stats.current_window_blocked >= alert_cfg.block_threshold {
                    let last_alert = self
                        .last_alert_times
                        .read()
                        .await
                        .get(&rule.id)
                        .copied()
                        .unwrap_or(0);

                    if now_ms - last_alert > window_ms {
                        self.send_alert(rule.id.as_str(), &stats.current_window_blocked, &alert_cfg.webhooks)
                            .await;
                        self.last_alert_times
                            .write()
                            .await
                            .insert(rule.id.clone(), now_ms);
                    }
                }
            }
        }
    }

    async fn send_alert(&self, rule_id: &str, blocked_count: &u64, webhooks: &[WebhookConfig]) {
        for webhook in webhooks {
            let result = match webhook.webhook_type {
                WebhookType::Feishu => send_feishu_alert(webhook, rule_id, blocked_count).await,
                WebhookType::Dingtalk => send_dingtalk_alert(webhook, rule_id, blocked_count).await,
                WebhookType::Slack => send_slack_alert(webhook, rule_id, blocked_count).await,
                WebhookType::Generic => send_generic_alert(webhook, rule_id, blocked_count).await,
            };

            if let Err(e) = result {
                tracing::error!("failed to send alert to {:?}: {}", webhook.webhook_type, e);
            }
        }
    }
}

async fn send_feishu_alert(webhook: &WebhookConfig, rule_id: &str, blocked_count: &u64) -> Result<(), String> {
    let client = reqwest::Client::new();
    let message = format!(
        "🚨 **限流告警**\n\n规则 ID: {rule_id}\n被限流次数: {blocked_count}\n告警时间: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    let payload = serde_json::json!({
        "msg_type": "text",
        "content": {
            "text": message
        }
    });

    client
        .post(&webhook.url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

async fn send_dingtalk_alert(webhook: &WebhookConfig, rule_id: &str, blocked_count: &u64) -> Result<(), String> {
    let client = reqwest::Client::new();
    let message = format!(
        "🚨 限流告警\n\n规则 ID: {rule_id}\n被限流次数: {blocked_count}\n告警时间: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    let payload = serde_json::json!({
        "msgtype": "text",
        "text": {
            "content": message
        }
    });

    client
        .post(&webhook.url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

async fn send_slack_alert(webhook: &WebhookConfig, rule_id: &str, blocked_count: &u64) -> Result<(), String> {
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "text": "🚨 限流告警",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {
                        "title": "规则 ID",
                        "value": rule_id,
                        "short": false
                    },
                    {
                        "title": "被限流次数",
                        "value": blocked_count.to_string(),
                        "short": false
                    }
                ]
            }
        ]
    });

    client
        .post(&webhook.url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

async fn send_generic_alert(webhook: &WebhookConfig, rule_id: &str, blocked_count: &u64) -> Result<(), String> {
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "rule_id": rule_id,
        "blocked_count": blocked_count,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "alert_type": "rate_limit"
    });

    client
        .post(&webhook.url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
