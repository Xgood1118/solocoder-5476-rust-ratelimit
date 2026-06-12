pub mod rule;
pub mod manager;
pub mod templates;

pub use rule::{Rule, RuleType, RuleStats, AlertConfig, GroupConfig, WebhookConfig, WebhookType};
pub use manager::ConfigManager;
pub use templates::RuleTemplate;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub groups: Option<HashMap<String, GroupConfig>>,
    pub alert: Option<AlertConfig>,
}

impl Config {
    pub async fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: vec![],
            groups: None,
            alert: None,
        }
    }
}
