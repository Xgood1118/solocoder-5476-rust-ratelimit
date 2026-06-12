use super::{Config, Rule, RuleStats};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<Arc<Config>>>,
    stats: Arc<RwLock<HashMap<String, RuleStats>>>,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(config: Config, config_path: PathBuf) -> Self {
        let mut stats = HashMap::new();
        for rule in &config.rules {
            stats.insert(rule.id.clone(), RuleStats::default());
        }

        Self {
            config: Arc::new(RwLock::new(Arc::new(config))),
            stats: Arc::new(RwLock::new(stats)),
            config_path,
        }
    }

    pub fn get_config(&self) -> Arc<Config> {
        self.config.read().clone()
    }

    pub fn get_rule(&self, id: &str) -> Option<Rule> {
        let config = self.get_config();
        config.rules.iter().find(|r| r.id == id).cloned()
    }

    pub fn get_all_rules(&self) -> Vec<Rule> {
        let config = self.get_config();
        let stats = self.stats.read();

        config
            .rules
            .iter()
            .map(|r| {
                let mut rule = r.clone();
                if let Some(s) = stats.get(&r.id) {
                    rule.stats = s.clone();
                }
                rule
            })
            .collect()
    }

    pub fn record_stat(&self, rule_id: &str, allowed: bool, now_ms: u64) {
        let mut stats = self.stats.write();
        if let Some(stat) = stats.get_mut(rule_id) {
            stat.record(allowed, now_ms);
        } else {
            let mut s = RuleStats::default();
            s.record(allowed, now_ms);
            stats.insert(rule_id.to_string(), s);
        }
    }

    pub fn get_stats(&self, rule_id: &str) -> Option<RuleStats> {
        self.stats.read().get(rule_id).cloned()
    }

    pub fn add_rule(&self, rule: Rule) {
        let config = self.get_config();
        let mut new_rules: Vec<Rule> = config.rules.clone();

        if let Some(pos) = new_rules.iter().position(|r| r.id == rule.id) {
            new_rules[pos] = rule.clone();
        } else {
            new_rules.push(rule.clone());
        }

        let new_config = Config {
            rules: new_rules,
            groups: config.groups.clone(),
            alert: config.alert.clone(),
        };

        *self.config.write() = Arc::new(new_config);

        let mut stats = self.stats.write();
        stats.entry(rule.id).or_insert_with(RuleStats::default);
    }

    pub fn update_rule(&self, rule: Rule) -> bool {
        let config = self.get_config();
        let mut new_rules: Vec<Rule> = config.rules.clone();

        if let Some(pos) = new_rules.iter().position(|r| r.id == rule.id) {
            new_rules[pos] = rule;

            let new_config = Config {
                rules: new_rules,
                groups: config.groups.clone(),
                alert: config.alert.clone(),
            };

            *self.config.write() = Arc::new(new_config);
            true
        } else {
            false
        }
    }

    pub fn delete_rule(&self, id: &str) -> bool {
        let config = self.get_config();
        let mut new_rules: Vec<Rule> = config.rules.clone();

        if let Some(pos) = new_rules.iter().position(|r| r.id == id) {
            new_rules.remove(pos);

            let new_config = Config {
                rules: new_rules,
                groups: config.groups.clone(),
                alert: config.alert.clone(),
            };

            *self.config.write() = Arc::new(new_config);

            let mut stats = self.stats.write();
            stats.remove(id);

            true
        } else {
            false
        }
    }

    pub async fn start_watcher(&self) -> anyhow::Result<()> {
        let manager = self.clone();
        let config_path = self.config_path.clone();

        tokio::spawn(async move {
            if let Err(e) = watch_config(manager, config_path).await {
                tracing::error!("config watcher error: {}", e);
            }
        });

        Ok(())
    }

    pub fn reload_from_file(&self) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(&self.config_path)?;
        let new_config: Config = serde_yaml::from_str(&content)?;

        let old_stats = self.stats.read().clone();
        let mut new_stats = HashMap::new();

        for rule in &new_config.rules {
            let stat = old_stats
                .get(&rule.id)
                .cloned()
                .unwrap_or_default();
            new_stats.insert(rule.id.clone(), stat);
        }

        *self.config.write() = Arc::new(new_config);
        *self.stats.write() = new_stats;

        tracing::info!("config reloaded from file");
        Ok(())
    }

    pub fn get_top_blocked_keys(&self, _n: usize) -> Vec<(String, u64)> {
        vec![]
    }

    pub fn get_rule_frequency_rank(&self) -> Vec<(String, u64)> {
        let stats = self.stats.read();
        let mut rules: Vec<(String, u64)> = stats
            .iter()
            .map(|(id, s)| (id.clone(), s.total_calls))
            .collect();
        rules.sort_by(|a, b| b.1.cmp(&a.1));
        rules
    }
}

async fn watch_config(manager: ConfigManager, path: PathBuf) -> anyhow::Result<()> {
    use notify::{RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::channel(10);

    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            let _ = tx.try_send(event);
        }
    })?;

    let path_to_watch = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    watcher.watch(&path_to_watch, RecursiveMode::NonRecursive)?;

    tracing::info!("watching config file: {:?}", path);

    let mut debounce = tokio::time::interval(tokio::time::Duration::from_secs(1));
    let mut has_changes = false;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                use notify::EventKind;
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                    has_changes = true;
                }
            }
            _ = debounce.tick() => {
                if has_changes {
                    tracing::info!("config file changed, reloading...");
                    if let Err(e) = manager.reload_from_file() {
                        tracing::error!("failed to reload config: {}", e);
                    }
                    has_changes = false;
                }
            }
        }
    }
}
