use crate::config::{Config, Rule, RuleType};
use std::sync::Arc;

pub struct MatchResult {
    pub action: MatchAction,
    pub rule: Rule,
}

#[derive(Debug, PartialEq)]
pub enum MatchAction {
    Allow,
    Deny,
    RateLimit,
}

pub fn match_rules(
    config: &Arc<Config>,
    ip: &str,
    path: &str,
    now_ms: u64,
) -> Option<MatchResult> {
    let mut active_rules: Vec<&Rule> = config
        .rules
        .iter()
        .filter(|r| r.is_active(now_ms))
        .collect();

    active_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in &active_rules {
        match rule.rule_type {
            RuleType::IpBlacklist => {
                if rule.matches_ip(ip) {
                    return Some(MatchResult {
                        action: MatchAction::Deny,
                        rule: (*rule).clone(),
                    });
                }
            }
            RuleType::IpWhitelist => {
                if rule.matches_ip(ip) {
                    return Some(MatchResult {
                        action: MatchAction::Allow,
                        rule: (*rule).clone(),
                    });
                }
            }
            RuleType::IpGraylist => {
                if rule.matches_ip(ip) {
                    return Some(MatchResult {
                        action: MatchAction::RateLimit,
                        rule: (*rule).clone(),
                    });
                }
            }
            _ => {}
        }
    }

    for rule in &active_rules {
        if rule.rule_type == RuleType::PathPrefix && rule.matches_path(path) {
            return Some(MatchResult {
                action: MatchAction::RateLimit,
                rule: (*rule).clone(),
            });
        }
    }

    for rule in &active_rules {
        if rule.rule_type == RuleType::Global {
            return Some(MatchResult {
                action: MatchAction::RateLimit,
                rule: (*rule).clone(),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::AlgorithmConfig;
    use crate::config::Rule;
    use crate::key_extractor::KeyExtractor;
    use std::time::Duration;

    fn create_test_config() -> Config {
        let mut rules = vec![];

        rules.push(Rule {
            id: "blacklist".to_string(),
            name: None,
            description: None,
            rule_type: RuleType::IpBlacklist,
            enabled: true,
            priority: 200,
            algorithm: AlgorithmConfig::fixed_window(0, Duration::from_secs(1)),
            key_extractor: KeyExtractor::ip(),
            path_prefix: None,
            ip_list: Some(vec!["10.0.0.1".to_string()]),
            graylist_multiplier: None,
            group: None,
            start_at: None,
            end_at: None,
            stats: Default::default(),
        });

        rules.push(Rule {
            id: "whitelist".to_string(),
            name: None,
            description: None,
            rule_type: RuleType::IpWhitelist,
            enabled: true,
            priority: 200,
            algorithm: AlgorithmConfig::fixed_window(u64::MAX, Duration::from_secs(1)),
            key_extractor: KeyExtractor::ip(),
            path_prefix: None,
            ip_list: Some(vec!["10.0.0.2".to_string()]),
            graylist_multiplier: None,
            group: None,
            start_at: None,
            end_at: None,
            stats: Default::default(),
        });

        rules.push(Rule {
            id: "api-path".to_string(),
            name: None,
            description: None,
            rule_type: RuleType::PathPrefix,
            enabled: true,
            priority: 100,
            algorithm: AlgorithmConfig::fixed_window(100, Duration::from_secs(60)),
            key_extractor: KeyExtractor::ip(),
            path_prefix: Some("/api/".to_string()),
            ip_list: None,
            graylist_multiplier: None,
            group: None,
            start_at: None,
            end_at: None,
            stats: Default::default(),
        });

        rules.push(Rule {
            id: "global".to_string(),
            name: None,
            description: None,
            rule_type: RuleType::Global,
            enabled: true,
            priority: 1,
            algorithm: AlgorithmConfig::fixed_window(1000, Duration::from_secs(60)),
            key_extractor: KeyExtractor::ip(),
            path_prefix: None,
            ip_list: None,
            graylist_multiplier: None,
            group: None,
            start_at: None,
            end_at: None,
            stats: Default::default(),
        });

        Config {
            rules,
            groups: None,
            alert: None,
        }
    }

    #[test]
    fn test_ip_blacklist() {
        let config = Arc::new(create_test_config());
        let result = match_rules(&config, "10.0.0.1", "/test", 1000000);

        assert!(result.is_some());
        assert_eq!(result.unwrap().action, MatchAction::Deny);
    }

    #[test]
    fn test_ip_whitelist() {
        let config = Arc::new(create_test_config());
        let result = match_rules(&config, "10.0.0.2", "/test", 1000000);

        assert!(result.is_some());
        assert_eq!(result.unwrap().action, MatchAction::Allow);
    }

    #[test]
    fn test_path_prefix() {
        let config = Arc::new(create_test_config());
        let result = match_rules(&config, "192.168.1.1", "/api/users", 1000000);

        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.action, MatchAction::RateLimit);
        assert_eq!(r.rule.id, "api-path");
    }

    #[test]
    fn test_global_fallback() {
        let config = Arc::new(create_test_config());
        let result = match_rules(&config, "192.168.1.1", "/other/path", 1000000);

        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.action, MatchAction::RateLimit);
        assert_eq!(r.rule.id, "global");
    }
}
