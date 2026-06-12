use crate::api::matcher::{self, MatchAction};
use crate::config::templates;
use crate::config::{Config, Rule, RuleStats};
use crate::key_extractor::{self, KeyExtractor};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use super::AppState;

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    #[serde(default = "default_rule_id")]
    pub rule_id: Option<String>,
    pub key: Option<String>,
    #[serde(default = "default_count")]
    pub count: Option<u64>,
    pub path: Option<String>,
    pub ip: Option<String>,
}

fn default_rule_id() -> Option<String> {
    None
}

fn default_count() -> Option<u64> {
    Some(1)
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub remaining: u64,
    pub reset_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    pub rule_id: String,
    pub key: String,
}

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let healthy = state.store.health_check().await;
    if healthy {
        (StatusCode::OK, Json(serde_json::json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "reason": "store unavailable"})),
        )
    }
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = state.metrics.gather_text();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(body))
        .unwrap()
}

pub async fn check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CheckRequest>,
) -> Response {
    let start = std::time::Instant::now();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let config = state.config_manager.get_config();

    let ip = req.ip.clone().unwrap_or_else(|| {
        headers
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    let path = req.path.clone().unwrap_or_else(|| "/".to_string());

    let query_params: HashMap<String, String> = HashMap::new();
    let cookies = key_extractor::parse_cookies(&headers);

    let (rule, key) = if let Some(rule_id) = &req.rule_id {
        let rule = match config.get_rule(rule_id) {
            Some(r) => r.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "rule not found"})),
                )
                    .into_response();
            }
        };

        let key = if let Some(k) = &req.key {
            k.clone()
        } else {
            extract_key(&rule.key_extractor, &headers, &query_params, None, &cookies, &ip, &path)
                .unwrap_or_else(|| "default".to_string())
        };

        (rule, key)
    } else {
        let match_result = matcher::match_rules(&config, &ip, &path, now_ms);

        match match_result {
            Some(m) => match m.action {
                MatchAction::Allow => {
                    let duration = start.elapsed().as_millis() as f64;
                    state.metrics.record_check(&m.rule.id, true, u64::MAX, duration);
                    state.config_manager.record_stat(&m.rule.id, true, now_ms);

                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "allowed": true,
                            "remaining": u64::MAX,
                            "reset_at": now_ms,
                            "rule_id": m.rule.id,
                            "key": ip
                        })),
                    )
                        .into_response();
                }
                MatchAction::Deny => {
                    let duration = start.elapsed().as_millis() as f64;
                    state.metrics.record_check(&m.rule.id, false, 0, duration);
                    state.config_manager.record_stat(&m.rule.id, false, now_ms);

                    let mut headers_map = HeaderMap::new();
                    headers_map.insert("X-RateLimit-Limit", HeaderValue::from_static("0"));
                    headers_map.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
                    headers_map.insert("Retry-After", HeaderValue::from_static("86400"));

                    return (
                        StatusCode::FORBIDDEN,
                        headers_map,
                        Json(serde_json::json!({
                            "allowed": false,
                            "remaining": 0,
                            "reset_at": now_ms + 86400000,
                            "retry_after": 86400,
                            "rule_id": m.rule.id,
                            "key": ip,
                            "reason": "ip blacklisted"
                        })),
                    )
                        .into_response();
                }
                MatchAction::RateLimit => {
                    let key = if let Some(k) = &req.key {
                        k.clone()
                    } else {
                        extract_key(
                            &m.rule.key_extractor,
                            &headers,
                            &query_params,
                            None,
                            &cookies,
                            &ip,
                            &path,
                        )
                        .unwrap_or_else(|| "default".to_string())
                    };

                    (m.rule, key)
                }
            },
            None => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "allowed": true,
                        "remaining": 0,
                        "reset_at": now_ms,
                        "rule_id": "",
                        "key": ""
                    })),
                )
                    .into_response();
            }
        }
    };

    let count = req.count.unwrap_or(1);

    let result = state
        .store
        .check(&rule.id, &key, count, &rule.algorithm, now_ms)
        .await;

    let duration = start.elapsed().as_millis() as f64;
    state
        .metrics
        .record_check(&rule.id, result.allowed, result.remaining, duration);
    state
        .config_manager
        .record_stat(&rule.id, result.allowed, now_ms);

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "X-RateLimit-Limit",
        HeaderValue::from(rule.algorithm.limit),
    );
    response_headers.insert(
        "X-RateLimit-Remaining",
        HeaderValue::from(result.remaining),
    );
    response_headers.insert(
        "X-RateLimit-Reset",
        HeaderValue::from(result.reset_at / 1000),
    );

    let status = if result.allowed {
        StatusCode::OK
    } else {
        if let Some(retry) = result.retry_after {
            response_headers.insert(
                "Retry-After",
                HeaderValue::from(retry.as_secs().max(1)),
            );
        }
        StatusCode::TOO_MANY_REQUESTS
    };

    let response = CheckResponse {
        allowed: result.allowed,
        remaining: result.remaining,
        reset_at: result.reset_at,
        retry_after: result.retry_after.map(|d| d.as_secs().max(1)),
        rule_id: rule.id.clone(),
        key: key.clone(),
    };

    tracing::info!(
        method = "POST",
        path = "/api/check",
        key = key.as_str(),
        rule_id = rule.id.as_str(),
        allowed = result.allowed,
        remaining = result.remaining,
        "rate limit check"
    );

    (status, response_headers, Json(response)).into_response()
}

fn extract_key(
    extractor: &KeyExtractor,
    headers: &HeaderMap,
    query_params: &HashMap<String, String>,
    body: Option<&serde_json::Value>,
    cookies: &HashMap<String, String>,
    client_ip: &str,
    request_path: &str,
) -> Option<String> {
    extractor.extract(headers, query_params, body, cookies, client_ip, request_path)
}

pub async fn list_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rules = state.config_manager.get_all_rules();
    let rule_responses: Vec<RuleResponse> = rules.into_iter().map(RuleResponse::from).collect();
    Json(serde_json::json!({ "rules": rule_responses }))
}

pub async fn get_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.config_manager.get_rule(&id) {
        Some(rule) => {
            let stats = state.config_manager.get_stats(&id).unwrap_or_default();
            let mut rule_with_stats = rule.clone();
            rule_with_stats.stats = stats;
            (StatusCode::OK, Json(RuleResponse::from(rule_with_stats)))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(RuleResponse::default()),
        ),
    }
}

pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<Rule>,
) -> impl IntoResponse {
    state.config_manager.add_rule(rule.clone());
    (StatusCode::CREATED, Json(RuleResponse::from(rule)))
}

pub async fn update_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut rule): Json<Rule>,
) -> impl IntoResponse {
    rule.id = id;
    if state.config_manager.update_rule(rule.clone()) {
        (StatusCode::OK, Json(RuleResponse::from(rule)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(RuleResponse::default()),
        )
    }
}

pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.config_manager.delete_rule(&id) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportRulesRequest {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub overwrite: bool,
}

pub async fn import_rules(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRulesRequest>,
) -> impl IntoResponse {
    let count = req.rules.len();
    for rule in req.rules {
        if req.overwrite {
            state.config_manager.add_rule(rule);
        } else if state.config_manager.get_rule(&rule.id).is_none() {
            state.config_manager.add_rule(rule);
        }
    }

    Json(serde_json::json!({
        "imported": count,
        "total": state.config_manager.get_all_rules().len()
    }))
}

pub async fn export_rules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rules = state.config_manager.get_all_rules();
    Json(serde_json::json!({
        "rules": rules,
        "exported_at": chrono::Utc::now().to_rfc3339()
    }))
}

pub async fn list_templates() -> impl IntoResponse {
    let templates = templates::builtin_templates();
    Json(serde_json::json!({ "templates": templates }))
}

pub async fn list_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config_manager.get_config();
    let groups = config.groups.clone().unwrap_or_default();
    Json(serde_json::json!({ "groups": groups }))
}

#[derive(Debug, Serialize, Default)]
pub struct RuleResponse {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i32,
    pub algorithm: serde_json::Value,
    pub stats: RuleStatsResponse,
    pub group: Option<String>,
    pub start_at: Option<String>,
    pub end_at: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct RuleStatsResponse {
    pub total_calls: u64,
    pub allowed_calls: u64,
    pub blocked_calls: u64,
    pub last_triggered_at: Option<u64>,
}

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        let stats = RuleStatsResponse {
            total_calls: rule.stats.total_calls,
            allowed_calls: rule.stats.allowed_calls,
            blocked_calls: rule.stats.blocked_calls,
            last_triggered_at: rule.stats.last_triggered_at,
        };

        let algorithm_json = serde_json::json!({
            "type": match rule.algorithm.algorithm {
                crate::algorithm::AlgorithmType::FixedWindow => "fixed_window",
                crate::algorithm::AlgorithmType::SlidingWindow => "sliding_window",
                crate::algorithm::AlgorithmType::TokenBucket => "token_bucket",
            },
            "limit": rule.algorithm.limit,
            "window_size_seconds": rule.algorithm.window_size.as_secs(),
            "rate": rule.algorithm.rate,
            "capacity": rule.algorithm.capacity,
            "warmup_period_seconds": rule.algorithm.warmup_period.map(|d| d.as_secs()),
        });

        Self {
            id: rule.id,
            name: rule.name,
            description: rule.description,
            enabled: rule.enabled,
            priority: rule.priority,
            algorithm: algorithm_json,
            stats,
            group: rule.group,
            start_at: rule.start_at.map(|d| d.to_rfc3339()),
            end_at: rule.end_at.map(|d| d.to_rfc3339()),
        }
    }
}

pub async fn rules_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rank = state.config_manager.get_rule_frequency_rank();
    let top_keys = state.config_manager.get_top_blocked_keys(10);

    Json(serde_json::json!({
        "rule_frequency_rank": rank,
        "top_blocked_keys": top_keys,
    }))
}

pub async fn admin_index() -> impl IntoResponse {
    let html = include_str!("../../static/admin/index.html");
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html.to_string()))
        .unwrap()
}

pub async fn admin_static(Path(path): Path<String>) -> impl IntoResponse {
    let content_type = mime_guess::from_path(&path).first_or_octet_stream();
    
    let file_path = format!("static/admin/{}", path);
    match std::fs::read_to_string(&file_path) {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type.essence_str())
            .body(Body::from(content))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap(),
    }
}
