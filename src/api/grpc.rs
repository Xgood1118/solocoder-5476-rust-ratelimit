#[cfg(feature = "grpc")]
use tonic::{Request, Response, Status};

#[cfg(feature = "grpc")]
use crate::api::AppState;

#[cfg(feature = "grpc")]
use crate::algorithm::AlgorithmType;

#[cfg(feature = "grpc")]
pub mod pb {
    tonic::include_proto!("ratelimit");
}

#[cfg(feature = "grpc")]
pub struct RateLimitServiceImpl {
    state: AppState,
}

#[cfg(feature = "grpc")]
impl RateLimitServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[cfg(feature = "grpc")]
fn algorithm_from_str(s: &str) -> AlgorithmType {
    match s {
        "fixed_window" => AlgorithmType::FixedWindow,
        "sliding_window" => AlgorithmType::SlidingWindow,
        "token_bucket" => AlgorithmType::TokenBucket,
        _ => AlgorithmType::FixedWindow,
    }
}

#[cfg(feature = "grpc")]
fn rule_to_proto(rule: &crate::config::Rule) -> pb::Rule {
    pb::Rule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        description: rule.description.clone().unwrap_or_default(),
        rule_type: match rule.rule_type {
            crate::config::RuleType::Global => "global".to_string(),
            crate::config::RuleType::PathPrefix => "path_prefix".to_string(),
            crate::config::RuleType::IpBlacklist => "ip_blacklist".to_string(),
            crate::config::RuleType::IpWhitelist => "ip_whitelist".to_string(),
            crate::config::RuleType::IpGraylist => "ip_graylist".to_string(),
        },
        enabled: rule.enabled,
        priority: rule.priority,
        algorithm: Some(pb::AlgorithmConfig {
            algorithm: match rule.algorithm.algorithm {
                AlgorithmType::FixedWindow => "fixed_window".to_string(),
                AlgorithmType::SlidingWindow => "sliding_window".to_string(),
                AlgorithmType::TokenBucket => "token_bucket".to_string(),
            },
            limit: rule.algorithm.limit,
            window_size_seconds: rule.algorithm.window_size.as_secs(),
            warmup_period_seconds: rule.algorithm.warmup_period.map(|d| d.as_secs()),
            rate: rule.algorithm.rate,
            capacity: rule.algorithm.capacity,
        }),
        key_extractor: Some(pb::KeyExtractor {
            source: match rule.key_extractor.source {
                crate::key_extractor::KeySource::Header => "header".to_string(),
                crate::key_extractor::KeySource::Query => "query".to_string(),
                crate::key_extractor::KeySource::Body => "body".to_string(),
                crate::key_extractor::KeySource::Cookie => "cookie".to_string(),
                crate::key_extractor::KeySource::Ip => "ip".to_string(),
                crate::key_extractor::KeySource::Path => "path".to_string(),
                crate::key_extractor::KeySource::Global => "global".to_string(),
            },
            expression: rule.key_extractor.expression.clone(),
        }),
        path_prefix: rule.path_prefix.clone(),
        ip_list: rule.ip_list.clone().unwrap_or_default(),
        graylist_multiplier: rule.graylist_multiplier,
        group: rule.group.clone(),
        start_at: rule.start_at.map(|dt| dt.and_utc().timestamp()),
        end_at: rule.end_at.map(|dt| dt.and_utc().timestamp()),
    }
}

#[cfg(feature = "grpc")]
fn proto_to_rule(proto: &pb::Rule) -> crate::config::Rule {
    use crate::config::{Rule, RuleStats, RuleType};
    use crate::key_extractor::KeyExtractor;
    use crate::algorithm::AlgorithmConfig;
    use std::time::Duration;

    let algo = proto.algorithm.as_ref().unwrap();
    let key_ext = proto.key_extractor.as_ref().unwrap();

    Rule {
        id: proto.id.clone(),
        name: proto.name.clone(),
        description: if proto.description.is_empty() { None } else { Some(proto.description.clone()) },
        rule_type: match proto.rule_type.as_str() {
            "global" => RuleType::Global,
            "path_prefix" => RuleType::PathPrefix,
            "ip_blacklist" => RuleType::IpBlacklist,
            "ip_whitelist" => RuleType::IpWhitelist,
            "ip_graylist" => RuleType::IpGraylist,
            _ => RuleType::Global,
        },
        enabled: proto.enabled,
        priority: proto.priority,
        algorithm: AlgorithmConfig {
            algorithm: algorithm_from_str(&algo.algorithm),
            limit: algo.limit,
            window_size: Duration::from_secs(algo.window_size_seconds),
            warmup_period: algo.warmup_period_seconds.map(Duration::from_secs),
            rate: algo.rate,
            capacity: algo.capacity,
        },
        key_extractor: KeyExtractor {
            source: match key_ext.source.as_str() {
                "header" => crate::key_extractor::KeySource::Header,
                "query" => crate::key_extractor::KeySource::Query,
                "body" => crate::key_extractor::KeySource::Body,
                "cookie" => crate::key_extractor::KeySource::Cookie,
                "ip" => crate::key_extractor::KeySource::Ip,
                "path" => crate::key_extractor::KeySource::Path,
                "global" => crate::key_extractor::KeySource::Global,
                _ => crate::key_extractor::KeySource::Global,
            },
            expression: key_ext.expression.clone(),
        },
        path_prefix: proto.path_prefix.clone(),
        ip_list: if proto.ip_list.is_empty() { None } else { Some(proto.ip_list.clone()) },
        graylist_multiplier: proto.graylist_multiplier,
        group: proto.group.clone(),
        start_at: None,
        end_at: None,
        stats: RuleStats::default(),
    }
}

#[cfg(feature = "grpc")]
#[tonic::async_trait]
impl pb::rate_limit_service_server::RateLimitService for RateLimitServiceImpl {
    async fn check(&self, request: Request<pb::CheckRequest>) -> Result<Response<pb::CheckResponse>, Status> {
        let req = request.into_inner();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let rule = self.state.config_manager.get_rule(&req.rule_id)
            .ok_or_else(|| Status::not_found(format!("rule {} not found", req.rule_id)))?;

        let count = if req.count == 0 { 1 } else { req.count };
        let result = self.state.store.check(&rule.id, &req.key, count, &rule.algorithm, now_ms).await;

        self.state.config_manager.record_stat(&rule.id, result.allowed);

        let resp = pb::CheckResponse {
            allowed: result.allowed,
            remaining: result.remaining,
            reset_at: result.reset_at,
            retry_after_ms: result.retry_after.map(|d| d.as_millis() as u64),
        };

        Ok(Response::new(resp))
    }

    async fn get_rule(&self, request: Request<pb::GetRuleRequest>) -> Result<Response<pb::Rule>, Status> {
        let req = request.into_inner();
        let rule = self.state.config_manager.get_rule(&req.id)
            .ok_or_else(|| Status::not_found(format!("rule {} not found", req.id)))?;

        Ok(Response::new(rule_to_proto(&rule)))
    }

    async fn list_rules(&self, _request: Request<pb::ListRulesRequest>) -> Result<Response<pb::ListRulesResponse>, Status> {
        let rules = self.state.config_manager.get_all_rules();
        let proto_rules: Vec<pb::Rule> = rules.iter().map(|r| rule_to_proto(r)).collect();

        Ok(Response::new(pb::ListRulesResponse { rules: proto_rules }))
    }

    async fn create_rule(&self, request: Request<pb::CreateRuleRequest>) -> Result<Response<pb::Rule>, Status> {
        let req = request.into_inner();
        let rule_proto = req.rule.ok_or_else(|| Status::invalid_argument("rule is required"))?;

        let rule = proto_to_rule(&rule_proto);
        self.state.config_manager.add_rule(rule.clone())
            .map_err(|e| Status::already_exists(e.to_string()))?;

        Ok(Response::new(rule_to_proto(&rule)))
    }

    async fn update_rule(&self, request: Request<pb::UpdateRuleRequest>) -> Result<Response<pb::Rule>, Status> {
        let req = request.into_inner();
        let rule_proto = req.rule.ok_or_else(|| Status::invalid_argument("rule is required"))?;

        let mut rule = proto_to_rule(&rule_proto);
        rule.id = req.id.clone();

        self.state.config_manager.update_rule(&req.id, rule.clone())
            .map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(rule_to_proto(&rule)))
    }

    async fn delete_rule(&self, request: Request<pb::DeleteRuleRequest>) -> Result<Response<pb::DeleteRuleResponse>, Status> {
        let req = request.into_inner();
        let success = self.state.config_manager.delete_rule(&req.id).is_ok();

        Ok(Response::new(pb::DeleteRuleResponse { success }))
    }
}

#[cfg(feature = "grpc")]
pub async fn start_grpc_server(state: AppState, socket_path: &str) -> anyhow::Result<()> {
    use pb::rate_limit_service_server::RateLimitServiceServer;
    use tonic::transport::Server;

    let service = RateLimitServiceImpl::new(state);

    #[cfg(unix)]
    {
        use std::path::Path;
        let path = Path::new(socket_path);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let uds = tokio::net::UnixListener::bind(path)?;
        tracing::info!("gRPC server listening on {}", socket_path);

        Server::builder()
            .add_service(RateLimitServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(uds))
            .await
            .map_err(|e| anyhow::anyhow!("gRPC server error: {}", e))?;
    }

    #[cfg(not(unix))]
    {
        tracing::warn!("Unix domain socket not supported on this platform, falling back to TCP");
        let addr: std::net::SocketAddr = "127.0.0.1:50051".parse()?;
        tracing::info!("gRPC server listening on {}", addr);

        Server::builder()
            .add_service(RateLimitServiceServer::new(service))
            .serve(addr)
            .await
            .map_err(|e| anyhow::anyhow!("gRPC server error: {}", e))?;
    }

    Ok(())
}

#[cfg(not(feature = "grpc"))]
pub async fn start_grpc_server(_state: crate::api::AppState, _socket_path: &str) -> anyhow::Result<()> {
    Ok(())
}
