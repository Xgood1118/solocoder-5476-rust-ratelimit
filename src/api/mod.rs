pub mod handlers;
pub mod matcher;
pub mod grpc;

use crate::config::ConfigManager;
use crate::metrics::Metrics;
use crate::store::Store;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config_manager: ConfigManager,
    pub store: Store,
    pub metrics: Metrics,
}

pub async fn start_http_server(state: AppState, port: u16) -> anyhow::Result<()> {
    use axum::{
        routing::{get, post, put, delete},
        Router,
    };
    use tower_http::cors::{CorsLayer, Any};

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .route("/metrics", get(handlers::metrics))
        .route("/api/check", post(handlers::check))
        .route("/api/rules", get(handlers::list_rules))
        .route("/api/rules", post(handlers::create_rule))
        .route("/api/rules/stats", get(handlers::rules_stats))
        .route("/api/rules/:id", get(handlers::get_rule))
        .route("/api/rules/:id", put(handlers::update_rule))
        .route("/api/rules/:id", delete(handlers::delete_rule))
        .route("/api/rules/import", post(handlers::import_rules))
        .route("/api/rules/export", get(handlers::export_rules))
        .route("/api/templates", get(handlers::list_templates))
        .route("/api/groups", get(handlers::list_groups))
        .route("/admin", get(handlers::admin_index))
        .route("/admin/", get(handlers::admin_index))
        .route("/admin/*path", get(handlers::admin_static))
        .with_state(Arc::new(state))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("HTTP server listening on port {}", port);

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("server error: {}", e))?;

    Ok(())
}

pub async fn start_grpc_server(state: AppState, socket_path: &str) -> anyhow::Result<()> {
    grpc::start_grpc_server(state, socket_path).await
}
