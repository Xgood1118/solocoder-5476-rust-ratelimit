mod algorithm;
mod store;
mod config;
mod api;
mod metrics;
mod key_extractor;
mod alert;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, env = "CONFIG_PATH", default_value = "./config.yaml")]
    config: PathBuf,

    #[arg(short, long, env = "PORT", default_value = "8080")]
    port: u16,

    #[arg(long, env = "GRPC_SOCKET_PATH", default_value = "/tmp/ratelimit.sock")]
    grpc_socket: String,

    #[arg(long, env = "ENABLE_GRPC", default_value = "true")]
    enable_grpc: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let cfg = config::Config::load(&args.config).await?;
    let store = store::Store::from_env().await?;
    let metrics = metrics::Metrics::new();

    let config_manager = config::ConfigManager::new(cfg, args.config.clone());
    config_manager.start_watcher().await?;

    let app_state = api::AppState {
        config_manager: config_manager.clone(),
        store: store.clone(),
        metrics: metrics.clone(),
    };

    let http_server = api::start_http_server(app_state.clone(), args.port);

    #[cfg(feature = "grpc")]
    let grpc_server = if args.enable_grpc {
        Some(api::start_grpc_server(app_state, &args.grpc_socket))
    } else {
        None
    };

    let alert_manager = alert::AlertManager::new(config_manager.clone());
    alert_manager.start().await;

    tokio::spawn(async move {
        if let Err(e) = background_stats_task(config_manager, store, metrics).await {
            tracing::error!("background stats task error: {}", e);
        }
    });

    tracing::info!("ratelimit service starting on port {}", args.port);

    #[cfg(feature = "grpc")]
    {
        if let Some(grpc) = grpc_server {
            tokio::try_join!(http_server, grpc)?;
        } else {
            http_server.await?;
        }
    }

    #[cfg(not(feature = "grpc"))]
    http_server.await?;

    Ok(())
}

async fn background_stats_task(
    _config_manager: config::ConfigManager,
    _store: store::Store,
    _metrics: metrics::Metrics,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
    loop {
        interval.tick().await;
        tracing::info!("running background stats aggregation");
    }
}
