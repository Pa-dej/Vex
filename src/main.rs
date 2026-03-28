mod admin;
mod backend;
mod config;
mod health;
mod mc;
mod memory;
mod metrics;
mod protocol_map;
mod server;
mod shutdown;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::admin::{AdminContext, run_admin_server};
use crate::backend::BackendPool;
use crate::config::Config;
use crate::health::spawn_health_checker;
use crate::metrics::Metrics;
use crate::protocol_map::ProtocolMap;
use crate::server::run_proxy_server;
use crate::state::RuntimeState;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from("vex.toml");
    let config = Config::load_or_default(&config_path)?;
    init_tracing(&config.observability.log_level);

    let protocol_map_path = PathBuf::from(&config.protocol_map.path);
    let protocol_map = ProtocolMap::load(&protocol_map_path).with_context(|| {
        format!(
            "failed loading protocol map from {}",
            protocol_map_path.display()
        )
    })?;

    let metrics = Arc::new(Metrics::new()?);
    let backends = BackendPool::from_config(&config.routing, metrics.clone())?;

    let state = RuntimeState::new(
        Arc::new(config.clone()),
        Arc::new(protocol_map),
        metrics,
        backends,
    );

    spawn_health_checker(state.clone());

    let admin_ctx = AdminContext {
        state: state.clone(),
        config_path: config_path.clone(),
        protocol_map_path: protocol_map_path.clone(),
    };
    tokio::spawn(async move {
        if let Err(err) = run_admin_server(admin_ctx).await {
            error!("admin server failed: {err:#}");
        }
    });

    let shutdown_state = state.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("ctrl-c received, initiating graceful shutdown");
            shutdown_state
                .shutdown
                .trigger(shutdown_state.config.shutdown.disconnect_message.clone());
        }
    });

    run_proxy_server(state).await
}

fn init_tracing(default_level: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default_level.to_string());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .compact()
        .init();
}
