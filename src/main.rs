mod admin;
mod analytics;
mod auth_circuit;
mod backend;
mod config;
mod crypto;
mod event_bus;
mod health;
mod limiter;
mod mc;
mod memory;
mod metrics;
mod plugin_host;
mod protocol_map;
mod reputation;
mod server;
mod session_registry;
mod shutdown;
mod state;
mod telemetry;
mod transfer;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};

use crate::admin::{AdminContext, run_admin_server};
use crate::backend::BackendPool;
use crate::config::Config;
use crate::health::spawn_health_checker;
use crate::metrics::Metrics;
use crate::plugin_host::{PluginHost, spawn_plugin_watcher};
use crate::protocol_map::ProtocolMap;
use crate::server::run_proxy_server;
use crate::state::RuntimeState;
use crate::telemetry::init_tracing;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from("vex.toml");
    let config = Config::load_or_default(&config_path)?;
    init_tracing(
        &config.observability.log_level,
        config.observability.log_format,
    );

    let protocol_map_path = PathBuf::from(&config.protocol_map.path);
    let protocol_map = ProtocolMap::load(&protocol_map_path).with_context(|| {
        format!(
            "failed loading protocol map from {}",
            protocol_map_path.display()
        )
    })?;

    let metrics = Arc::new(Metrics::new()?);
    metrics.spawn_runtime_sampler();
    for version in protocol_map.versions().keys() {
        metrics.init_protocol_version_label(version);
    }
    let backends = BackendPool::from_config(&config.routing, metrics.clone())?;

    let state = RuntimeState::new(config.clone(), protocol_map, metrics, backends)?;
    let _reputation_maintenance_task = state.reputation().spawn_maintenance_task();

    let plugin_runtime = state.plugin_runtime();
    let plugin_host = Arc::new(tokio::sync::Mutex::new(PluginHost::new(
        state.snapshot().config.plugins.dir.clone(),
        plugin_runtime.events.clone(),
        plugin_runtime.proxy.clone(),
        plugin_runtime.commands.clone(),
        state.metrics.registry(),
    )));
    if state.snapshot().config.plugins.enabled {
        let mut host = plugin_host.lock().await;
        match host.load_all() {
            Ok(loaded) => {
                plugin_runtime.set_active_plugins(loaded);
                info!("plugin host loaded {} plugin(s)", loaded);
            }
            Err(err) => {
                plugin_runtime.set_active_plugins(0);
                error!("plugin host failed to load plugins: {err:#}");
            }
        }
    } else {
        plugin_runtime.set_active_plugins(0);
    }

    if state.snapshot().config.plugins.enabled && state.snapshot().config.plugins.watch {
        let debounce = Duration::from_millis(state.snapshot().config.plugins.watch_debounce_ms);
        if let Err(err) = spawn_plugin_watcher(
            PathBuf::from(state.snapshot().config.plugins.dir.clone()),
            plugin_host.clone(),
            plugin_runtime.active_plugins_counter(),
            debounce,
        ) {
            error!("plugin watcher failed to start: {err:#}");
        } else {
            info!(
                debounce_ms = state.snapshot().config.plugins.watch_debounce_ms,
                "plugin watcher enabled"
            );
        }
    }

    spawn_health_checker(state.clone());

    let admin_ctx = AdminContext {
        state: state.clone(),
        config_path: config_path.clone(),
        plugin_host: plugin_host.clone(),
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
            let snapshot = shutdown_state.snapshot();
            shutdown_state
                .shutdown
                .trigger(snapshot.config.shutdown.disconnect_message.clone());
        }
    });

    run_proxy_server(state).await
}
