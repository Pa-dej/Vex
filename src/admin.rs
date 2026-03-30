use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use vex_proxy_sdk::api::CommandSender;
use vex_proxy_sdk::event::OnReload;

use crate::backend::BackendHealth;
use crate::config::{AuthMode, Config};
use crate::plugin_host::PluginHost;
use crate::protocol_map::ProtocolMap;
use crate::state::RuntimeState;

#[derive(Clone)]
pub struct AdminContext {
    pub state: RuntimeState,
    pub config_path: PathBuf,
    pub plugin_host: std::sync::Arc<tokio::sync::Mutex<PluginHost>>,
}

pub async fn run_admin_server(ctx: AdminContext) -> anyhow::Result<()> {
    let bind_addr = ctx.state.snapshot().config.admin.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/reload", post(reload))
        .route("/auth/mode", post(set_auth_mode))
        .route("/commands/{name}", post(execute_command))
        .route("/shutdown", post(shutdown))
        .with_state(ctx);
    info!("admin API listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz(State(ctx): State<AdminContext>) -> impl IntoResponse {
    let snapshot = ctx.state.snapshot();
    let mut backends = Vec::new();
    for backend in snapshot.backends.backends() {
        backends.push(BackendHealthView {
            name: backend.name().to_string(),
            address: backend.address().to_string(),
            state: match backend.health() {
                BackendHealth::Healthy => "healthy",
                BackendHealth::Degraded => "degraded",
                BackendHealth::Unhealthy => "unhealthy",
            }
            .to_string(),
            inflight: backend.inflight(),
        });
    }

    let auth_mode = ctx.state.auth_mode().await;
    let auth_mode = match auth_mode {
        AuthMode::Offline => "offline",
        AuthMode::Online => "online",
        AuthMode::Auto => "auto",
    };

    let resp = HealthResponse {
        status: "ok".to_string(),
        draining: ctx.state.shutdown.is_draining(),
        auth_mode: auth_mode.to_string(),
        backends,
    };
    (StatusCode::OK, Json(resp))
}

async fn metrics(State(ctx): State<AdminContext>) -> impl IntoResponse {
    match ctx.state.metrics.gather_text() {
        Ok(text) => (StatusCode::OK, text),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to gather metrics: {err}"),
        ),
    }
}

async fn reload(State(ctx): State<AdminContext>, headers: HeaderMap) -> impl IntoResponse {
    let snapshot = ctx.state.snapshot();
    if let Err(code) = verify_token(&headers, &snapshot.config.admin.auth_token) {
        return (code, "unauthorized".to_string());
    }
    let cfg = match Config::load_or_default(&ctx.config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("config reload validation failed: {err:#}"),
            );
        }
    };

    let protocol_path = PathBuf::from(&cfg.protocol_map.path);
    let map = match ProtocolMap::load(&protocol_path) {
        Ok(map) => map,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("protocol map reload validation failed: {err:#}"),
            );
        }
    };

    let backends =
        match crate::backend::BackendPool::from_config(&cfg.routing, ctx.state.metrics.clone()) {
            Ok(backends) => backends,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("routing reload validation failed: {err:#}"),
                );
            }
        };

    let plugins_enabled = cfg.plugins.enabled;
    ctx.state.apply_reload(cfg, map, backends).await;
    if plugins_enabled {
        let mut host = ctx.plugin_host.lock().await;
        match host.reload().await {
            Ok(loaded) => {
                ctx.state.plugin_runtime().set_active_plugins(loaded);
            }
            Err(err) => {
                ctx.state.plugin_runtime().set_active_plugins(0);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("plugin reload failed: {err:#}"),
                );
            }
        }
    } else {
        let mut host = ctx.plugin_host.lock().await;
        host.unload_all();
        ctx.state.plugin_runtime().set_active_plugins(0);
    }
    let _ = ctx
        .state
        .plugin_runtime()
        .events
        .dispatch(std::sync::Arc::new(OnReload {}))
        .await;
    info!("reload applied via arcswap snapshot swap");
    (StatusCode::OK, "reload applied atomically".to_string())
}

#[derive(Debug, Deserialize)]
struct AuthModeRequest {
    mode: String,
}

async fn set_auth_mode(
    State(ctx): State<AdminContext>,
    headers: HeaderMap,
    Json(req): Json<AuthModeRequest>,
) -> impl IntoResponse {
    let snapshot = ctx.state.snapshot();
    if let Err(code) = verify_token(&headers, &snapshot.config.admin.auth_token) {
        return (code, "unauthorized".to_string());
    }

    let parsed = match req.mode.as_str() {
        "offline" => AuthMode::Offline,
        "online" => AuthMode::Online,
        "auto" => AuthMode::Auto,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "mode must be one of: offline, online, auto".to_string(),
            );
        }
    };
    ctx.state.set_auth_mode(parsed).await;
    (StatusCode::OK, "auth mode updated".to_string())
}

async fn shutdown(State(ctx): State<AdminContext>, headers: HeaderMap) -> impl IntoResponse {
    let snapshot = ctx.state.snapshot();
    if let Err(code) = verify_token(&headers, &snapshot.config.admin.auth_token) {
        return (code, "unauthorized".to_string());
    }
    let message = snapshot.config.shutdown.disconnect_message.clone();
    if !ctx.state.shutdown.trigger(message.clone()) {
        return (
            StatusCode::ACCEPTED,
            "shutdown already in progress".to_string(),
        );
    }

    let drain = snapshot.config.shutdown.drain_seconds;
    let shutdown = ctx.state.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(drain)).await;
        if !shutdown.is_draining() {
            error!("unexpected shutdown state reset");
        }
    });

    (
        StatusCode::OK,
        format!("shutdown started with drain={}s", drain),
    )
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    #[serde(default)]
    args: Vec<String>,
}

async fn execute_command(
    State(ctx): State<AdminContext>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CommandRequest>,
) -> impl IntoResponse {
    let snapshot = ctx.state.snapshot();
    if let Err(code) = verify_token(&headers, &snapshot.config.admin.auth_token) {
        return (code, "unauthorized".to_string());
    }

    let commands = ctx.state.plugin_runtime().commands.clone();
    if commands.execute(&name, CommandSender::Console, req.args) {
        (StatusCode::OK, "command executed".to_string())
    } else {
        (StatusCode::NOT_FOUND, "command not found".to_string())
    }
}

fn verify_token(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let Some(actual) = headers.get("x-admin-token") else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(actual) = actual.to_str() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if actual == expected {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Debug, Serialize)]
struct BackendHealthView {
    name: String,
    address: String,
    state: String,
    inflight: usize,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    draining: bool,
    auth_mode: String,
    backends: Vec<BackendHealthView>,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::http::HeaderValue;
    use axum::response::IntoResponse;
    use tempfile::tempdir;
    use vex_proxy_sdk::api::MetricsHandle;

    use super::*;
    use crate::backend::BackendPool;
    use crate::config::BackendConfig;
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn reload_route_dispatches_on_reload_event() -> anyhow::Result<()> {
        let temp = tempdir()?;
        let plugin_dir = temp.path().join("plugins");
        std::fs::create_dir_all(&plugin_dir)?;
        let config_path = temp.path().join("vex.toml");
        std::fs::write(&config_path, "")?;

        let mut config = Config::default();
        config.admin.auth_token = "reload-token".to_string();
        config.plugins.enabled = true;
        config.plugins.dir = plugin_dir.to_string_lossy().to_string();
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: "127.0.0.1:25566".to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;

        let plugin_runtime = state.plugin_runtime();
        let plugin_host = Arc::new(tokio::sync::Mutex::new(PluginHost::new(
            plugin_dir,
            plugin_runtime.events.clone(),
            plugin_runtime.proxy.clone(),
            plugin_runtime.commands.clone(),
            state.metrics.registry(),
        )));

        let reload_calls = Arc::new(AtomicUsize::new(0));
        let reload_calls_handler = reload_calls.clone();
        plugin_runtime
            .events
            .with_plugin("test-reload")
            .on::<OnReload, _, _>(move |_event| {
                let reload_calls_handler = reload_calls_handler.clone();
                async move {
                    reload_calls_handler.fetch_add(1, Ordering::Relaxed);
                }
            });

        let ctx = AdminContext {
            state,
            config_path,
            plugin_host,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-token", HeaderValue::from_static("reload-token"));

        let response = super::reload(State(ctx), headers).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(reload_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn plugin_metrics_register_and_deregister_from_metrics_output() -> anyhow::Result<()> {
        let mut config = Config::default();
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: "127.0.0.1:25566".to_string(),
            weight: 1.0,
        }];
        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;

        let plugin_metrics = MetricsHandle::new(state.metrics.registry(), "metrics_plugin");
        let counter = plugin_metrics.register_counter(
            "players_greeted_total",
            "Total greeted players",
            &["source"],
        )?;
        counter.inc(&["login"]);

        let with_metric = state.metrics.gather_text()?;
        assert!(with_metric.contains("vex_plugin_metrics_plugin_players_greeted_total"));

        plugin_metrics.deregister_all();
        let without_metric = state.metrics.gather_text()?;
        assert!(!without_metric.contains("vex_plugin_metrics_plugin_players_greeted_total"));
        Ok(())
    }
}
