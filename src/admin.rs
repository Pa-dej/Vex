use std::path::PathBuf;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::backend::BackendHealth;
use crate::config::{AuthMode, Config};
use crate::protocol_map::ProtocolMap;
use crate::state::RuntimeState;

#[derive(Clone)]
pub struct AdminContext {
    pub state: RuntimeState,
    pub config_path: PathBuf,
}

pub async fn run_admin_server(ctx: AdminContext) -> anyhow::Result<()> {
    let bind_addr = ctx.state.snapshot().config.admin.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/reload", post(reload))
        .route("/auth/mode", post(set_auth_mode))
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

    ctx.state.apply_reload(cfg, map, backends).await;
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
