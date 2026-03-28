use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listener: ListenerConfig,
    pub routing: RoutingConfig,
    pub auth: AuthConfig,
    pub limits: LimitsConfig,
    pub health: HealthConfig,
    pub observability: ObservabilityConfig,
    pub admin: AdminConfig,
    pub shutdown: ShutdownConfig,
    pub protocol_map: ProtocolMapConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listener: ListenerConfig::default(),
            routing: RoutingConfig::default(),
            auth: AuthConfig::default(),
            limits: LimitsConfig::default(),
            health: HealthConfig::default(),
            observability: ObservabilityConfig::default(),
            admin: AdminConfig::default(),
            shutdown: ShutdownConfig::default(),
            protocol_map: ProtocolMapConfig::default(),
        }
    }
}

impl Config {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ListenerConfig {
    pub bind: String,
    pub max_packet_size: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:25565".to_string(),
            max_packet_size: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub backends: Vec<BackendConfig>,
    pub allow_degraded: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            backends: vec![BackendConfig {
                name: "default".to_string(),
                address: "127.0.0.1:25566".to_string(),
                weight: 1.0,
            }],
            allow_degraded: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Offline,
    Online,
    Auto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub mode: AuthMode,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Offline,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_connections: usize,
    pub initial_buffer_bytes: usize,
    pub per_connection_cap_bytes: usize,
    pub global_memory_budget_bytes: usize,
    pub handshake_timeout_ms: u64,
    pub login_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 100_000,
            initial_buffer_bytes: 1024,
            per_connection_cap_bytes: 64 * 1024,
            global_memory_budget_bytes: 2 * 1024 * 1024 * 1024,
            handshake_timeout_ms: 2_000,
            login_timeout_ms: 4_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthConfig {
    pub interval_ms: u64,
    pub status_timeout_ms: u64,
    pub tcp_timeout_ms: u64,
    pub unhealthy_fail_threshold: u32,
    pub recovery_success_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval_ms: 2000,
            status_timeout_ms: 1000,
            tcp_timeout_ms: 500,
            unhealthy_fail_threshold: 3,
            recovery_success_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ObservabilityConfig {
    pub log_level: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    pub bind: String,
    pub auth_token: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            auth_token: "change-me".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ShutdownConfig {
    pub drain_seconds: u64,
    pub disconnect_message: String,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_seconds: 20,
            disconnect_message: "Proxy is restarting, reconnect in a few seconds.".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtocolMapConfig {
    pub path: String,
}

impl Default for ProtocolMapConfig {
    fn default() -> Self {
        Self {
            path: "config/protocol_ids.toml".to_string(),
        }
    }
}
