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
    pub forwarding: ForwardingConfig,
    pub limits: LimitsConfig,
    pub anti_bot: AntiBotConfig,
    pub reputation: ReputationConfig,
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
            forwarding: ForwardingConfig::default(),
            limits: LimitsConfig::default(),
            anti_bot: AntiBotConfig::default(),
            reputation: ReputationConfig::default(),
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
pub struct ForwardingConfig {
    pub velocity: VelocityForwardingConfig,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            velocity: VelocityForwardingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VelocityForwardingConfig {
    pub enabled: bool,
    pub secret: String,
}

impl Default for VelocityForwardingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_connections: usize,
    pub max_connections_total: u32,
    pub per_ip_rate_limit: u32,
    pub per_subnet_rate_limit: u32,
    pub initial_buffer_bytes: usize,
    pub per_connection_cap_bytes: usize,
    pub global_memory_budget_bytes: usize,
    pub handshake_timeout_ms: u64,
    pub login_timeout_ms: u64,
    pub max_packet_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 100_000,
            max_connections_total: 10_000,
            per_ip_rate_limit: 20,
            per_subnet_rate_limit: 50,
            initial_buffer_bytes: 1024,
            per_connection_cap_bytes: 64 * 1024,
            global_memory_budget_bytes: 2 * 1024 * 1024 * 1024,
            handshake_timeout_ms: 2_000,
            login_timeout_ms: 4_000,
            max_packet_size: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AntiBotConfig {
    pub enabled: bool,
    pub attack_cps_threshold: u32,
    pub attack_login_fail_ratio: f64,
    pub attack_unique_ip_threshold: usize,
}

impl Default for AntiBotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            attack_cps_threshold: 100,
            attack_login_fail_ratio: 0.5,
            attack_unique_ip_threshold: 500,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReputationConfig {
    pub enabled: bool,
    pub decay_interval_secs: u64,
    pub cleanup_timeout_secs: u64,
    pub block_duration_first_secs: u64,
    pub block_duration_second_secs: u64,
    pub block_duration_max_secs: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decay_interval_secs: 60,
            cleanup_timeout_secs: 600,
            block_duration_first_secs: 30,
            block_duration_second_secs: 120,
            block_duration_max_secs: 600,
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
    pub log_format: LogFormat,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_format: LogFormat::Pretty,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
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
