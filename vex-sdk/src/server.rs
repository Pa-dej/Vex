//! Backend/server references used by plugins.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::player::ProxiedPlayer;

/// Backend health state as observed by the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    /// Backend responds normally.
    Healthy,
    /// Backend is reachable but degraded.
    Degraded,
    /// Backend is currently unhealthy/unreachable.
    Unhealthy,
}

/// Immutable backend metadata exposed to plugins.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Backend logical name.
    pub name: Arc<str>,
    /// Backend network address.
    pub address: Arc<str>,
    /// Health hint snapshot.
    pub healthy: bool,
}

impl BackendInfo {
    /// Creates backend info.
    pub fn new(name: impl Into<Arc<str>>, address: impl Into<Arc<str>>, healthy: bool) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            healthy,
        }
    }
}

/// Cheap cloneable backend handle.
#[derive(Debug, Clone)]
pub struct BackendRef {
    inner: Arc<BackendInfo>,
}

impl BackendRef {
    /// Creates a reference wrapper around backend info.
    pub fn new(info: BackendInfo) -> Self {
        Self {
            inner: Arc::new(info),
        }
    }

    /// Returns backend name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Returns backend address.
    pub fn address(&self) -> &str {
        &self.inner.address
    }

    /// Returns backend health flag.
    pub fn is_healthy(&self) -> bool {
        self.inner.healthy
    }

    /// Returns immutable backend info.
    pub fn as_info(&self) -> &BackendInfo {
        &self.inner
    }
}

/// Cluster node information advertised through Redis.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    /// Unique node identifier.
    pub node_id: String,
    /// Listener bind address.
    pub bind_addr: String,
    /// Current online players on this node.
    pub online_players: u32,
    /// Startup timestamp (unix seconds).
    pub started_at: u64,
    /// Running Vex version.
    pub version: String,
}

/// Player representation used for cross-node session sync.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemotePlayerInfo {
    /// Player UUID.
    pub uuid: Uuid,
    /// Username snapshot.
    pub username: String,
    /// Node identifier where player is connected.
    pub node_id: String,
    /// Backend name.
    pub backend: String,
    /// Session start timestamp (unix seconds).
    pub connected_at: u64,
}

/// Local or remote player abstraction used by cluster-aware APIs.
#[derive(Clone, Debug)]
pub enum AnyPlayerInfo {
    /// Player connected to the current node.
    Local(ProxiedPlayer),
    /// Player connected to another node.
    Remote(RemotePlayerInfo),
}
