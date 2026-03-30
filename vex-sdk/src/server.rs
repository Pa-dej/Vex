//! Backend/server references used by plugins.

use std::sync::Arc;

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
