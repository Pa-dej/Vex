use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use anyhow::{Result, bail};

use crate::config::{BackendConfig, RoutingConfig};
use crate::metrics::Metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

impl BackendHealth {
    pub fn encoded(self) -> i64 {
        match self {
            BackendHealth::Healthy => 2,
            BackendHealth::Degraded => 1,
            BackendHealth::Unhealthy => 0,
        }
    }
}

#[derive(Debug)]
pub struct Backend {
    name: String,
    address: String,
    weight: f64,
    inflight: AtomicUsize,
    health: RwLock<BackendHealth>,
    consecutive_failures: AtomicU32,
    consecutive_successes: AtomicU32,
}

impl Backend {
    pub fn from_config(cfg: &BackendConfig) -> Result<Self> {
        if cfg.weight <= 0.0 {
            bail!(
                "backend {} has non-positive weight {}",
                cfg.name,
                cfg.weight
            );
        }
        Ok(Self {
            name: cfg.name.clone(),
            address: cfg.address.clone(),
            weight: cfg.weight,
            inflight: AtomicUsize::new(0),
            health: RwLock::new(BackendHealth::Healthy),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn score(&self) -> f64 {
        let inflight = self.inflight.load(Ordering::Relaxed) as f64;
        inflight / self.weight
    }

    pub fn health(&self) -> BackendHealth {
        *self
            .health
            .read()
            .expect("backend health lock poisoned while reading")
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn record_probe(
        &self,
        status_ok: bool,
        tcp_ok: bool,
        unhealthy_fail_threshold: u32,
        recovery_success_threshold: u32,
    ) -> BackendHealth {
        if status_ok {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
            if successes >= recovery_success_threshold {
                self.set_health(BackendHealth::Healthy);
            }
            return self.health();
        }

        self.consecutive_successes.store(0, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if !tcp_ok || fails >= unhealthy_fail_threshold {
            self.set_health(BackendHealth::Unhealthy);
            return BackendHealth::Unhealthy;
        }

        self.set_health(BackendHealth::Degraded);
        BackendHealth::Degraded
    }

    fn set_health(&self, new_state: BackendHealth) {
        let mut guard = self
            .health
            .write()
            .expect("backend health lock poisoned while writing");
        *guard = new_state;
    }
}

#[derive(Clone)]
pub struct BackendPool {
    backends: Vec<Arc<Backend>>,
    allow_degraded: bool,
    metrics: Arc<Metrics>,
}

impl BackendPool {
    pub fn from_config(routing: &RoutingConfig, metrics: Arc<Metrics>) -> Result<Self> {
        if routing.backends.is_empty() {
            bail!("at least one backend is required");
        }
        let mut backends = Vec::with_capacity(routing.backends.len());
        for cfg in &routing.backends {
            let backend = Arc::new(Backend::from_config(cfg)?);
            metrics.init_backend_labels(backend.name());
            metrics.set_backend_health_state(backend.name(), BackendHealth::Healthy.encoded());
            metrics.set_backend_inflight(backend.name(), 0);
            backends.push(backend);
        }
        Ok(Self {
            backends,
            allow_degraded: routing.allow_degraded,
            metrics,
        })
    }

    pub fn choose_backend(&self) -> Option<BackendLease> {
        let mut best_healthy: Option<Arc<Backend>> = None;
        let mut best_healthy_score = f64::MAX;
        let mut best_degraded: Option<Arc<Backend>> = None;
        let mut best_degraded_score = f64::MAX;

        for backend in &self.backends {
            let score = backend.score();
            match backend.health() {
                BackendHealth::Healthy if score < best_healthy_score => {
                    best_healthy_score = score;
                    best_healthy = Some(backend.clone());
                }
                BackendHealth::Degraded if score < best_degraded_score => {
                    best_degraded_score = score;
                    best_degraded = Some(backend.clone());
                }
                _ => {}
            }
        }

        let selected = if let Some(healthy) = best_healthy {
            Some(healthy)
        } else if self.allow_degraded {
            best_degraded
        } else {
            None
        }?;

        let now = selected.inflight.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics
            .set_backend_inflight(selected.name(), now as i64);

        Some(BackendLease {
            backend: selected,
            metrics: self.metrics.clone(),
        })
    }

    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}

pub struct BackendLease {
    backend: Arc<Backend>,
    metrics: Arc<Metrics>,
}

impl BackendLease {
    pub fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        let prev = self.backend.inflight.fetch_sub(1, Ordering::Relaxed);
        let now = prev.saturating_sub(1);
        self.metrics
            .set_backend_inflight(self.backend.name(), now as i64);
    }
}
