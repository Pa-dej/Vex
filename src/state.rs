use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{RwLock, Semaphore};

use crate::auth_circuit::AuthCircuitBreaker;
use crate::backend::BackendPool;
use crate::config::{AuthMode, Config};
use crate::crypto::RsaKeyPair;
use crate::limiter::ConnectionLimiter;
use crate::memory::MemoryBudget;
use crate::metrics::Metrics;
use crate::protocol_map::ProtocolMap;
use crate::shutdown::ShutdownManager;

pub struct RuntimeSnapshot {
    pub config: Arc<Config>,
    pub protocol_map: Arc<ProtocolMap>,
    pub backends: Arc<BackendPool>,
}

impl RuntimeSnapshot {
    fn new(config: Config, protocol_map: ProtocolMap, backends: BackendPool) -> Self {
        Self {
            config: Arc::new(config),
            protocol_map: Arc::new(protocol_map),
            backends: Arc::new(backends),
        }
    }
}

#[derive(Clone)]
pub struct RuntimeState {
    snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
    pub metrics: Arc<Metrics>,
    pub shutdown: ShutdownManager,
    connection_slots: Arc<ArcSwap<Semaphore>>,
    memory_budget: Arc<ArcSwap<MemoryBudget>>,
    auth_mode: Arc<RwLock<AuthMode>>,
    crypto: Arc<RsaKeyPair>,
    auth_circuit: Arc<AuthCircuitBreaker>,
    mojang_client: Arc<reqwest::Client>,
    mojang_session_base_url: Arc<String>,
    limiter: Arc<ConnectionLimiter>,
}

impl RuntimeState {
    pub fn new(
        config: Config,
        protocol_map: ProtocolMap,
        metrics: Arc<Metrics>,
        backends: BackendPool,
    ) -> anyhow::Result<Self> {
        let max_connections = config.limits.max_connections;
        let memory_budget = MemoryBudget::new(
            config.limits.global_memory_budget_bytes,
            config.limits.per_connection_cap_bytes,
        );
        let mojang_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(750))
            .timeout(Duration::from_secs(2))
            .build()?;
        let mojang_session_base_url = std::env::var("VEX_MOJANG_SESSION_BASE_URL")
            .unwrap_or_else(|_| "https://sessionserver.mojang.com".to_string());
        Ok(Self {
            snapshot: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot::new(
                config.clone(),
                protocol_map,
                backends,
            ))),
            metrics,
            shutdown: ShutdownManager::new(),
            connection_slots: Arc::new(ArcSwap::from_pointee(Semaphore::new(max_connections))),
            memory_budget: Arc::new(ArcSwap::from_pointee(memory_budget)),
            auth_mode: Arc::new(RwLock::new(config.auth.mode)),
            crypto: Arc::new(RsaKeyPair::generate()?),
            auth_circuit: Arc::new(AuthCircuitBreaker::default()),
            mojang_client: Arc::new(mojang_client),
            mojang_session_base_url: Arc::new(mojang_session_base_url),
            limiter: Arc::new(ConnectionLimiter::new(
                config.limits.max_connections_total,
                config.limits.per_ip_rate_limit,
                config.limits.per_subnet_rate_limit,
            )),
        })
    }

    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.snapshot.load_full()
    }

    pub fn connection_slots(&self) -> Arc<Semaphore> {
        self.connection_slots.load_full()
    }

    pub fn memory_budget(&self) -> Arc<MemoryBudget> {
        self.memory_budget.load_full()
    }

    pub async fn auth_mode(&self) -> AuthMode {
        self.auth_mode.read().await.clone()
    }

    pub async fn set_auth_mode(&self, mode: AuthMode) {
        *self.auth_mode.write().await = mode;
    }

    pub fn crypto(&self) -> Arc<RsaKeyPair> {
        self.crypto.clone()
    }

    pub fn auth_circuit(&self) -> Arc<AuthCircuitBreaker> {
        self.auth_circuit.clone()
    }

    pub fn mojang_client(&self) -> Arc<reqwest::Client> {
        self.mojang_client.clone()
    }

    pub fn mojang_session_base_url(&self) -> Arc<String> {
        self.mojang_session_base_url.clone()
    }

    pub fn limiter(&self) -> Arc<ConnectionLimiter> {
        self.limiter.clone()
    }

    pub async fn apply_reload(
        &self,
        config: Config,
        protocol_map: ProtocolMap,
        backends: BackendPool,
    ) {
        self.connection_slots
            .store(Arc::new(Semaphore::new(config.limits.max_connections)));
        self.memory_budget.store(Arc::new(MemoryBudget::new(
            config.limits.global_memory_budget_bytes,
            config.limits.per_connection_cap_bytes,
        )));
        self.snapshot.store(Arc::new(RuntimeSnapshot::new(
            config.clone(),
            protocol_map,
            backends,
        )));
        self.set_auth_mode(config.auth.mode).await;
    }
}
