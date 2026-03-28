use std::sync::Arc;

use tokio::sync::{RwLock, Semaphore};

use crate::backend::BackendPool;
use crate::config::{AuthMode, Config};
use crate::memory::MemoryBudget;
use crate::metrics::Metrics;
use crate::protocol_map::ProtocolMap;
use crate::shutdown::ShutdownManager;

#[derive(Clone)]
pub struct RuntimeState {
    pub config: Arc<Config>,
    pub protocol_map: Arc<ProtocolMap>,
    pub metrics: Arc<Metrics>,
    pub backends: BackendPool,
    pub shutdown: ShutdownManager,
    pub connection_slots: Arc<Semaphore>,
    pub memory_budget: MemoryBudget,
    auth_mode: Arc<RwLock<AuthMode>>,
}

impl RuntimeState {
    pub fn new(
        config: Arc<Config>,
        protocol_map: Arc<ProtocolMap>,
        metrics: Arc<Metrics>,
        backends: BackendPool,
    ) -> Self {
        let connection_slots = Arc::new(Semaphore::new(config.limits.max_connections));
        let memory_budget = MemoryBudget::new(
            config.limits.global_memory_budget_bytes,
            config.limits.per_connection_cap_bytes,
        );
        Self {
            auth_mode: Arc::new(RwLock::new(config.auth.mode.clone())),
            config,
            protocol_map,
            metrics,
            backends,
            shutdown: ShutdownManager::new(),
            connection_slots,
            memory_budget,
        }
    }

    pub async fn auth_mode(&self) -> AuthMode {
        self.auth_mode.read().await.clone()
    }

    pub async fn set_auth_mode(&self, mode: AuthMode) {
        *self.auth_mode.write().await = mode;
    }
}
