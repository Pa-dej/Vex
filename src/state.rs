use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;
use vex_proxy_sdk::api::{CommandRegistry, EventBus, ProxyHandle, ProxyOps};
use vex_proxy_sdk::event::OnPermissionCheck;
use vex_proxy_sdk::player::ProxiedPlayer;
use vex_proxy_sdk::server::{BackendInfo, BackendRef};

use crate::analytics::AttackAnalytics;
use crate::auth_circuit::AuthCircuitBreaker;
use crate::backend::BackendPool;
use crate::config::{AuthMode, Config};
use crate::crypto::RsaKeyPair;
use crate::limiter::ConnectionLimiter;
use crate::memory::MemoryBudget;
use crate::metrics::Metrics;
use crate::protocol_map::ProtocolMap;
use crate::reputation::ReputationStore;
use crate::session_registry::SessionRegistry;
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
    reputation: Arc<ReputationStore>,
    attack_analytics: Arc<AttackAnalytics>,
    plugin_runtime: Arc<PluginRuntime>,
}

#[derive(Clone)]
pub struct PluginRuntime {
    pub events: Arc<EventBus>,
    pub commands: Arc<CommandRegistry>,
    pub proxy: Arc<ProxyHandle>,
    pub sessions: Arc<SessionRegistry>,
    active_plugins: Arc<AtomicUsize>,
}

impl PluginRuntime {
    pub fn active_plugins(&self) -> usize {
        self.active_plugins.load(Ordering::Relaxed)
    }

    pub fn has_active_plugins(&self) -> bool {
        self.active_plugins() > 0
    }

    pub fn set_active_plugins(&self, count: usize) {
        self.active_plugins.store(count, Ordering::Relaxed);
    }

    pub fn active_plugins_counter(&self) -> Arc<AtomicUsize> {
        self.active_plugins.clone()
    }
}

struct RuntimeProxyOps {
    snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
    sessions: Arc<SessionRegistry>,
}

impl ProxyOps for RuntimeProxyOps {
    fn get_players(&self) -> Vec<ProxiedPlayer> {
        self.sessions.get_players()
    }

    fn get_player(&self, username: &str) -> Option<ProxiedPlayer> {
        self.sessions.get_player(username)
    }

    fn get_player_by_uuid(&self, uuid: Uuid) -> Option<ProxiedPlayer> {
        self.sessions.get_player_by_uuid(uuid)
    }

    fn get_backends(&self) -> Vec<BackendRef> {
        let snapshot = self.snapshot.load_full();
        snapshot
            .backends
            .backends()
            .iter()
            .map(|backend| {
                BackendRef::new(BackendInfo::new(
                    backend.name().to_string(),
                    backend.address().to_string(),
                    backend.health() != crate::backend::BackendHealth::Unhealthy,
                ))
            })
            .collect()
    }

    fn broadcast(&self, message: &str) {
        self.sessions.broadcast(message);
    }

    fn broadcast_to(&self, message: &str, filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync)) {
        self.sessions.broadcast_to(message, filter);
    }

    fn online_count(&self) -> usize {
        self.sessions.online_count()
    }

    fn online_count_for(&self, backend: &BackendRef) -> usize {
        self.sessions.online_count_for(backend)
    }

    fn forward_plugin_message(
        &self,
        channel: &str,
        data: bytes::Bytes,
        filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync),
    ) {
        self.sessions.forward_plugin_message(channel, data, filter);
    }
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
        let reputation = Arc::new(ReputationStore::new(config.reputation.clone()));
        let attack_analytics = Arc::new(AttackAnalytics::new(config.anti_bot.clone()));
        let snapshot = Arc::new(ArcSwap::from_pointee(RuntimeSnapshot::new(
            config.clone(),
            protocol_map,
            backends,
        )));
        let sessions = Arc::new(SessionRegistry::new());
        let events = Arc::new(EventBus::new(Duration::from_millis(
            config.plugins.event_handler_timeout_ms,
        )));
        let commands = Arc::new(CommandRegistry::new());
        let permission_events = events.clone();
        commands.set_permission_checker(move |player, permission| {
            let event = Arc::new(OnPermissionCheck::new(
                player.clone(),
                permission.to_string(),
                true,
            ));
            let dispatch_events = permission_events.clone();
            let dispatch_event = event.clone();
            let join = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(runtime) = runtime {
                    runtime.block_on(async move {
                        let _ = dispatch_events.dispatch(dispatch_event).await;
                    });
                }
            });
            let _ = join.join();
            event.is_allowed()
        });
        let proxy = Arc::new(ProxyHandle::new(Arc::new(RuntimeProxyOps {
            snapshot: snapshot.clone(),
            sessions: sessions.clone(),
        })));
        let plugin_runtime = Arc::new(PluginRuntime {
            events,
            commands,
            proxy,
            sessions,
            active_plugins: Arc::new(AtomicUsize::new(0)),
        });

        Ok(Self {
            snapshot,
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
            reputation,
            attack_analytics,
            plugin_runtime,
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

    pub fn reputation(&self) -> Arc<ReputationStore> {
        self.reputation.clone()
    }

    pub fn attack_analytics(&self) -> Arc<AttackAnalytics> {
        self.attack_analytics.clone()
    }

    pub fn plugin_runtime(&self) -> Arc<PluginRuntime> {
        self.plugin_runtime.clone()
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
        self.plugin_runtime
            .events
            .set_timeout(Duration::from_millis(
                config.plugins.event_handler_timeout_ms,
            ));
    }
}
