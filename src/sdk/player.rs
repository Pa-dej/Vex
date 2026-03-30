use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use uuid::Uuid;

use crate::meta::PlayerMeta;
use crate::server::BackendRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    Success,
    BackendUnreachable,
    BackendUnhealthy,
    PlayerDisconnected,
    Timeout,
}

pub type DisconnectHook = Arc<dyn Fn(Uuid, &str) + Send + Sync>;
pub type PluginMessageHook = Arc<dyn Fn(Uuid, &str, Bytes) + Send + Sync>;
pub type TransferHook = Arc<dyn Fn(Uuid, BackendRef) -> TransferResult + Send + Sync>;
pub type CurrentBackendHook = Arc<dyn Fn(Uuid) -> Option<BackendRef> + Send + Sync>;
pub type LatencyHook = Arc<dyn Fn(Uuid) -> u32 + Send + Sync>;

#[derive(Clone)]
pub struct PlayerHooks {
    pub disconnect: DisconnectHook,
    pub send_plugin_message: PluginMessageHook,
    pub transfer: TransferHook,
    pub current_backend: CurrentBackendHook,
    pub latency_ms: LatencyHook,
}

impl Default for PlayerHooks {
    fn default() -> Self {
        Self {
            disconnect: Arc::new(|_, _| {}),
            send_plugin_message: Arc::new(|_, _, _| {}),
            transfer: Arc::new(|_, _| TransferResult::PlayerDisconnected),
            current_backend: Arc::new(|_| None),
            latency_ms: Arc::new(|_| 0),
        }
    }
}

#[derive(Clone)]
pub struct ProxiedPlayer {
    pub uuid: Uuid,
    pub username: Arc<str>,
    pub address: SocketAddr,
    pub protocol_version: u32,
    hooks: PlayerHooks,
    meta: PlayerMeta,
}

impl std::fmt::Debug for ProxiedPlayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxiedPlayer")
            .field("uuid", &self.uuid)
            .field("username", &self.username)
            .field("address", &self.address)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

pub type PlayerRef = Arc<ProxiedPlayer>;

impl ProxiedPlayer {
    pub fn new(
        uuid: Uuid,
        username: impl Into<Arc<str>>,
        address: SocketAddr,
        protocol_version: u32,
        hooks: PlayerHooks,
        meta: PlayerMeta,
    ) -> Self {
        Self {
            uuid,
            username: username.into(),
            address,
            protocol_version,
            hooks,
            meta,
        }
    }

    pub fn disconnect(&self, reason: &str) {
        (self.hooks.disconnect)(self.uuid, reason);
    }

    pub fn send_plugin_message(&self, channel: &str, data: Bytes) {
        (self.hooks.send_plugin_message)(self.uuid, channel, data);
    }

    pub fn transfer(&self, backend: BackendRef) -> TransferResult {
        (self.hooks.transfer)(self.uuid, backend)
    }

    pub fn get_meta<T: Clone + Send + Sync + 'static>(&self, key: &str) -> Option<T> {
        self.meta.get(key)
    }

    pub fn set_meta<T: Clone + Send + Sync + 'static>(&self, key: &str, value: T) {
        self.meta.set(key, value);
    }

    pub fn remove_meta(&self, key: &str) {
        self.meta.remove(key);
    }

    pub fn has_meta(&self, key: &str) -> bool {
        self.meta.has(key)
    }

    pub fn current_backend(&self) -> Option<BackendRef> {
        (self.hooks.current_backend)(self.uuid)
    }

    pub fn latency_ms(&self) -> u32 {
        (self.hooks.latency_ms)(self.uuid)
    }
}
