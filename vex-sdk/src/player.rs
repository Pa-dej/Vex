//! Player-facing API types.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use uuid::Uuid;

use crate::meta::PlayerMeta;
use crate::server::BackendRef;

/// Result of a backend transfer attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferResult {
    /// Transfer completed successfully.
    Success,
    /// Target backend could not be reached.
    BackendUnreachable,
    /// Target backend is currently unhealthy.
    BackendUnhealthy,
    /// Player disconnected during transfer.
    PlayerDisconnected,
    /// Transfer exceeded deadline.
    Timeout,
}

/// Hook used by [`ProxiedPlayer::disconnect`].
pub type DisconnectHook = Arc<dyn Fn(Uuid, &str) + Send + Sync>;
/// Hook used by [`ProxiedPlayer::send_plugin_message`].
pub type PluginMessageHook = Arc<dyn Fn(Uuid, &str, Bytes) + Send + Sync>;
/// Hook used by [`ProxiedPlayer::transfer`].
pub type TransferHook = Arc<dyn Fn(Uuid, BackendRef) -> TransferResult + Send + Sync>;
/// Hook used by [`ProxiedPlayer::current_backend`].
pub type CurrentBackendHook = Arc<dyn Fn(Uuid) -> Option<BackendRef> + Send + Sync>;
/// Hook used by [`ProxiedPlayer::latency_ms`].
pub type LatencyHook = Arc<dyn Fn(Uuid) -> u32 + Send + Sync>;
/// Hook used by [`ProxiedPlayer::set_tab_list`].
pub type TabListHook = Arc<dyn Fn(Uuid, &str, &str) + Send + Sync>;
/// Hook used by [`ProxiedPlayer::send_title`].
pub type TitleHook = Arc<dyn Fn(Uuid, &str, &str, u32, u32, u32) + Send + Sync>;
/// Hook used by [`ProxiedPlayer::send_actionbar`].
pub type ActionBarHook = Arc<dyn Fn(Uuid, &str) + Send + Sync>;
/// Hook used by [`ProxiedPlayer::send_message`].
pub type MessageHook = Arc<dyn Fn(Uuid, &str) + Send + Sync>;

/// Proxy-provided hook table for player actions.
#[derive(Clone)]
pub struct PlayerHooks {
    /// Disconnect implementation.
    pub disconnect: DisconnectHook,
    /// Plugin-message send implementation.
    pub send_plugin_message: PluginMessageHook,
    /// Transfer implementation.
    pub transfer: TransferHook,
    /// Current backend lookup implementation.
    pub current_backend: CurrentBackendHook,
    /// Latency lookup implementation.
    pub latency_ms: LatencyHook,
    /// Tab list update implementation.
    pub set_tab_list: TabListHook,
    /// Title update implementation.
    pub send_title: TitleHook,
    /// Action bar implementation.
    pub send_actionbar: ActionBarHook,
    /// Plain message implementation.
    pub send_message: MessageHook,
}

impl Default for PlayerHooks {
    fn default() -> Self {
        Self {
            disconnect: Arc::new(|_, _| {}),
            send_plugin_message: Arc::new(|_, _, _| {}),
            transfer: Arc::new(|_, _| TransferResult::PlayerDisconnected),
            current_backend: Arc::new(|_| None),
            latency_ms: Arc::new(|_| 0),
            set_tab_list: Arc::new(|_, _, _| {}),
            send_title: Arc::new(|_, _, _, _, _, _| {}),
            send_actionbar: Arc::new(|_, _| {}),
            send_message: Arc::new(|_, _| {}),
        }
    }
}

/// Runtime player handle exposed to plugins.
#[derive(Clone)]
pub struct ProxiedPlayer {
    /// Player UUID.
    pub uuid: Uuid,
    /// Current username.
    pub username: Arc<str>,
    /// Remote socket address.
    pub address: SocketAddr,
    /// Negotiated protocol version.
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

/// Shared player reference type.
pub type PlayerRef = Arc<ProxiedPlayer>;

impl ProxiedPlayer {
    /// Creates a new player handle.
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

    /// Disconnects the player from proxy session.
    pub fn disconnect(&self, reason: &str) {
        (self.hooks.disconnect)(self.uuid, reason);
    }

    /// Sends a plugin channel payload to the player.
    pub fn send_plugin_message(&self, channel: &str, data: Bytes) {
        (self.hooks.send_plugin_message)(self.uuid, channel, data);
    }

    /// Transfers the player to a new backend.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use vex_proxy_sdk::{BackendInfo, BackendRef, PlayerHooks, PlayerMeta, ProxiedPlayer, TransferResult};
    /// # use uuid::Uuid;
    /// let player = ProxiedPlayer::new(
    ///     Uuid::new_v4(),
    ///     "Alex",
    ///     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
    ///     774,
    ///     PlayerHooks::default(),
    ///     PlayerMeta::new(),
    /// );
    /// let backend = BackendRef::new(BackendInfo::new("lobby", "127.0.0.1:25566", true));
    /// let result = player.transfer(backend);
    /// assert!(matches!(
    ///     result,
    ///     TransferResult::Success
    ///         | TransferResult::BackendUnreachable
    ///         | TransferResult::BackendUnhealthy
    ///         | TransferResult::PlayerDisconnected
    ///         | TransferResult::Timeout
    /// ));
    /// ```
    pub fn transfer(&self, backend: BackendRef) -> TransferResult {
        (self.hooks.transfer)(self.uuid, backend)
    }

    /// Gets a typed metadata value for this player.
    pub fn get_meta<T: Clone + Send + Sync + 'static>(&self, key: &str) -> Option<T> {
        self.meta.get(key)
    }

    /// Sets a typed metadata value for this player.
    pub fn set_meta<T: Clone + Send + Sync + 'static>(&self, key: &str, value: T) {
        self.meta.set(key, value);
    }

    /// Removes metadata entry from this player.
    pub fn remove_meta(&self, key: &str) {
        self.meta.remove(key);
    }

    /// Returns true if metadata key exists for this player.
    pub fn has_meta(&self, key: &str) -> bool {
        self.meta.has(key)
    }

    /// Returns current backend if known.
    pub fn current_backend(&self) -> Option<BackendRef> {
        (self.hooks.current_backend)(self.uuid)
    }

    /// Returns current player latency in milliseconds.
    pub fn latency_ms(&self) -> u32 {
        (self.hooks.latency_ms)(self.uuid)
    }

    /// Sets tab list header/footer visible in the in-game player list.
    pub fn set_tab_list(&self, header: &str, footer: &str) {
        (self.hooks.set_tab_list)(self.uuid, header, footer);
    }

    /// Sends title/subtitle with animation timings.
    pub fn send_title(
        &self,
        title: &str,
        subtitle: &str,
        fade_in_ticks: u32,
        stay_ticks: u32,
        fade_out_ticks: u32,
    ) {
        (self.hooks.send_title)(
            self.uuid,
            title,
            subtitle,
            fade_in_ticks,
            stay_ticks,
            fade_out_ticks,
        );
    }

    /// Sends an action bar message above the hotbar.
    pub fn send_actionbar(&self, message: &str) {
        (self.hooks.send_actionbar)(self.uuid, message);
    }

    /// Sends a plain chat message.
    pub fn send_message(&self, message: &str) {
        (self.hooks.send_message)(self.uuid, message);
    }
}
