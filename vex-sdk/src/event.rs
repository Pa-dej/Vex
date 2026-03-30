//! Event model exposed to plugins.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;

use crate::player::ProxiedPlayer;
use crate::server::BackendRef;
pub use crate::server::HealthState;

/// Base trait for all plugin events.
pub trait Event: Any + Send + Sync + 'static {
    /// Returns true when event flow should stop after current priority group.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Shared cancellable event behavior.
pub trait Cancellable {
    /// Cancels the event and stores optional reason.
    fn cancel(&self, reason: impl Into<String>);
    /// Returns true when event is cancelled.
    fn is_cancelled(&self) -> bool;
    /// Returns cancellation reason if present.
    fn cancel_reason(&self) -> Option<&str>;
}

/// Cancellation token shared between cloned event instances.
#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    cancelled: Arc<AtomicBool>,
    reason: Arc<OnceLock<String>>,
}

impl Cancellation {
    /// Cancels event without a reason.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Cancels event and stores a reason.
    pub fn cancel_with_reason(&self, reason: impl Into<String>) {
        let _ = self.reason.set(reason.into());
        self.cancel();
    }

    /// Returns cancellation flag.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Returns cancellation reason.
    pub fn reason(&self) -> Option<&str> {
        self.reason.get().map(String::as_str)
    }
}

/// Sample player entry for status ping hover.
#[derive(Clone, Debug)]
pub struct SamplePlayer {
    /// Display name.
    pub name: String,
    /// UUID string.
    pub id: String,
}

/// Mutable status ping response.
#[derive(Clone, Debug)]
pub struct StatusResponse {
    /// Version label shown to clients.
    pub version_name: String,
    /// Protocol version id.
    pub protocol: i32,
    /// Max player count.
    pub max_players: i32,
    /// Current online players.
    pub online_players: i32,
    /// MOTD.
    pub description: String,
    /// Optional base64 png favicon.
    pub favicon_png_b64: Option<String>,
    /// Sample players list for hover.
    pub sample_players: Vec<SamplePlayer>,
}

/// Disconnect reason for established player sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Client closed connection.
    ClientLeft,
    /// Backend kicked player with message.
    BackendKicked(String),
    /// Session timed out.
    Timeout,
    /// Transfer pipeline failed.
    TransferFailed,
    /// Plugin requested disconnect.
    PluginDisconnected,
}

/// Fired immediately after TCP accept.
#[derive(Clone, Debug)]
pub struct OnTcpConnect {
    /// Remote address.
    pub addr: SocketAddr,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnTcpConnect {
    /// Creates event instance.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnTcpConnect {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnTcpConnect {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired after handshake parse.
#[derive(Clone, Debug)]
pub struct OnHandshake {
    /// Remote address.
    pub addr: SocketAddr,
    /// Requested host.
    pub host: String,
    /// Requested port.
    pub port: u16,
    /// Client protocol version.
    pub protocol: u32,
    /// Next protocol state.
    pub next_state: i32,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnHandshake {
    /// Creates event instance.
    pub fn new(
        addr: SocketAddr,
        host: impl Into<String>,
        port: u16,
        protocol: u32,
        next_state: i32,
    ) -> Self {
        Self {
            addr,
            host: host.into(),
            port,
            protocol,
            next_state,
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnHandshake {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnHandshake {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired after Login Start and before auth.
#[derive(Clone, Debug)]
pub struct OnPreLogin {
    /// Remote address.
    pub addr: SocketAddr,
    /// Login username.
    pub username: String,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnPreLogin {
    /// Creates event instance.
    pub fn new(addr: SocketAddr, username: impl Into<String>) -> Self {
        Self {
            addr,
            username: username.into(),
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnPreLogin {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnPreLogin {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired after player login success and session registration.
#[derive(Clone, Debug)]
pub struct OnLoginSuccess {
    /// Player handle.
    pub player: ProxiedPlayer,
}

impl Event for OnLoginSuccess {}

/// Fired when an established session ends.
#[derive(Clone, Debug)]
pub struct OnDisconnect {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Disconnect reason.
    pub reason: DisconnectReason,
}

impl Event for OnDisconnect {}

/// Fired before backend login starts.
#[derive(Clone, Debug)]
pub struct OnBackendConnect {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Target backend.
    pub backend: BackendRef,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnBackendConnect {
    /// Creates event instance.
    pub fn new(player: ProxiedPlayer, backend: BackendRef) -> Self {
        Self {
            player,
            backend,
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnBackendConnect {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnBackendConnect {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired after backend login success and before relay starts.
#[derive(Clone, Debug)]
pub struct OnBackendReady {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Ready backend.
    pub backend: BackendRef,
}

impl Event for OnBackendReady {}

/// Fired when backend connection drops during relay.
#[derive(Clone, Debug)]
pub struct OnBackendDisconnect {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Backend that disconnected.
    pub backend: BackendRef,
    /// Backend-side reason string.
    pub reason: String,
}

impl Event for OnBackendDisconnect {}

/// Fired when backend kicks player with disconnect packet.
#[derive(Clone, Debug)]
pub struct OnBackendKick {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Backend that issued kick.
    pub backend: BackendRef,
    /// Kick message.
    pub message: String,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnBackendKick {
    /// Creates event instance.
    pub fn new(player: ProxiedPlayer, backend: BackendRef, message: impl Into<String>) -> Self {
        Self {
            player,
            backend,
            message: message.into(),
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnBackendKick {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnBackendKick {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired after successful backend transfer.
#[derive(Clone, Debug)]
pub struct OnBackendSwitch {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Previous backend.
    pub from: BackendRef,
    /// New backend.
    pub to: BackendRef,
}

impl Event for OnBackendSwitch {}

/// Fired for status ping requests.
#[derive(Clone, Debug)]
pub struct OnStatusPing {
    /// Remote address.
    pub addr: SocketAddr,
    /// Mutable response object.
    pub response: Arc<Mutex<StatusResponse>>,
}

impl OnStatusPing {
    /// Creates event instance.
    pub fn new(addr: SocketAddr, response: StatusResponse) -> Self {
        Self {
            addr,
            response: Arc::new(Mutex::new(response)),
        }
    }
}

impl Event for OnStatusPing {}

/// Fired after proxy reload.
#[derive(Clone, Debug, Default)]
pub struct OnReload {}

impl Event for OnReload {}

/// Fired when plugin channel payload is intercepted.
#[derive(Clone, Debug)]
pub struct OnPluginMessage {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Channel name.
    pub channel: String,
    /// Raw plugin payload.
    pub data: Bytes,
    /// Cancellation state.
    pub cancellation: Cancellation,
}

impl OnPluginMessage {
    /// Creates event instance.
    pub fn new(player: ProxiedPlayer, channel: impl Into<String>, data: Bytes) -> Self {
        Self {
            player,
            channel: channel.into(),
            data,
            cancellation: Cancellation::default(),
        }
    }

    /// Cancels event and stores reason.
    pub fn cancel(&self, reason: impl Into<String>) {
        Cancellable::cancel(self, reason);
    }

    /// Returns cancellation state.
    pub fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }

    /// Returns cancellation reason.
    pub fn cancel_reason(&self) -> Option<&str> {
        Cancellable::cancel_reason(self)
    }
}

impl Cancellable for OnPluginMessage {
    fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

impl Event for OnPluginMessage {
    fn is_cancelled(&self) -> bool {
        Cancellable::is_cancelled(self)
    }
}

/// Fired when attack mode toggles.
#[derive(Clone, Debug)]
pub struct OnAttackModeChange {
    /// New attack mode state.
    pub active: bool,
    /// Current connections per second.
    pub cps: f64,
    /// Recent handshake/login failure ratio.
    pub fail_ratio: f64,
}

impl Event for OnAttackModeChange {}

/// Fired when backend health state changes.
#[derive(Clone, Debug)]
pub struct OnBackendHealthChange {
    /// Backend reference.
    pub backend: BackendRef,
    /// Previous state.
    pub old_state: HealthState,
    /// New state.
    pub new_state: HealthState,
}

impl Event for OnBackendHealthChange {}

/// Fired when proxy asks whether player has permission.
#[derive(Clone, Debug)]
pub struct OnPermissionCheck {
    /// Player handle.
    pub player: ProxiedPlayer,
    /// Permission id.
    pub permission: String,
    /// Mutable check result.
    pub result: Arc<AtomicBool>,
}

impl OnPermissionCheck {
    /// Creates event instance.
    pub fn new(player: ProxiedPlayer, permission: impl Into<String>, initial: bool) -> Self {
        Self {
            player,
            permission: permission.into(),
            result: Arc::new(AtomicBool::new(initial)),
        }
    }

    /// Marks permission as allowed.
    pub fn allow(&self) {
        self.result.store(true, Ordering::Relaxed);
    }

    /// Marks permission as denied.
    pub fn deny(&self) {
        self.result.store(false, Ordering::Relaxed);
    }

    /// Returns current permission result.
    pub fn is_allowed(&self) -> bool {
        self.result.load(Ordering::Relaxed)
    }
}

impl Event for OnPermissionCheck {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use uuid::Uuid;

    use super::{
        HealthState, OnBackendConnect, OnBackendHealthChange, OnBackendKick, OnHandshake,
        OnPluginMessage, OnPreLogin, OnTcpConnect,
    };
    use crate::meta::PlayerMeta;
    use crate::player::{PlayerHooks, ProxiedPlayer, TransferResult};
    use crate::server::{BackendInfo, BackendRef};

    fn dummy_player() -> ProxiedPlayer {
        ProxiedPlayer::new(
            Uuid::from_u128(42),
            "TestPlayer",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
            774,
            PlayerHooks::default(),
            PlayerMeta::new(),
        )
    }

    fn dummy_backend() -> BackendRef {
        BackendRef::new(BackendInfo::new("test-backend", "127.0.0.1:25566", true))
    }

    #[test]
    fn cancellable_events_store_reason() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565);

        let tcp = OnTcpConnect::new(addr);
        tcp.cancel("tcp blocked");
        assert!(tcp.is_cancelled());
        assert_eq!(tcp.cancel_reason(), Some("tcp blocked"));

        let handshake = OnHandshake::new(addr, "localhost", 25565, 774, 2);
        handshake.cancel("bad handshake");
        assert!(handshake.is_cancelled());
        assert_eq!(handshake.cancel_reason(), Some("bad handshake"));

        let pre_login = OnPreLogin::new(addr, "player");
        pre_login.cancel("name denied");
        assert!(pre_login.is_cancelled());
        assert_eq!(pre_login.cancel_reason(), Some("name denied"));

        let backend_connect = OnBackendConnect::new(dummy_player(), dummy_backend());
        backend_connect.cancel("route denied");
        assert!(backend_connect.is_cancelled());
        assert_eq!(backend_connect.cancel_reason(), Some("route denied"));

        let backend_kick = OnBackendKick::new(dummy_player(), dummy_backend(), "kicked");
        backend_kick.cancel("redirected");
        assert!(backend_kick.is_cancelled());
        assert_eq!(backend_kick.cancel_reason(), Some("redirected"));

        let plugin_message = OnPluginMessage::new(
            dummy_player(),
            "blocked:channel",
            Bytes::from_static(b"data"),
        );
        plugin_message.cancel("blocked channel");
        assert!(plugin_message.is_cancelled());
        assert_eq!(plugin_message.cancel_reason(), Some("blocked channel"));
    }

    #[test]
    fn transfer_result_variants_exist() {
        let variants = [
            TransferResult::Success,
            TransferResult::BackendUnreachable,
            TransferResult::BackendUnhealthy,
            TransferResult::PlayerDisconnected,
            TransferResult::Timeout,
        ];
        assert_eq!(variants.len(), 5);
    }

    #[test]
    fn backend_health_change_constructs() {
        let event = OnBackendHealthChange {
            backend: dummy_backend(),
            old_state: HealthState::Healthy,
            new_state: HealthState::Degraded,
        };
        assert!(matches!(event.old_state, HealthState::Healthy));
        assert!(matches!(event.new_state, HealthState::Degraded));
    }
}
