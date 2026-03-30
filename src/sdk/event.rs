use std::any::Any;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;

use crate::player::ProxiedPlayer;
use crate::server::BackendRef;

pub trait Event: Any + Send + Sync + 'static {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    cancelled: Arc<AtomicBool>,
    reason: Arc<OnceLock<String>>,
}

impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn cancel_with_reason(&self, reason: impl Into<String>) {
        let _ = self.reason.set(reason.into());
        self.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.get().map(String::as_str)
    }
}

#[derive(Clone, Debug)]
pub struct SamplePlayer {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct StatusResponse {
    pub version_name: String,
    pub protocol: i32,
    pub max_players: i32,
    pub online_players: i32,
    pub description: String,
    pub favicon_png_b64: Option<String>,
    pub sample_players: Vec<SamplePlayer>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    ClientLeft,
    BackendKicked(String),
    Timeout,
    TransferFailed,
    PluginDisconnected,
}

#[derive(Clone, Debug)]
pub struct OnTcpConnect {
    pub addr: SocketAddr,
    pub cancellation: Cancellation,
}

impl Event for OnTcpConnect {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnTcpConnect {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnHandshake {
    pub addr: SocketAddr,
    pub host: String,
    pub port: u16,
    pub protocol: u32,
    pub next_state: i32,
    pub cancellation: Cancellation,
}

impl Event for OnHandshake {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnHandshake {
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

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnPreLogin {
    pub addr: SocketAddr,
    pub username: String,
    pub cancellation: Cancellation,
}

impl Event for OnPreLogin {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnPreLogin {
    pub fn new(addr: SocketAddr, username: impl Into<String>) -> Self {
        Self {
            addr,
            username: username.into(),
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnLoginSuccess {
    pub player: ProxiedPlayer,
}

impl Event for OnLoginSuccess {}

#[derive(Clone, Debug)]
pub struct OnDisconnect {
    pub player: ProxiedPlayer,
    pub reason: DisconnectReason,
}

impl Event for OnDisconnect {}

#[derive(Clone, Debug)]
pub struct OnBackendConnect {
    pub player: ProxiedPlayer,
    pub backend: BackendRef,
    pub cancellation: Cancellation,
}

impl Event for OnBackendConnect {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnBackendConnect {
    pub fn new(player: ProxiedPlayer, backend: BackendRef) -> Self {
        Self {
            player,
            backend,
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnBackendReady {
    pub player: ProxiedPlayer,
    pub backend: BackendRef,
}

impl Event for OnBackendReady {}

#[derive(Clone, Debug)]
pub struct OnBackendDisconnect {
    pub player: ProxiedPlayer,
    pub backend: BackendRef,
    pub reason: String,
}

impl Event for OnBackendDisconnect {}

#[derive(Clone, Debug)]
pub struct OnBackendKick {
    pub player: ProxiedPlayer,
    pub backend: BackendRef,
    pub message: String,
    pub cancellation: Cancellation,
}

impl Event for OnBackendKick {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnBackendKick {
    pub fn new(player: ProxiedPlayer, backend: BackendRef, message: impl Into<String>) -> Self {
        Self {
            player,
            backend,
            message: message.into(),
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnBackendSwitch {
    pub player: ProxiedPlayer,
    pub from: BackendRef,
    pub to: BackendRef,
}

impl Event for OnBackendSwitch {}

#[derive(Clone, Debug)]
pub struct OnStatusPing {
    pub addr: SocketAddr,
    pub response: Arc<Mutex<StatusResponse>>,
}

impl Event for OnStatusPing {}

impl OnStatusPing {
    pub fn new(addr: SocketAddr, response: StatusResponse) -> Self {
        Self {
            addr,
            response: Arc::new(Mutex::new(response)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OnReload {}

impl Event for OnReload {}

#[derive(Clone, Debug)]
pub struct OnPluginMessage {
    pub player: ProxiedPlayer,
    pub channel: String,
    pub data: Bytes,
    pub cancellation: Cancellation,
}

impl Event for OnPluginMessage {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl OnPluginMessage {
    pub fn new(player: ProxiedPlayer, channel: impl Into<String>, data: Bytes) -> Self {
        Self {
            player,
            channel: channel.into(),
            data,
            cancellation: Cancellation::default(),
        }
    }

    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancellation.cancel_with_reason(reason);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn cancel_reason(&self) -> Option<&str> {
        self.cancellation.reason()
    }
}

#[derive(Clone, Debug)]
pub struct OnAttackModeChange {
    pub active: bool,
    pub cps: f64,
    pub fail_ratio: f64,
}

impl Event for OnAttackModeChange {}

#[derive(Clone, Debug)]
pub struct OnBackendHealthChange {
    pub backend: BackendRef,
    pub old_state: HealthState,
    pub new_state: HealthState,
}

impl Event for OnBackendHealthChange {}

#[derive(Clone, Debug)]
pub struct OnPermissionCheck {
    pub player: ProxiedPlayer,
    pub permission: String,
    pub result: Arc<AtomicBool>,
}

impl Event for OnPermissionCheck {}

impl OnPermissionCheck {
    pub fn new(player: ProxiedPlayer, permission: impl Into<String>, initial: bool) -> Self {
        Self {
            player,
            permission: permission.into(),
            result: Arc::new(AtomicBool::new(initial)),
        }
    }

    pub fn allow(&self) {
        self.result.store(true, Ordering::Relaxed);
    }

    pub fn deny(&self) {
        self.result.store(false, Ordering::Relaxed);
    }

    pub fn is_allowed(&self) -> bool {
        self.result.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use uuid::Uuid;

    use super::*;
    use crate::meta::PlayerMeta;
    use crate::player::{PlayerHooks, ProxiedPlayer};
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
}
