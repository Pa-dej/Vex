use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use vex_sdk::meta::PlayerMeta;
use vex_sdk::player::{PlayerHooks, ProxiedPlayer};
use vex_sdk::server::BackendRef;

#[derive(Debug)]
pub enum RelayCommand {
    Pause {
        ack: oneshot::Sender<()>,
    },
    Resume,
    SwitchBackend {
        stream: TcpStream,
        backend: BackendRef,
        ack: oneshot::Sender<Result<(), String>>,
    },
    Disconnect(String),
    PluginMessage {
        channel: Arc<str>,
        data: Bytes,
    },
}

#[derive(Clone)]
pub struct PlayerSession {
    pub player: ProxiedPlayer,
    pub relay_control: mpsc::Sender<RelayCommand>,
    _meta: PlayerMeta,
    backend: Arc<std::sync::RwLock<Option<BackendRef>>>,
    latency_ms: Arc<AtomicU32>,
}

impl PlayerSession {
    pub fn new(
        player: ProxiedPlayer,
        relay_control: mpsc::Sender<RelayCommand>,
        meta: PlayerMeta,
        backend: Option<BackendRef>,
    ) -> Self {
        Self {
            player,
            relay_control,
            _meta: meta,
            backend: Arc::new(std::sync::RwLock::new(backend)),
            latency_ms: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn set_backend(&self, backend: Option<BackendRef>) {
        if let Ok(mut guard) = self.backend.write() {
            *guard = backend;
        }
    }

    pub fn current_backend(&self) -> Option<BackendRef> {
        self.backend.read().ok().and_then(|guard| guard.clone())
    }

    pub fn latency_ms(&self) -> u32 {
        self.latency_ms.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: DashMap<Uuid, Arc<PlayerSession>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, session: PlayerSession) -> Arc<PlayerSession> {
        let wrapped = Arc::new(session);
        self.sessions.insert(wrapped.player.uuid, wrapped.clone());
        wrapped
    }

    pub fn remove(&self, uuid: &Uuid) -> Option<Arc<PlayerSession>> {
        self.sessions.remove(uuid).map(|(_, session)| session)
    }

    pub fn get(&self, uuid: &Uuid) -> Option<Arc<PlayerSession>> {
        self.sessions.get(uuid).map(|entry| entry.value().clone())
    }

    pub fn get_players(&self) -> Vec<ProxiedPlayer> {
        self.sessions
            .iter()
            .map(|entry| entry.value().player.clone())
            .collect()
    }

    pub fn get_player(&self, username: &str) -> Option<ProxiedPlayer> {
        let needle = username.to_ascii_lowercase();
        self.sessions
            .iter()
            .find(|entry| entry.value().player.username.to_ascii_lowercase() == needle)
            .map(|entry| entry.value().player.clone())
    }

    pub fn get_player_by_uuid(&self, uuid: Uuid) -> Option<ProxiedPlayer> {
        self.sessions
            .get(&uuid)
            .map(|entry| entry.value().player.clone())
    }

    pub fn online_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn online_count_for(&self, backend: &BackendRef) -> usize {
        self.sessions
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .current_backend()
                    .map(|current| current.name() == backend.name())
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn relay_sender(&self, uuid: Uuid) -> Option<mpsc::Sender<RelayCommand>> {
        self.sessions
            .get(&uuid)
            .map(|entry| entry.value().relay_control.clone())
    }

    pub fn disconnect(&self, uuid: Uuid, reason: &str) -> bool {
        let Some(sender) = self.relay_sender(uuid) else {
            return false;
        };
        sender
            .try_send(RelayCommand::Disconnect(reason.to_string()))
            .is_ok()
    }

    pub fn send_plugin_message(&self, uuid: Uuid, channel: &str, data: Bytes) -> bool {
        let Some(sender) = self.relay_sender(uuid) else {
            return false;
        };
        sender
            .try_send(RelayCommand::PluginMessage {
                channel: Arc::from(channel.to_string()),
                data,
            })
            .is_ok()
    }

    pub fn broadcast(&self, message: &str) {
        let payload = Bytes::from(message.to_string());
        for player in self.get_players() {
            player.send_plugin_message("vex:broadcast", payload.clone());
        }
    }

    pub fn broadcast_to<F>(&self, message: &str, filter: F)
    where
        F: Fn(&ProxiedPlayer) -> bool,
    {
        let payload = Bytes::from(message.to_string());
        for player in self.get_players().into_iter().filter(filter) {
            player.send_plugin_message("vex:broadcast", payload.clone());
        }
    }

    pub fn forward_plugin_message<F>(&self, channel: &str, data: Bytes, filter: F)
    where
        F: Fn(&ProxiedPlayer) -> bool,
    {
        for player in self.get_players().into_iter().filter(filter) {
            player.send_plugin_message(channel, data.clone());
        }
    }

    pub fn make_player_hooks(self: &Arc<Self>) -> PlayerHooks {
        let disconnect_registry = Arc::clone(self);
        let plugin_msg_registry = Arc::clone(self);
        let transfer_registry = Arc::clone(self);
        let current_backend_registry = Arc::clone(self);
        let latency_registry = Arc::clone(self);

        PlayerHooks {
            disconnect: Arc::new(move |uuid, reason| {
                let _ = disconnect_registry.disconnect(uuid, reason);
            }),
            send_plugin_message: Arc::new(move |uuid, channel, data| {
                let _ = plugin_msg_registry.send_plugin_message(uuid, channel, data);
            }),
            transfer: Arc::new(move |uuid, backend| {
                crate::transfer::transfer_player_blocking(transfer_registry.clone(), uuid, backend)
            }),
            current_backend: Arc::new(move |uuid| {
                current_backend_registry
                    .get(&uuid)
                    .and_then(|session| session.current_backend())
            }),
            latency_ms: Arc::new(move |uuid| {
                latency_registry
                    .get(&uuid)
                    .map(|session| session.latency_ms())
                    .unwrap_or(0)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    use vex_sdk::meta::PlayerMeta;
    use vex_sdk::player::ProxiedPlayer;

    use super::*;

    #[tokio::test]
    async fn register_and_lookup_player_session() {
        let registry = Arc::new(SessionRegistry::new());
        let hooks = registry.make_player_hooks();
        let meta = PlayerMeta::new();
        let player = ProxiedPlayer::new(
            Uuid::from_u128(1),
            "Tester",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
            767,
            hooks,
            meta.clone(),
        );
        let (tx, _rx) = mpsc::channel(8);
        let session = PlayerSession::new(player.clone(), tx, meta, None);
        registry.register(session);

        assert_eq!(registry.online_count(), 1);
        assert!(registry.get_player("tester").is_some());
        assert!(registry.get_player_by_uuid(player.uuid).is_some());
    }

    #[tokio::test]
    async fn broadcast_sends_zero_copy_payload_to_all_players() {
        let registry = Arc::new(SessionRegistry::new());
        let payloads = Arc::new(tokio::sync::Mutex::new(Vec::<Bytes>::new()));
        let captured = payloads.clone();

        let hooks = PlayerHooks {
            send_plugin_message: Arc::new(move |_uuid, _channel, data| {
                if let Ok(mut guard) = captured.try_lock() {
                    guard.push(data);
                }
            }),
            ..registry.make_player_hooks()
        };

        let meta = PlayerMeta::new();
        let player = ProxiedPlayer::new(
            Uuid::from_u128(2),
            "Tester",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
            767,
            hooks,
            meta.clone(),
        );
        let (tx, _rx) = mpsc::channel(8);
        registry.register(PlayerSession::new(player, tx, meta, None));

        registry.broadcast("hello");
        let guard = payloads.lock().await;
        assert_eq!(guard.len(), 1);
        assert_eq!(&guard[0], &Bytes::from("hello".to_string()));
    }
}
