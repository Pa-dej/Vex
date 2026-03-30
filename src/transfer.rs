use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use uuid::Uuid;
use vex_sdk::player::TransferResult;
use vex_sdk::server::BackendRef;

use crate::mc::{build_handshake_packet, build_login_start_packet, write_packet};
use crate::session_registry::{RelayCommand, SessionRegistry};

const TRANSFER_BUDGET: Duration = Duration::from_millis(500);
const PAUSE_BUDGET: Duration = Duration::from_millis(50);
const CONNECT_BUDGET: Duration = Duration::from_millis(400);
const SWITCH_BUDGET: Duration = Duration::from_millis(75);

pub fn transfer_player_blocking(
    registry: Arc<SessionRegistry>,
    uuid: Uuid,
    backend: BackendRef,
) -> TransferResult {
    let join = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let Ok(runtime) = runtime else {
            return TransferResult::Timeout;
        };
        runtime.block_on(transfer_player(registry, uuid, backend))
    });
    match join.join() {
        Ok(result) => result,
        Err(_) => TransferResult::Timeout,
    }
}

pub async fn transfer_player(
    registry: Arc<SessionRegistry>,
    uuid: Uuid,
    backend: BackendRef,
) -> TransferResult {
    let task = async move {
        if !backend.is_healthy() {
            return TransferResult::BackendUnhealthy;
        }

        let Some(session) = registry.get(&uuid) else {
            return TransferResult::PlayerDisconnected;
        };

        let mut deferred_relay_control = false;
        let (pause_ack_tx, pause_ack_rx) = oneshot::channel();
        if timeout(
            PAUSE_BUDGET,
            session
                .relay_control
                .send(RelayCommand::Pause { ack: pause_ack_tx }),
        )
        .await
        .is_err()
        {
            return TransferResult::Timeout;
        }
        if timeout(PAUSE_BUDGET, pause_ack_rx).await.is_err() {
            // During kick-event dispatch the relay loop may be inside plugin execution and will
            // process queued control commands right after the handler returns.
            deferred_relay_control = true;
        }

        let new_backend_stream = match timeout(CONNECT_BUDGET, async {
            let mut stream = TcpStream::connect(backend.address()).await?;
            if let Ok((host, port)) = split_host_port(backend.address()) {
                let handshake =
                    build_handshake_packet(session.player.protocol_version as i32, host, port, 2);
                let login_start = build_login_start_packet(session.player.username.as_ref());
                write_packet(&mut stream, &handshake).await?;
                write_packet(&mut stream, &login_start).await?;
            }
            let mut probe = [0u8; 1];
            let _ = stream.peek(&mut probe).await?;
            std::io::Result::Ok(stream)
        })
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                let _ = session.relay_control.send(RelayCommand::Resume).await;
                return TransferResult::BackendUnreachable;
            }
            Err(_) => {
                let _ = session.relay_control.send(RelayCommand::Resume).await;
                return TransferResult::Timeout;
            }
        };

        let (switch_ack_tx, switch_ack_rx) = oneshot::channel();
        if timeout(
            SWITCH_BUDGET,
            session.relay_control.send(RelayCommand::SwitchBackend {
                stream: new_backend_stream,
                backend: backend.clone(),
                ack: switch_ack_tx,
            }),
        )
        .await
        .is_err()
        {
            let _ = session.relay_control.send(RelayCommand::Resume).await;
            return TransferResult::Timeout;
        }

        match timeout(SWITCH_BUDGET, switch_ack_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(_))) => {
                let _ = session.relay_control.send(RelayCommand::Resume).await;
                return TransferResult::BackendUnreachable;
            }
            Ok(Err(_)) | Err(_) => {
                if !deferred_relay_control {
                    let _ = session.relay_control.send(RelayCommand::Resume).await;
                    return TransferResult::Timeout;
                }
            }
        }

        if timeout(
            SWITCH_BUDGET,
            session.relay_control.send(RelayCommand::Resume),
        )
        .await
        .is_err()
            && !deferred_relay_control
        {
            return TransferResult::Timeout;
        }

        session.set_backend(Some(backend));
        TransferResult::Success
    };

    match timeout(TRANSFER_BUDGET, task).await {
        Ok(result) => result,
        Err(_) => TransferResult::Timeout,
    }
}

fn split_host_port(addr: &str) -> anyhow::Result<(&str, u16)> {
    let mut parts = addr.rsplitn(2, ':');
    let port_part = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("address missing port"))?;
    let host = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("address missing host"))?;
    let port: u16 = port_part.parse()?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Instant;

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use uuid::Uuid;
    use vex_sdk::meta::PlayerMeta;
    use vex_sdk::player::ProxiedPlayer;
    use vex_sdk::server::{BackendInfo, BackendRef};

    use super::*;
    use crate::mc::read_packet;
    use crate::session_registry::PlayerSession;

    #[tokio::test]
    async fn transfer_switches_relay_to_new_backend() -> anyhow::Result<()> {
        let backend1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend1_addr = backend1_listener.local_addr()?;
        let backend2_addr = backend2_listener.local_addr()?;

        let registry = Arc::new(SessionRegistry::new());
        let hooks = registry.make_player_hooks();
        let player_meta = PlayerMeta::new();
        let player_uuid = Uuid::from_u128(3);
        let player = ProxiedPlayer::new(
            player_uuid,
            "Switcher",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
            767,
            hooks,
            player_meta.clone(),
        );

        let (relay_tx, mut relay_rx) = mpsc::channel(16);
        let _session = registry.register(PlayerSession::new(
            player.clone(),
            relay_tx,
            player_meta,
            Some(BackendRef::new(BackendInfo::new(
                "backend-1",
                backend1_addr.to_string(),
                true,
            ))),
        ));

        let backend1_connect = tokio::spawn(async move { TcpStream::connect(backend1_addr).await });
        let (mut backend1_conn, _) = backend1_listener.accept().await?;
        let _initial_backend_stream = backend1_connect.await??;

        let (switched_tx, switched_rx) = oneshot::channel::<SocketAddr>();
        let relay_task = tokio::spawn(async move {
            let mut switched_tx = Some(switched_tx);
            let mut paused = false;
            loop {
                tokio::select! {
                    Some(cmd) = relay_rx.recv() => {
                        match cmd {
                            RelayCommand::Pause { ack } => {
                                paused = true;
                                let _ = ack.send(());
                            }
                            RelayCommand::Resume => paused = false,
                            RelayCommand::SwitchBackend { stream: new_stream, ack, .. } => {
                                let switched_addr = new_stream.peer_addr().unwrap_or(backend2_addr);
                                let _ = ack.send(Ok(()));
                                if let Some(tx) = switched_tx.take() {
                                    let _ = tx.send(switched_addr);
                                }
                            }
                            RelayCommand::Disconnect(_) => break,
                            RelayCommand::PluginMessage { .. } => {}
                        }
                    }
                    _ = backend1_conn.read_u8(), if !paused => {
                        // ignored for this test
                    }
                }
            }
        });

        let backend2_task = tokio::spawn(async move {
            let (mut socket, _) = backend2_listener.accept().await?;
            let _ = read_packet(&mut socket, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut socket, 8 * 1024 * 1024).await?;
            anyhow::Result::<()>::Ok(())
        });

        let backend2_ref = BackendRef::new(BackendInfo::new(
            "backend-2",
            backend2_addr.to_string(),
            true,
        ));
        let started = Instant::now();
        let result = transfer_player(registry.clone(), player_uuid, backend2_ref).await;
        assert_eq!(result, TransferResult::Success);
        assert!(
            started.elapsed() < TRANSFER_BUDGET,
            "transfer exceeded 500ms budget: {:?}",
            started.elapsed()
        );

        let switched_addr = switched_rx.await?;
        assert_eq!(switched_addr, backend2_addr);

        backend2_task.await??;
        relay_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn transfer_times_out_when_new_backend_never_responds() -> anyhow::Result<()> {
        let backend1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend1_addr = backend1_listener.local_addr()?;
        let backend2_addr = backend2_listener.local_addr()?;

        let registry = Arc::new(SessionRegistry::new());
        let hooks = registry.make_player_hooks();
        let player_meta = PlayerMeta::new();
        let player_uuid = Uuid::from_u128(4);
        let player = ProxiedPlayer::new(
            player_uuid,
            "TimeoutUser",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
            767,
            hooks,
            player_meta.clone(),
        );

        let (relay_tx, mut relay_rx) = mpsc::channel(16);
        let _session = registry.register(PlayerSession::new(
            player,
            relay_tx,
            player_meta,
            Some(BackendRef::new(BackendInfo::new(
                "backend-1",
                backend1_addr.to_string(),
                true,
            ))),
        ));

        let _backend1_conn_task =
            tokio::spawn(async move { TcpStream::connect(backend1_addr).await });
        let _ = backend1_listener.accept().await?;

        let _backend2_hang = tokio::spawn(async move {
            let (_socket, _) = backend2_listener.accept().await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            anyhow::Result::<()>::Ok(())
        });

        let relay_task = tokio::spawn(async move {
            while let Some(cmd) = relay_rx.recv().await {
                match cmd {
                    RelayCommand::Pause { ack } => {
                        let _ = ack.send(());
                    }
                    RelayCommand::Resume => {}
                    RelayCommand::SwitchBackend { ack, .. } => {
                        let _ = ack.send(Ok(()));
                    }
                    RelayCommand::Disconnect(_) | RelayCommand::PluginMessage { .. } => {}
                }
            }
        });

        let backend2_ref = BackendRef::new(BackendInfo::new(
            "backend-2",
            backend2_addr.to_string(),
            true,
        ));
        let started = Instant::now();
        let result = transfer_player(registry.clone(), player_uuid, backend2_ref).await;
        assert_eq!(result, TransferResult::Timeout);
        assert!(
            started.elapsed() <= Duration::from_millis(550),
            "transfer timeout exceeded expected cap: {:?}",
            started.elapsed()
        );

        relay_task.abort();
        Ok(())
    }
}
