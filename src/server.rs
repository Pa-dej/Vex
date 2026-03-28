use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::json;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::AuthMode;
use crate::mc::{
    build_login_disconnect, build_status_ping_response, build_status_response, parse_handshake,
    parse_login_start_username, parse_packet_id, read_packet, write_packet,
};
use crate::state::RuntimeState;

pub async fn run_proxy_server(state: RuntimeState) -> Result<()> {
    let listener = TcpListener::bind(&state.config.listener.bind).await?;
    info!("proxy listener on {}", state.config.listener.bind);

    let mut shutdown_rx = state.shutdown.subscribe();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && shutdown_rx.borrow().is_some() {
                    info!("proxy listener enters drain mode");
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(ok) => ok,
                    Err(err) => {
                        warn!("accept failed: {err}");
                        continue;
                    }
                };

                let permit = match state.connection_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        state.metrics.inc_reject("max_connections");
                        let mut stream = stream;
                        let _ = reject_without_handshake(
                            &mut stream,
                            "Proxy is at max connection capacity",
                        ).await;
                        continue;
                    }
                };

                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, addr, state_clone, permit).await {
                        debug!(peer = %addr, error = %err, "connection ended with error");
                    }
                });
            }
        }
    }

    tokio::time::sleep(Duration::from_secs(state.config.shutdown.drain_seconds)).await;
    Ok(())
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    state: RuntimeState,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    state.metrics.inc_active_connections();
    let _active_guard = ActiveConnectionGuard {
        state: state.clone(),
    };

    let mut conn_mem = match state
        .memory_budget
        .acquire_connection(state.config.limits.initial_buffer_bytes)
    {
        Ok(mem) => mem,
        Err(_) => {
            state.metrics.inc_reject("memory_budget");
            reject_without_handshake(&mut client, "Proxy memory budget exceeded").await?;
            return Ok(());
        }
    };
    conn_mem.reserve_for(state.config.limits.initial_buffer_bytes)?;

    let handshake_timeout = Duration::from_millis(state.config.limits.handshake_timeout_ms);
    let login_timeout = Duration::from_millis(state.config.limits.login_timeout_ms);

    let handshake_packet = timeout(
        handshake_timeout,
        read_packet(&mut client, state.config.listener.max_packet_size),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timeout"))??;

    let handshake = parse_handshake(&handshake_packet)?;
    debug!(
        peer = %peer,
        host = %handshake.server_address,
        port = handshake.server_port,
        protocol = handshake.protocol_version,
        next_state = handshake.next_state,
        "received handshake"
    );

    if !state.protocol_map.is_supported(handshake.protocol_version) {
        state.metrics.inc_reject("unsupported_protocol");
        let msg = format!(
            "Unsupported protocol {}. Supported protocol IDs: {}",
            handshake.protocol_version,
            state.protocol_map.supported_compact_range()
        );
        reject_with_reason(&mut client, handshake.next_state, &msg).await?;
        return Ok(());
    }

    if state.shutdown.is_draining() {
        state.metrics.inc_reject("draining");
        reject_with_reason(
            &mut client,
            handshake.next_state,
            &state.config.shutdown.disconnect_message,
        )
        .await?;
        return Ok(());
    }

    match handshake.next_state {
        1 => {
            handle_status(&mut client, &state, &handshake).await?;
        }
        2 => {
            handle_login(
                &mut client,
                &state,
                handshake_packet,
                handshake.protocol_version,
                login_timeout,
            )
            .await?;
        }
        _ => {
            state.metrics.inc_reject("bad_next_state");
            reject_with_reason(&mut client, 2, "Invalid next state in handshake").await?;
        }
    }

    debug!(peer = %peer, "connection finished");
    Ok(())
}

async fn handle_status(
    client: &mut TcpStream,
    state: &RuntimeState,
    handshake: &crate::mc::Handshake,
) -> Result<()> {
    let req = read_packet(client, state.config.listener.max_packet_size).await?;
    let (packet_id, _) = parse_packet_id(&req)?;
    if packet_id != 0 {
        bail!("unexpected status packet id {packet_id}");
    }

    let description = if state.shutdown.is_draining() {
        state.config.shutdown.disconnect_message.clone()
    } else {
        "Vex proxy online".to_string()
    };
    let status_json = json!({
        "version": {
            "name": "Vex 1.20-1.21",
            "protocol": handshake.protocol_version
        },
        "players": {
            "max": 0,
            "online": 0
        },
        "description": {
            "text": description
        },
        "vex": {
            "supported_protocol_count": state.protocol_map.versions().len(),
            "supported_protocol_range": state.protocol_map.supported_compact_range(),
        }
    })
    .to_string();
    let response = build_status_response(&status_json);
    write_packet(client, &response).await?;

    if let Ok(ping_packet) = read_packet(client, state.config.listener.max_packet_size).await {
        let (id, read) = parse_packet_id(&ping_packet)?;
        if id == 1 && ping_packet.len() >= read + 8 {
            let payload = i64::from_be_bytes(
                ping_packet[read..read + 8]
                    .try_into()
                    .expect("slice len verified"),
            );
            let pong = build_status_ping_response(payload);
            write_packet(client, &pong).await?;
        }
    }
    Ok(())
}

async fn handle_login(
    client: &mut TcpStream,
    state: &RuntimeState,
    _handshake_packet: Vec<u8>,
    protocol_version: i32,
    login_timeout: Duration,
) -> Result<()> {
    let auth_mode = state.auth_mode().await;
    if !matches!(auth_mode, AuthMode::Offline) {
        state.metrics.inc_reject("auth_mode_not_offline");
        reject_with_reason(
            client,
            2,
            "Online auth path is not enabled in v1 core. Set auth.mode=offline.",
        )
        .await?;
        return Ok(());
    }

    let login_start_packet = timeout(
        login_timeout,
        read_packet(client, state.config.listener.max_packet_size),
    )
    .await
    .map_err(|_| anyhow::anyhow!("login start timeout"))??;

    if let Ok(Some(username)) = parse_login_start_username(&login_start_packet) {
        debug!(username = %username, "incoming offline login");
    }

    let Some(lease) = state.backends.choose_backend() else {
        state.metrics.inc_reject("no_healthy_backend");
        reject_with_reason(
            client,
            2,
            "No healthy backend available. Try again in a few seconds.",
        )
        .await?;
        return Ok(());
    };

    let backend = lease.backend().clone();
    let mut backend_stream =
        match timeout(login_timeout, TcpStream::connect(backend.address())).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                state
                    .metrics
                    .inc_backend_error(backend.name(), "connect_error");
                reject_with_reason(client, 2, "Failed to connect backend").await?;
                return Err(anyhow::anyhow!("backend connect error: {err}"));
            }
            Err(_) => {
                state
                    .metrics
                    .inc_backend_error(backend.name(), "connect_timeout");
                reject_with_reason(client, 2, "Backend connection timeout").await?;
                return Err(anyhow::anyhow!("backend connect timeout"));
            }
        };

    let (host, port) = split_host_port(backend.address())?;
    let rewritten_handshake = crate::mc::build_handshake_packet(protocol_version, host, port, 2);
    write_packet(&mut backend_stream, &rewritten_handshake).await?;
    write_packet(&mut backend_stream, &login_start_packet).await?;

    let mut shutdown_rx = state.shutdown.subscribe();
    let shutdown_message = state.config.shutdown.disconnect_message.clone();
    let max_packet = state.config.listener.max_packet_size;

    let mut shutdown_requested = false;
    {
        let relay = copy_bidirectional(client, &mut backend_stream);
        tokio::pin!(relay);
        tokio::select! {
            result = &mut relay => {
                let _ = result?;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && shutdown_rx.borrow().is_some() {
                    shutdown_requested = true;
                }
            }
        }
    };
    if shutdown_requested {
        let _ = send_login_disconnect_best_effort(client, &shutdown_message, max_packet).await;
    }

    Ok(())
}

async fn send_login_disconnect_best_effort(
    stream: &mut TcpStream,
    message: &str,
    _max_packet: usize,
) -> Result<()> {
    let payload = build_login_disconnect(message);
    let _ = write_packet(stream, &payload).await;
    Ok(())
}

async fn reject_with_reason(stream: &mut TcpStream, next_state: i32, message: &str) -> Result<()> {
    if next_state == 1 {
        let status_json = json!({
            "version": {
                "name": "Vex",
                "protocol": 0
            },
            "players": {
                "max": 0,
                "online": 0
            },
            "description": {
                "text": message
            }
        })
        .to_string();
        let payload = build_status_response(&status_json);
        let _ = write_packet(stream, &payload).await;
        return Ok(());
    }

    let payload = build_login_disconnect(message);
    let _ = write_packet(stream, &payload).await;
    Ok(())
}

async fn reject_without_handshake(stream: &mut TcpStream, message: &str) -> Result<()> {
    let payload = build_login_disconnect(message);
    let _ = write_packet(stream, &payload).await;
    Ok(())
}

fn split_host_port(addr: &str) -> Result<(&str, u16)> {
    let mut parts = addr.rsplitn(2, ':');
    let port_part = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing port"))?;
    let host = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let port: u16 = port_part.parse()?;
    Ok((host, port))
}

struct ActiveConnectionGuard {
    state: RuntimeState,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.state.metrics.dec_active_connections();
    }
}
