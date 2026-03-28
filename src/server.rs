use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::json;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::AuthMode;
use crate::mc::{
    build_login_disconnect, build_login_plugin_response, build_signed_velocity_forwarding_data,
    build_status_ping_response, build_status_response, build_velocity_modern_forwarding_payload,
    decode_login_packet_from_backend, encode_login_packet_for_backend, parse_handshake,
    parse_login_plugin_request, parse_login_start_username, parse_packet_id,
    parse_set_compression_threshold, read_packet, write_packet,
};
use crate::state::RuntimeState;

pub async fn run_proxy_server(state: RuntimeState) -> Result<()> {
    let snapshot = state.snapshot();
    let bind_addr = snapshot.config.listener.bind.clone();
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("proxy listener on {}", bind_addr);

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

                let permit = match state.connection_slots().try_acquire_owned() {
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
                        error!(peer = %addr, err = %format!("{err:#}"), "connection ended with error");
                    }
                });
            }
        }
    }

    let drain_seconds = state.snapshot().config.shutdown.drain_seconds;
    tokio::time::sleep(Duration::from_secs(drain_seconds)).await;
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
    let snapshot = state.snapshot();

    let mut conn_mem = match state
        .memory_budget()
        .acquire_connection(snapshot.config.limits.initial_buffer_bytes)
    {
        Ok(mem) => mem,
        Err(_) => {
            state.metrics.inc_reject("memory_budget");
            reject_without_handshake(&mut client, "Proxy memory budget exceeded").await?;
            return Ok(());
        }
    };
    conn_mem.reserve_for(snapshot.config.limits.initial_buffer_bytes)?;

    let handshake_timeout = Duration::from_millis(snapshot.config.limits.handshake_timeout_ms);
    let login_timeout = Duration::from_millis(snapshot.config.limits.login_timeout_ms);

    let handshake_packet = timeout(
        handshake_timeout,
        read_packet(&mut client, snapshot.config.listener.max_packet_size),
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

    if !snapshot
        .protocol_map
        .is_supported(handshake.protocol_version)
    {
        state.metrics.inc_reject("unsupported_protocol");
        let msg = format!(
            "Unsupported protocol {}. Supported protocol IDs: {}",
            handshake.protocol_version,
            snapshot.protocol_map.supported_compact_range()
        );
        reject_with_reason(&mut client, handshake.next_state, &msg).await?;
        return Ok(());
    }

    if state.shutdown.is_draining() {
        state.metrics.inc_reject("draining");
        reject_with_reason(
            &mut client,
            handshake.next_state,
            &snapshot.config.shutdown.disconnect_message,
        )
        .await?;
        return Ok(());
    }

    match handshake.next_state {
        1 => {
            handle_status(&mut client, &snapshot, &state, &handshake).await?;
        }
        2 => {
            let client_ip = peer.ip().to_string();
            if let Err(e) = handle_login(
                &mut client,
                &snapshot,
                &state,
                handshake_packet,
                handshake.protocol_version,
                login_timeout,
                &client_ip,
                peer,
            )
            .await
            {
                error!("login error peer={} err={:#}", peer, e);
                return Err(e);
            }
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
    snapshot: &Arc<crate::state::RuntimeSnapshot>,
    state: &RuntimeState,
    handshake: &crate::mc::Handshake,
) -> Result<()> {
    let req = read_packet(client, snapshot.config.listener.max_packet_size).await?;
    let (packet_id, _) = parse_packet_id(&req)?;
    if packet_id != 0 {
        bail!("unexpected status packet id {packet_id}");
    }

    let description = if state.shutdown.is_draining() {
        snapshot.config.shutdown.disconnect_message.clone()
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
            "supported_protocol_count": snapshot.protocol_map.versions().len(),
            "supported_protocol_range": snapshot.protocol_map.supported_compact_range(),
        }
    })
    .to_string();
    let response = build_status_response(&status_json);
    write_packet(client, &response).await?;

    if let Ok(ping_packet) = read_packet(client, snapshot.config.listener.max_packet_size).await {
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
    snapshot: &Arc<crate::state::RuntimeSnapshot>,
    state: &RuntimeState,
    _handshake_packet: Vec<u8>,
    protocol_version: i32,
    login_timeout: Duration,
    client_ip: &str,
    peer: SocketAddr,
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
        read_packet(client, snapshot.config.listener.max_packet_size),
    )
    .await
    .map_err(|_| anyhow::anyhow!("login start timeout"))??;

    let username =
        parse_login_start_username(&login_start_packet)?.unwrap_or_else(|| "unknown".to_string());
    debug!(username = %username, "incoming offline login");

    let Some(lease) = snapshot.backends.choose_backend() else {
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
    tracing::debug!("forwarded login start to backend peer={}", peer);

    if snapshot.config.forwarding.velocity.enabled {
        tracing::debug!("entering velocity intercept loop peer={}", peer);
        let login_phase = run_velocity_login_intercept(
            client,
            &mut backend_stream,
            snapshot.config.listener.max_packet_size,
            client_ip,
            &username,
            &snapshot.config.forwarding.velocity.secret,
            peer,
        )
        .await?;
        if matches!(login_phase, LoginPhaseOutcome::Terminated) {
            return Ok(());
        }
    }

    let mut shutdown_rx = state.shutdown.subscribe();
    let shutdown_message = snapshot.config.shutdown.disconnect_message.clone();
    let max_packet = snapshot.config.listener.max_packet_size;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginPhaseOutcome {
    ContinueToRelay,
    Terminated,
}

async fn run_velocity_login_intercept(
    client: &mut TcpStream,
    backend: &mut TcpStream,
    max_packet_size: usize,
    client_ip: &str,
    username: &str,
    secret: &str,
    peer: SocketAddr,
) -> Result<LoginPhaseOutcome> {
    let mut compression_threshold: Option<i32> = None;
    loop {
        let raw_packet = read_packet(backend, max_packet_size).await?;
        let packet =
            decode_login_packet_from_backend(&raw_packet, compression_threshold.is_some())?;
        let (packet_id, _) = parse_packet_id(&packet)?;
        tracing::debug!(
            "backend packet id={:#04x} len={} peer={}",
            packet_id,
            raw_packet.len(),
            peer
        );
        match packet_id {
            0x03 => {
                let Some(threshold) = parse_set_compression_threshold(&packet)? else {
                    bail!("failed to parse set compression packet");
                };
                compression_threshold = Some(threshold);
                tracing::debug!(
                    "backend enabled compression threshold={} peer={}",
                    threshold,
                    peer
                );
                write_packet(client, &raw_packet).await?;
                continue;
            }
            0x04 => {
                let Some(request) = parse_login_plugin_request(&packet)? else {
                    bail!("failed to parse login plugin request");
                };
                let _request_data_len = request.data.len();
                if request.channel == "velocity:player_info" {
                    let payload = build_velocity_modern_forwarding_payload(client_ip, username);
                    let signed = build_signed_velocity_forwarding_data(secret, &payload)?;
                    let response =
                        build_login_plugin_response(request.message_id, true, Some(&signed));
                    let encoded_response =
                        encode_login_packet_for_backend(&response, compression_threshold)?;
                    write_packet(backend, &encoded_response).await?;
                    tracing::debug!("sent velocity plugin response peer={}", peer);
                } else {
                    let response = build_login_plugin_response(request.message_id, false, None);
                    let encoded_response =
                        encode_login_packet_for_backend(&response, compression_threshold)?;
                    write_packet(backend, &encoded_response).await?;
                }
            }
            0x02 => {
                tracing::debug!("received login success from backend peer={}", peer);
                write_packet(client, &raw_packet).await?;
                return Ok(LoginPhaseOutcome::ContinueToRelay);
            }
            0x00 => {
                write_packet(client, &raw_packet).await?;
                return Ok(LoginPhaseOutcome::Terminated);
            }
            _ => {
                warn!(
                    "unexpected backend packet id={:#04x} peer={}",
                    packet_id, peer
                );
                write_packet(client, &raw_packet).await?;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::backend::BackendPool;
    use crate::config::{BackendConfig, Config};
    use crate::mc::{
        build_handshake_packet, build_login_disconnect, build_login_plugin_request,
        build_login_start_packet, decode_login_packet_from_backend,
        encode_login_packet_for_backend, offline_uuid, parse_login_plugin_response,
        parse_velocity_modern_forwarding_payload, sign_hmac_sha256, write_varint,
    };
    use crate::metrics::Metrics;
    use crate::protocol_map::ProtocolMap;
    use crate::state::RuntimeState;

    #[tokio::test]
    async fn velocity_forwarding_login_plugin_is_signed() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.routing.backends = vec![BackendConfig {
            name: "backend-test".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];
        config.forwarding.velocity.enabled = true;
        config.forwarding.velocity.secret = "test-secret".to_string();

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let pool = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config.clone(), protocol_map, metrics, pool);

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let secret = config.forwarding.velocity.secret.clone();
        let backend_task = tokio::spawn(async move {
            let (mut stream, _addr) = backend_listener.accept().await?;
            let _handshake = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _login_start = read_packet(&mut stream, 8 * 1024 * 1024).await?;

            let plugin_request = build_login_plugin_request(42, "velocity:player_info", &[]);
            write_packet(&mut stream, &plugin_request).await?;

            let response = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let parsed = parse_login_plugin_response(&response)?
                .ok_or_else(|| anyhow::anyhow!("expected login plugin response packet"))?;
            if parsed.message_id != 42 {
                bail!("unexpected message id {}", parsed.message_id);
            }
            if !parsed.success {
                bail!("velocity forwarding response was not successful");
            }
            let data = parsed
                .data
                .ok_or_else(|| anyhow::anyhow!("missing velocity forwarding data"))?;
            if data.len() < 32 {
                bail!("velocity forwarding data too small");
            }
            let signature = &data[..32];
            let payload = &data[32..];
            let expected_signature = sign_hmac_sha256(&secret, payload)?;
            if signature != expected_signature {
                bail!("invalid hmac signature");
            }

            let forwarded = parse_velocity_modern_forwarding_payload(payload)?;
            if forwarded.version != 1 {
                bail!("unexpected forwarding version {}", forwarded.version);
            }
            if forwarded.client_ip != "127.0.0.1" {
                bail!("unexpected forwarded client ip {}", forwarded.client_ip);
            }
            if forwarded.uuid_bytes != offline_uuid("TestUser") {
                bail!("unexpected offline uuid bytes");
            }
            if forwarded.username != "TestUser" {
                bail!("unexpected forwarded username {}", forwarded.username);
            }
            if forwarded.properties_count != 0 {
                bail!(
                    "expected zero properties, got {}",
                    forwarded.properties_count
                );
            }

            let mut set_compression = BytesMut::new();
            write_varint(0x03, &mut set_compression);
            write_varint(256, &mut set_compression);
            write_packet(&mut stream, &set_compression).await?;

            let disconnect = build_login_disconnect("done");
            let encoded_disconnect = encode_login_packet_for_backend(&disconnect, Some(256))?;
            write_packet(&mut stream, &encoded_disconnect).await?;
            Result::<()>::Ok(())
        });

        let mut client = None;
        for _ in 0..30 {
            match TcpStream::connect(proxy_addr).await {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
        let mut client = client.ok_or_else(|| anyhow::anyhow!("proxy did not start in time"))?;

        let handshake = build_handshake_packet(767, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("TestUser");
        write_packet(&mut client, &login_start).await?;

        let backend_result = timeout(Duration::from_secs(5), backend_task).await??;
        backend_result?;

        let set_compression_packet = timeout(
            Duration::from_secs(5),
            read_packet(&mut client, 8 * 1024 * 1024),
        )
        .await??;
        let (set_comp_id, _) = parse_packet_id(&set_compression_packet)?;
        if set_comp_id != 0x03 {
            bail!("expected set compression packet, got {set_comp_id}");
        }

        let disconnect = timeout(
            Duration::from_secs(5),
            read_packet(&mut client, 8 * 1024 * 1024),
        )
        .await??;
        let decoded_disconnect = decode_login_packet_from_backend(&disconnect, true)?;
        let (packet_id, _) = parse_packet_id(&decoded_disconnect)?;
        if packet_id != 0x00 {
            bail!("expected login disconnect packet, got {packet_id}");
        }

        state.shutdown.trigger("test complete".to_string());
        let server_result = timeout(Duration::from_secs(5), server_task).await??;
        server_result?;
        Ok(())
    }
}
