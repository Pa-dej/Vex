use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, bail};
use rand::distributions::{Alphanumeric, DistString};
use rand::{Rng, thread_rng};
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::time::timeout;
use tracing::{Instrument, debug, error, info, info_span, warn};
use vex_sdk::event::{
    DisconnectReason, OnAttackModeChange, OnBackendConnect, OnBackendDisconnect, OnBackendKick,
    OnBackendReady, OnBackendSwitch, OnDisconnect, OnHandshake, OnLoginSuccess, OnPluginMessage,
    OnPreLogin, OnStatusPing, OnTcpConnect, SamplePlayer, StatusResponse,
};
use vex_sdk::meta::PlayerMeta;
use vex_sdk::player::ProxiedPlayer;
use vex_sdk::server::{BackendInfo, BackendRef};

use crate::analytics::AttackUpdate;
use crate::auth_circuit::CircuitState;
use crate::config::AuthMode;
use crate::limiter::AcquireRejectReason;
use crate::mc::{
    EncryptionResponse, VelocityProperty, build_encryption_request, build_login_disconnect,
    build_login_plugin_response, build_play_plugin_message_packet,
    build_play_system_chat_packet, build_respawn_packet,
    build_signed_velocity_forwarding_data, build_status_ping_response, build_status_response,
    build_velocity_modern_forwarding_payload, decode_login_packet_from_backend,
    encode_login_packet_for_backend, offline_uuid, parse_encryption_response, parse_handshake,
    parse_login_plugin_request, parse_login_start_username, parse_packet_id,
    parse_play_plugin_message_packet, parse_set_compression_threshold, parse_varint, read_packet,
    write_packet, write_varint,
};
use crate::reputation::{ReputationAction, connection_block_message};
use crate::session_registry::{PlayerSession, RelayCommand};
use crate::state::RuntimeState;
use crate::telemetry::generate_trace_id;

pub async fn run_proxy_server(state: RuntimeState) -> Result<()> {
    let snapshot = state.snapshot();
    let bind_addr = snapshot.config.listener.bind.clone();
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("proxy listener on {}", bind_addr);
    let _limiter_cleanup_task = state.limiter().spawn_cleanup_task();

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
                let accepted_at = Instant::now();
                let plugin_runtime = state.plugin_runtime();
                if state.snapshot().config.plugins.enabled && plugin_runtime.has_active_plugins() {
                    let tcp_event = Arc::new(OnTcpConnect::new(addr));
                    let tcp_event = plugin_runtime.events.dispatch(tcp_event).await;
                    if tcp_event.is_cancelled() {
                        continue;
                    }
                }
                let connection_update = state.attack_analytics().record_connection(addr.ip());
                apply_attack_update(&state, connection_update);

                let limiter_lease = match state.limiter().try_acquire(addr.ip()) {
                    Ok(lease) => lease,
                    Err(AcquireRejectReason::GlobalCap) => {
                        state.reputation().record_rate_limit_hit(addr.ip());
                        state.metrics.inc_reject("global_cap");
                        state.metrics.inc_ratelimit_hit("global");
                        state.metrics.inc_connection_result("reject");
                        state
                            .metrics
                            .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
                        let mut stream = stream;
                        let _ = reject_without_handshake(&mut stream, "Server is full").await;
                        continue;
                    }
                    Err(AcquireRejectReason::IpRateLimit) => {
                        state.reputation().record_rate_limit_hit(addr.ip());
                        state.metrics.inc_reject("ip_rate_limit");
                        state.metrics.inc_ratelimit_hit("ip");
                        state.metrics.inc_connection_result("reject");
                        state
                            .metrics
                            .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
                        let mut stream = stream;
                        let _ = reject_without_handshake(
                            &mut stream,
                            "Too many connections from your address",
                        )
                        .await;
                        continue;
                    }
                    Err(AcquireRejectReason::SubnetRateLimit) => {
                        state.reputation().record_rate_limit_hit(addr.ip());
                        state.metrics.inc_reject("subnet_rate_limit");
                        state.metrics.inc_ratelimit_hit("subnet");
                        state.metrics.inc_connection_result("reject");
                        state
                            .metrics
                            .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
                        let mut stream = stream;
                        let _ = reject_without_handshake(
                            &mut stream,
                            "Too many connections from your address",
                        )
                        .await;
                        continue;
                    }
                };

                let reputation_delay = match state.reputation().assess_connection(addr.ip()) {
                    ReputationAction::Allow => None,
                    ReputationAction::Delay {
                        duration,
                        tier_label,
                        warn,
                    } => {
                        state.metrics.inc_reputation_delay(tier_label);
                        if warn {
                            warn!(peer = %addr, delay_ms = duration.as_millis(), "low reputation connection delayed");
                        }
                        Some(duration)
                    }
                    ReputationAction::Block {
                        duration_label,
                        newly_applied,
                        ..
                    } => {
                        if newly_applied {
                            state.metrics.inc_reputation_block(duration_label);
                        }
                        state.metrics.inc_reject("reputation_block");
                        state.metrics.inc_connection_result("reject");
                        state
                            .metrics
                            .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
                        let mut stream = stream;
                        let _ = reject_without_handshake(&mut stream, connection_block_message()).await;
                        continue;
                    }
                };

                let permit = match state.connection_slots().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        state.metrics.inc_reject("max_connections");
                        state.metrics.inc_connection_result("reject");
                        state
                            .metrics
                            .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
                        let mut stream = stream;
                        let _ = reject_without_handshake(
                            &mut stream,
                            "Proxy is at max connection capacity",
                        ).await;
                        continue;
                    }
                };

                let state_clone = state.clone();
                let trace_id = generate_trace_id();
                let connection_span = info_span!(
                    "client_connection",
                    trace_id = %trace_id,
                    peer = %addr
                );
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_connection(
                            stream,
                            addr,
                            accepted_at,
                            reputation_delay,
                            state_clone,
                            permit,
                            limiter_lease,
                        )
                        .await
                    {
                        error!(peer = %addr, err = %format!("{err:#}"), "connection ended with error");
                    }
                }
                .instrument(connection_span));
            }
        }
    }

    let drain_seconds = state.snapshot().config.shutdown.drain_seconds;
    tokio::time::sleep(Duration::from_secs(drain_seconds)).await;
    Ok(())
}

fn apply_attack_update(state: &RuntimeState, update: AttackUpdate) {
    state
        .metrics
        .set_connections_per_second(update.connections_per_second);
    state
        .metrics
        .set_unique_ips_per_minute(update.unique_ips_per_minute);
    state
        .metrics
        .set_attack_mode_active(update.attack_mode_active);

    if let Some(enabled) = update.mode_changed {
        state.limiter().set_attack_mode(enabled);
        let events = state.plugin_runtime().events.clone();
        let cps = update.connections_per_second as f64;
        let fail_ratio = update.login_fail_ratio;
        tokio::spawn(async move {
            let _ = events
                .dispatch(Arc::new(OnAttackModeChange {
                    active: enabled,
                    cps,
                    fail_ratio,
                }))
                .await;
        });
        if enabled {
            state.metrics.inc_attack_detection();
            warn!(
                cps = update.connections_per_second,
                unique_ips_per_minute = update.unique_ips_per_minute,
                login_fail_ratio = update.login_fail_ratio,
                "attack pattern detected"
            );
        } else {
            info!("attack mode exited");
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    accepted_at: Instant,
    reputation_delay: Option<Duration>,
    state: RuntimeState,
    _permit: OwnedSemaphorePermit,
    _limiter_lease: crate::limiter::ConnectionLease,
) -> Result<()> {
    state.metrics.inc_active_connections();
    state.metrics.observe_reputation_score(100.0);
    let _active_guard = ActiveConnectionGuard {
        state: state.clone(),
    };
    let snapshot = state.snapshot();
    let mut connection_result = ConnectionResult::Success;
    let result: Result<()> = async {
        let mut conn_mem = match state
            .memory_budget()
            .acquire_connection(snapshot.config.limits.initial_buffer_bytes)
        {
            Ok(mem) => mem,
            Err(_) => {
                connection_result = ConnectionResult::Reject;
                state.metrics.inc_reject("memory_budget");
                reject_without_handshake(&mut client, "Proxy memory budget exceeded").await?;
                return Ok(());
            }
        };
        conn_mem.reserve_for(snapshot.config.limits.initial_buffer_bytes)?;

        let handshake_timeout = Duration::from_millis(snapshot.config.limits.handshake_timeout_ms);
        let login_timeout = Duration::from_millis(snapshot.config.limits.login_timeout_ms);

        let handshake_packet = match timeout(
            handshake_timeout,
            read_first_packet(&mut client, snapshot.config.limits.max_packet_size),
        )
        .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(FirstFrameError::Malformed)) => {
                connection_result = ConnectionResult::Reject;
                state.reputation().record_malformed_frame(peer.ip());
                state.metrics.inc_reject("malformed_frame");
                return Ok(());
            }
            Ok(Err(FirstFrameError::Io(err))) => {
                return Err(err.into());
            }
            Err(_) => {
                state.reputation().record_handshake_timeout(peer.ip());
                return Err(anyhow::anyhow!("handshake timeout"));
            }
        };

        let handshake = parse_handshake(&handshake_packet)?;
        let version_label = snapshot
            .protocol_map
            .version_label_for_id(handshake.protocol_version)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| handshake.protocol_version.to_string());
        state.metrics.inc_protocol_version(&version_label);
        debug!(
            peer = %peer,
            host = %handshake.server_address,
            port = handshake.server_port,
            protocol = handshake.protocol_version,
            next_state = handshake.next_state,
            "received handshake"
        );

        let plugin_runtime = state.plugin_runtime();
        if snapshot.config.plugins.enabled && plugin_runtime.has_active_plugins() {
            let handshake_event = Arc::new(OnHandshake::new(
                peer,
                handshake.server_address.clone(),
                handshake.server_port,
                handshake.protocol_version as u32,
                handshake.next_state,
            ));
            let handshake_event = plugin_runtime.events.dispatch(handshake_event).await;
            if handshake_event.is_cancelled() {
                connection_result = ConnectionResult::Reject;
                state.metrics.inc_reject("handshake_cancelled");
                reject_with_reason(
                    &mut client,
                    handshake.next_state,
                    handshake_event
                        .cancel_reason()
                        .unwrap_or("Connection rejected by plugin"),
                )
                .await?;
                return Ok(());
            }
        }

        if !snapshot
            .protocol_map
            .is_supported(handshake.protocol_version)
        {
            connection_result = ConnectionResult::Reject;
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
            connection_result = ConnectionResult::Reject;
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
                match handle_login(
                    &mut client,
                    &snapshot,
                    &state,
                    handshake.protocol_version,
                    login_timeout,
                    reputation_delay,
                    &client_ip,
                    peer,
                )
                .await
                {
                    Ok(LoginOutcome::Accepted) => {
                        connection_result = ConnectionResult::Success;
                        state.reputation().record_successful_login(peer.ip());
                        let update = state.attack_analytics().record_login_result(true);
                        apply_attack_update(&state, update);
                    }
                    Ok(LoginOutcome::Rejected) => {
                        connection_result = ConnectionResult::Reject;
                        let update = state.attack_analytics().record_login_result(false);
                        apply_attack_update(&state, update);
                    }
                    Err(e) => {
                        let update = state.attack_analytics().record_login_result(false);
                        apply_attack_update(&state, update);
                        error!("login error peer={} err={:#}", peer, e);
                        return Err(e);
                    }
                }
                return Ok(());
            }
            _ => {
                connection_result = ConnectionResult::Reject;
                state.metrics.inc_reject("bad_next_state");
                reject_with_reason(&mut client, 2, "Invalid next state in handshake").await?;
            }
        }

        debug!(peer = %peer, "connection finished");
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            state
                .metrics
                .inc_connection_result(connection_result.as_label());
        }
        Err(_) => {
            state.metrics.inc_connection_result("error");
        }
    }
    state
        .metrics
        .observe_connection_duration(accepted_at.elapsed().as_secs_f64());
    result
}

enum FirstFrameError {
    Malformed,
    Io(std::io::Error),
}

async fn read_first_packet(
    stream: &mut TcpStream,
    max_packet_size: usize,
) -> std::result::Result<Vec<u8>, FirstFrameError> {
    let mut num_read = 0usize;
    let mut result = 0i32;
    let mut shift = 0u32;

    loop {
        let byte = stream.read_u8().await.map_err(FirstFrameError::Io)?;
        let value = (byte & 0x7F) as i32;
        result |= value << shift;
        num_read += 1;
        if num_read > 5 {
            return Err(FirstFrameError::Malformed);
        }
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }

    if result <= 0 {
        return Err(FirstFrameError::Malformed);
    }
    let packet_len = result as usize;
    if packet_len > max_packet_size {
        return Err(FirstFrameError::Malformed);
    }

    let mut payload = vec![0u8; packet_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(FirstFrameError::Io)?;
    Ok(payload)
}

async fn handle_status(
    client: &mut TcpStream,
    snapshot: &Arc<crate::state::RuntimeSnapshot>,
    state: &RuntimeState,
    handshake: &crate::mc::Handshake,
) -> Result<()> {
    let req = read_packet(client, snapshot.config.limits.max_packet_size).await?;
    let (packet_id, _) = parse_packet_id(&req)?;
    if packet_id != 0 {
        bail!("unexpected status packet id {packet_id}");
    }

    let description = if state.shutdown.is_draining() {
        snapshot.config.shutdown.disconnect_message.clone()
    } else {
        snapshot.config.status.motd.clone()
    };
    let plugin_runtime = state.plugin_runtime();
    let online_players = if snapshot.config.status.show_real_online {
        plugin_runtime
            .proxy
            .get_backends()
            .iter()
            .map(|backend| plugin_runtime.proxy.online_count_for(backend))
            .sum::<usize>() as i32
    } else {
        plugin_runtime.proxy.online_count() as i32
    };
    let status_response = StatusResponse {
        version_name: "Vex 1.20-1.21".to_string(),
        protocol: handshake.protocol_version,
        max_players: snapshot.config.status.max_players,
        online_players,
        description,
        favicon_png_b64: None,
        sample_players: Vec::<SamplePlayer>::new(),
    };
    let status_event = Arc::new(OnStatusPing::new(
        client
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        status_response,
    ));
    let _ = plugin_runtime.events.dispatch(status_event.clone()).await;

    let status = status_event
        .response
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or(StatusResponse {
            version_name: "Vex 1.20-1.21".to_string(),
            protocol: handshake.protocol_version,
            max_players: snapshot.config.status.max_players,
            online_players,
            description: snapshot.config.status.motd.clone(),
            favicon_png_b64: None,
            sample_players: Vec::new(),
        });
    let status_json = json!({
        "version": {
            "name": status.version_name,
            "protocol": status.protocol
        },
        "players": {
            "max": status.max_players,
            "online": status.online_players,
            "sample": status.sample_players.iter().map(|sample| {
                json!({
                    "name": sample.name,
                    "id": sample.id,
                })
            }).collect::<Vec<_>>()
        },
        "description": {
            "text": status.description
        },
        "favicon": status.favicon_png_b64.as_ref().map(|icon| format!("data:image/png;base64,{}", icon)),
        "enforcesSecureChat": false,
        "previewsChat": false,
        "vex": {
            "supported_protocol_count": snapshot.protocol_map.versions().len(),
            "supported_protocol_range": snapshot.protocol_map.supported_compact_range(),
        },
    })
    .to_string();
    let response = build_status_response(&status_json);
    write_packet(client, &response).await?;

    if let Ok(ping_packet) = read_packet(client, snapshot.config.limits.max_packet_size).await {
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

#[allow(clippy::too_many_arguments)]
async fn handle_login(
    client: &mut TcpStream,
    snapshot: &Arc<crate::state::RuntimeSnapshot>,
    state: &RuntimeState,
    protocol_version: i32,
    login_timeout: Duration,
    reputation_delay: Option<Duration>,
    client_ip: &str,
    peer: SocketAddr,
) -> Result<LoginOutcome> {
    let login_started = Instant::now();
    let auth_mode = state.auth_mode().await;
    let auth_mode_label = match auth_mode {
        AuthMode::Offline => "offline",
        AuthMode::Online | AuthMode::Auto => "online",
    };

    let result: Result<LoginOutcome> = async {
        let login_start_packet = match timeout(
            login_timeout,
            read_client_packet(client, snapshot.config.limits.max_packet_size, None),
        )
        .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                state.metrics.inc_login_failure("timeout");
                return Err(anyhow::anyhow!("login start timeout"));
            }
        };

        let login_start_username = parse_login_start_username(&login_start_packet)?
            .unwrap_or_else(|| "unknown".to_string());
        debug!(username = %login_start_username, "incoming login start");

        let plugin_runtime = state.plugin_runtime();
        let plugins_active = snapshot.config.plugins.enabled && plugin_runtime.has_active_plugins();
        if plugins_active {
            let pre_login = Arc::new(OnPreLogin::new(peer, login_start_username.clone()));
            let pre_login = plugin_runtime.events.dispatch(pre_login).await;
            if pre_login.is_cancelled() {
                state.metrics.inc_reject("prelogin_cancelled");
                send_login_disconnect_best_effort(
                    client,
                    pre_login
                        .cancel_reason()
                        .unwrap_or("Login rejected by plugin"),
                    None,
                )
                .await?;
                return Ok(LoginOutcome::Rejected);
            }
        }

        let mut client_crypto: Option<ClientCrypto> = None;
        let identity = match auth_mode {
            AuthMode::Offline => {
                warn!(peer = %peer, "offline auth fallback is active for accepted connection");
                AuthenticatedIdentity {
                    uuid_bytes: offline_uuid(&login_start_username),
                    username: login_start_username.clone(),
                    properties: Vec::new(),
                }
            }
            AuthMode::Online | AuthMode::Auto => {
                let server_id = random_ascii(20);
                let mut verify_token = [0u8; 4];
                thread_rng().fill(&mut verify_token);

                let crypto = state.crypto();
                let encryption_request =
                    build_encryption_request(&server_id, crypto.public_key_der(), &verify_token);
                write_client_packet(client, &encryption_request, None).await?;

                let encryption_response_packet = match timeout(
                    login_timeout,
                    read_client_packet(client, snapshot.config.limits.max_packet_size, None),
                )
                .await
                {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        state.metrics.inc_login_failure("timeout");
                        return Err(anyhow::anyhow!("encryption response timeout"));
                    }
                };

                let EncryptionResponse {
                    shared_secret,
                    verify_token: encrypted_verify_token,
                } = parse_encryption_response(&encryption_response_packet)?.ok_or_else(|| {
                    anyhow::anyhow!("expected encryption response packet id 0x01")
                })?;

                let decrypted_secret = crypto.decrypt(&shared_secret)?;
                if decrypted_secret.len() != 16 {
                    state.metrics.inc_login_failure("auth_failed");
                    send_login_disconnect_best_effort(client, "Invalid shared secret", None)
                        .await?;
                    return Ok(LoginOutcome::Rejected);
                }
                let decrypted_verify_token = crypto.decrypt(&encrypted_verify_token)?;
                if decrypted_verify_token.as_slice() != verify_token {
                    state.metrics.inc_login_failure("auth_failed");
                    send_login_disconnect_best_effort(client, "Invalid verify token", None).await?;
                    return Ok(LoginOutcome::Rejected);
                }

                let shared_secret: [u8; 16] = decrypted_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("shared secret must be 16 bytes"))?;
                client_crypto = Some(ClientCrypto::new(&shared_secret)?);

                let server_hash = compute_minecraft_server_hash(
                    &server_id,
                    &shared_secret,
                    crypto.public_key_der(),
                );
                let profile = match authenticate_online(
                    state,
                    &login_start_username,
                    &server_hash,
                    login_timeout,
                )
                .await
                {
                    Ok(profile) => profile,
                    Err(MojangAuthError::AuthenticationFailed) => {
                        state.metrics.inc_login_failure("auth_failed");
                        send_login_disconnect_best_effort(
                            client,
                            "Authentication failed",
                            client_crypto.as_mut(),
                        )
                        .await?;
                        return Ok(LoginOutcome::Rejected);
                    }
                    Err(MojangAuthError::CircuitOpen) => {
                        state.metrics.inc_login_failure("circuit_open");
                        send_login_disconnect_best_effort(
                            client,
                            "Authentication service unavailable. Try again later.",
                            client_crypto.as_mut(),
                        )
                        .await?;
                        return Ok(LoginOutcome::Rejected);
                    }
                    Err(MojangAuthError::ServiceUnavailable) => {
                        state.metrics.inc_login_failure("timeout");
                        send_login_disconnect_best_effort(
                            client,
                            "Authentication service unavailable. Try again later.",
                            client_crypto.as_mut(),
                        )
                        .await?;
                        return Ok(LoginOutcome::Rejected);
                    }
                };

                let uuid_bytes = parse_mojang_uuid_bytes(&profile.id)?;
                let properties = profile
                    .properties
                    .into_iter()
                    .map(|property| VelocityProperty {
                        name: property.name,
                        value: property.value,
                        signature: property.signature,
                    })
                    .collect::<Vec<_>>();
                AuthenticatedIdentity {
                    uuid_bytes,
                    username: profile.name,
                    properties,
                }
            }
        };

        if let Some(delay) = reputation_delay {
            tokio::time::sleep(delay).await;
        }

        let mut player_meta = None;
        let mut player = None;
        if plugins_active {
            let meta = PlayerMeta::new();
            let hooks = plugin_runtime.sessions.make_player_hooks();
            let proxied = ProxiedPlayer::new(
                uuid::Uuid::from_bytes(identity.uuid_bytes),
                identity.username.clone(),
                peer,
                protocol_version as u32,
                hooks,
                meta.clone(),
            );
            player_meta = Some(meta);
            player = Some(proxied);
        }

        let mut cancelled_leases = Vec::new();
        let mut selected_lease = None;
        let mut selected_backend = None;
        let mut selected_backend_ref = None;
        let mut selected_backend_stream = None;
        let mut last_backend_cancel_reason: Option<String> = None;
        let backend_candidates = snapshot.backends.backends().len().max(1);

        for _ in 0..backend_candidates {
            let Some(lease) = snapshot.backends.choose_backend() else {
                break;
            };
            let backend = lease.backend().clone();
            let backend_ref = BackendRef::new(BackendInfo::new(
                backend.name().to_string(),
                backend.address().to_string(),
                backend.health() != crate::backend::BackendHealth::Unhealthy,
            ));

            if let Some(player) = player.as_ref() {
                let event = Arc::new(OnBackendConnect::new(player.clone(), backend_ref.clone()));
                let event = plugin_runtime.events.dispatch(event).await;
                if event.is_cancelled() {
                    last_backend_cancel_reason = event.cancel_reason().map(ToOwned::to_owned);
                    cancelled_leases.push(lease);
                    continue;
                }
            }

            let mut backend_stream =
                match timeout(login_timeout, TcpStream::connect(backend.address())).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(err)) => {
                        state
                            .metrics
                            .inc_backend_error(backend.name(), "connect_error");
                        cancelled_leases.push(lease);
                        warn!(
                            backend = backend.name(),
                            error = %err,
                            "backend connect failed, trying next backend"
                        );
                        continue;
                    }
                    Err(_) => {
                        state
                            .metrics
                            .inc_backend_error(backend.name(), "connect_timeout");
                        cancelled_leases.push(lease);
                        warn!(
                            backend = backend.name(),
                            "backend connect timeout, trying next backend"
                        );
                        continue;
                    }
                };

            let (host, port) = split_host_port(backend.address())?;
            let rewritten_handshake =
                crate::mc::build_handshake_packet(protocol_version, host, port, 2);
            write_packet(&mut backend_stream, &rewritten_handshake).await?;
            write_packet(&mut backend_stream, &login_start_packet).await?;
            tracing::debug!("forwarded login start to backend peer={}", peer);

            let login_phase = run_backend_login_intercept(
                client,
                client_crypto.as_mut(),
                &mut backend_stream,
                snapshot.config.limits.max_packet_size,
                login_timeout,
                snapshot.config.forwarding.velocity.enabled,
                client_ip,
                &identity,
                &snapshot.config.forwarding.velocity.secret,
                peer,
                player.as_ref(),
                &backend_ref,
                &plugin_runtime,
            )
            .await?;
            match login_phase {
                BackendLoginPhase::Ready => {
                    selected_lease = Some(lease);
                    selected_backend = Some(backend);
                    selected_backend_ref = Some(backend_ref);
                    selected_backend_stream = Some(backend_stream);
                    break;
                }
                BackendLoginPhase::RetryNextBackend(reason) => {
                    last_backend_cancel_reason = Some(reason);
                    cancelled_leases.push(lease);
                }
                BackendLoginPhase::Terminated => {
                    state.reputation().record_login_disconnect(peer.ip());
                    last_backend_cancel_reason =
                        Some("Backend closed connection during login".to_string());
                    cancelled_leases.push(lease);
                }
            }
        }

        drop(cancelled_leases);

        let Some(lease) = selected_lease else {
            state.metrics.inc_reject("no_healthy_backend");
            state.metrics.inc_login_failure("backend_unavailable");
            send_login_disconnect_best_effort(
                client,
                last_backend_cancel_reason
                    .as_deref()
                    .unwrap_or("No healthy backend available. Try again in a few seconds."),
                client_crypto.as_mut(),
            )
            .await?;
            return Ok(LoginOutcome::Rejected);
        };
        let backend = selected_backend.expect("selected backend is set with lease");
        let backend_ref = selected_backend_ref.expect("selected backend ref is set with lease");
        let mut backend_stream =
            selected_backend_stream.expect("selected backend stream is set with lease");
        let _lease = lease;

        let mut shutdown_rx = state.shutdown.subscribe();
        let shutdown_message = snapshot.config.shutdown.disconnect_message.clone();
        let mut shutdown_requested = false;

        if plugins_active {
            let player = player.expect("plugin player initialized");
            let player_meta = player_meta.expect("plugin player meta initialized");
            let (relay_control_tx, mut relay_control_rx) = mpsc::channel(64);
            let _session = plugin_runtime.sessions.register(PlayerSession::new(
                player.clone(),
                relay_control_tx,
                player_meta,
                Some(backend_ref.clone()),
            ));
            let _ = plugin_runtime
                .events
                .dispatch(Arc::new(OnBackendReady {
                    player: player.clone(),
                    backend: backend_ref.clone(),
                }))
                .await;
            let _ = plugin_runtime
                .events
                .dispatch(Arc::new(OnLoginSuccess {
                    player: player.clone(),
                }))
                .await;

            let relay_outcome = if let Some(crypto) = client_crypto {
                relay_with_control_encrypted_client(
                    client,
                    backend_stream,
                    crypto,
                    &mut shutdown_rx,
                    &mut relay_control_rx,
                    &plugin_runtime,
                    &player,
                    &backend_ref,
                    snapshot.config.limits.max_packet_size,
                    snapshot.config.plugins.intercept_plugin_messages,
                )
                .await?
            } else {
                relay_with_control_plain_client(
                    client,
                    backend_stream,
                    &mut shutdown_rx,
                    &mut relay_control_rx,
                    &plugin_runtime,
                    &player,
                    &backend_ref,
                    snapshot.config.limits.max_packet_size,
                    snapshot.config.plugins.intercept_plugin_messages,
                )
                .await?
            };

            shutdown_requested = relay_outcome.shutdown_requested;
            state
                .metrics
                .inc_backend_bytes_sent(backend.name(), relay_outcome.traffic.to_backend);
            state
                .metrics
                .inc_backend_bytes_recv(backend.name(), relay_outcome.traffic.from_backend);

            if shutdown_requested {
                let _ = send_login_disconnect_best_effort(client, &shutdown_message, None).await;
            }
            plugin_runtime.sessions.remove(&player.uuid);
            if let Some(reason) = relay_outcome.backend_disconnect_reason.clone() {
                let _ = plugin_runtime
                    .events
                    .dispatch(Arc::new(OnBackendDisconnect {
                        player: player.clone(),
                        backend: backend_ref.clone(),
                        reason,
                    }))
                    .await;
            }
            let disconnect_reason = if shutdown_requested {
                DisconnectReason::Timeout
            } else {
                relay_outcome.disconnect_reason
            };
            let _ = plugin_runtime
                .events
                .dispatch(Arc::new(OnDisconnect {
                    player,
                    reason: disconnect_reason,
                }))
                .await;
        } else {
            let relay_traffic = if let Some(crypto) = client_crypto {
                relay_with_encrypted_client(client, &mut backend_stream, crypto, &mut shutdown_rx)
                    .await?
            } else {
                let relay = copy_bidirectional(client, &mut backend_stream);
                tokio::pin!(relay);
                let mut totals = RelayTraffic::default();
                tokio::select! {
                    result = &mut relay => {
                        let (to_backend, from_backend) = result?;
                        totals.to_backend = to_backend;
                        totals.from_backend = from_backend;
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && shutdown_rx.borrow().is_some() {
                            shutdown_requested = true;
                        }
                    }
                }
                totals
            };

            state
                .metrics
                .inc_backend_bytes_sent(backend.name(), relay_traffic.to_backend);
            state
                .metrics
                .inc_backend_bytes_recv(backend.name(), relay_traffic.from_backend);

            if shutdown_requested {
                let _ = send_login_disconnect_best_effort(client, &shutdown_message, None).await;
            }
        }

        Ok(LoginOutcome::Accepted)
    }
    .await;

    state
        .metrics
        .observe_login_duration(auth_mode_label, login_started.elapsed().as_secs_f64());
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionResult {
    Success,
    Reject,
}

impl ConnectionResult {
    fn as_label(self) -> &'static str {
        match self {
            ConnectionResult::Success => "success",
            ConnectionResult::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginOutcome {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendLoginPhase {
    Ready,
    RetryNextBackend(String),
    Terminated,
}

#[derive(Default)]
struct RelayTraffic {
    to_backend: u64,
    from_backend: u64,
}

struct RelayOutcome {
    traffic: RelayTraffic,
    shutdown_requested: bool,
    disconnect_reason: DisconnectReason,
    backend_disconnect_reason: Option<String>,
}

struct ClientCrypto {
    encryptor: Cfb8Encryptor,
    decryptor: Cfb8Decryptor,
}

impl ClientCrypto {
    fn new(shared_secret: &[u8; 16]) -> Result<Self> {
        let encryptor = Cfb8Encryptor::new(shared_secret, shared_secret)
            .map_err(|_| anyhow::anyhow!("failed to initialize client encryptor"))?;
        let decryptor = Cfb8Decryptor::new(shared_secret, shared_secret)
            .map_err(|_| anyhow::anyhow!("failed to initialize client decryptor"))?;
        Ok(Self {
            encryptor,
            decryptor,
        })
    }
}

struct Cfb8Encryptor {
    cipher: Aes128,
    register: [u8; 16],
}

impl Cfb8Encryptor {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> anyhow::Result<Self> {
        let cipher = Aes128::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES key"))?;
        Ok(Self {
            cipher,
            register: *iv,
        })
    }

    fn encrypt(&mut self, buf: &mut [u8]) {
        for byte in buf {
            let mut block = GenericArray::clone_from_slice(&self.register);
            self.cipher.encrypt_block(&mut block);
            let ciphertext = *byte ^ block[0];
            self.register.copy_within(1.., 0);
            self.register[15] = ciphertext;
            *byte = ciphertext;
        }
    }
}

struct Cfb8Decryptor {
    cipher: Aes128,
    register: [u8; 16],
}

impl Cfb8Decryptor {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> anyhow::Result<Self> {
        let cipher = Aes128::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES key"))?;
        Ok(Self {
            cipher,
            register: *iv,
        })
    }

    fn decrypt(&mut self, buf: &mut [u8]) {
        for byte in buf {
            let ciphertext = *byte;
            let mut block = GenericArray::clone_from_slice(&self.register);
            self.cipher.encrypt_block(&mut block);
            let plaintext = ciphertext ^ block[0];
            self.register.copy_within(1.., 0);
            self.register[15] = ciphertext;
            *byte = plaintext;
        }
    }
}

#[derive(Debug, Clone)]
struct AuthenticatedIdentity {
    uuid_bytes: [u8; 16],
    username: String,
    properties: Vec<VelocityProperty>,
}

#[derive(Debug, Deserialize)]
struct MojangHasJoinedProfile {
    id: String,
    name: String,
    #[serde(default)]
    properties: Vec<MojangProperty>,
}

#[derive(Debug, Clone, Deserialize)]
struct MojangProperty {
    name: String,
    value: String,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MojangAuthError {
    AuthenticationFailed,
    CircuitOpen,
    ServiceUnavailable,
}

#[allow(clippy::too_many_arguments)]
async fn run_backend_login_intercept(
    client: &mut TcpStream,
    client_crypto: Option<&mut ClientCrypto>,
    backend: &mut TcpStream,
    max_packet_size: usize,
    login_timeout: Duration,
    velocity_enabled: bool,
    client_ip: &str,
    identity: &AuthenticatedIdentity,
    secret: &str,
    peer: SocketAddr,
    player: Option<&ProxiedPlayer>,
    backend_ref: &BackendRef,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
) -> Result<BackendLoginPhase> {
    let mut compression_threshold: Option<i32> = None;
    let mut client_crypto = client_crypto;
    let intercept_read_timeout = login_timeout.min(Duration::from_millis(250));
    loop {
        let raw_packet = match timeout(
            intercept_read_timeout,
            read_packet(backend, max_packet_size),
        )
        .await
        {
            Ok(Ok(packet)) => packet,
            Ok(Err(err)) if is_connection_closed_error(&err) => {
                return Ok(BackendLoginPhase::Terminated);
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                debug!(peer = %peer, "backend login intercept timeout, falling back to relay");
                return Ok(BackendLoginPhase::Ready);
            }
        };
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
                if let Some(player) = player {
                    player.set_meta("vex.compression_threshold", threshold);
                }
                tracing::debug!(
                    "backend enabled compression threshold={} peer={}",
                    threshold,
                    peer
                );
                let crypto = client_crypto.as_deref_mut();
                write_client_packet(client, &raw_packet, crypto).await?;
                continue;
            }
            0x04 => {
                if velocity_enabled {
                    let Some(request) = parse_login_plugin_request(&packet)? else {
                        bail!("failed to parse login plugin request");
                    };
                    let _request_data_len = request.data.len();
                    if request.channel == "velocity:player_info" {
                        let payload = build_velocity_modern_forwarding_payload(
                            client_ip,
                            identity.uuid_bytes,
                            &identity.username,
                            &identity.properties,
                        );
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
                } else {
                    let crypto = client_crypto.as_deref_mut();
                    write_client_packet(client, &raw_packet, crypto).await?;
                }
            }
            0x02 => {
                tracing::debug!("received login success from backend peer={}", peer);
                let crypto = client_crypto.as_deref_mut();
                write_client_packet(client, &raw_packet, crypto).await?;
                return Ok(BackendLoginPhase::Ready);
            }
            0x00 => {
                let message = parse_disconnect_message(&packet)
                    .unwrap_or_else(|| "Disconnected by backend".to_string());
                if let Some(player) = player {
                    let kick_event = Arc::new(OnBackendKick::new(
                        player.clone(),
                        backend_ref.clone(),
                        message.clone(),
                    ));
                    let kick_event = plugin_runtime.events.dispatch(kick_event).await;
                    if kick_event.is_cancelled() {
                        return Ok(BackendLoginPhase::RetryNextBackend(
                            kick_event
                                .cancel_reason()
                                .unwrap_or("Backend rejected connection")
                                .to_string(),
                        ));
                    }
                }
                let crypto = client_crypto.as_deref_mut();
                write_client_packet(client, &raw_packet, crypto).await?;
                return Ok(BackendLoginPhase::Terminated);
            }
            _ => {
                warn!(
                    "unexpected backend packet id={:#04x} peer={}",
                    packet_id, peer
                );
                let crypto = client_crypto.as_deref_mut();
                write_client_packet(client, &raw_packet, crypto).await?;
                return Ok(BackendLoginPhase::Ready);
            }
        }
    }
}

async fn send_login_disconnect_best_effort(
    stream: &mut TcpStream,
    message: &str,
    client_crypto: Option<&mut ClientCrypto>,
) -> Result<()> {
    let payload = build_login_disconnect(message);
    let _ = write_client_packet(stream, &payload, client_crypto).await;
    Ok(())
}

async fn authenticate_online(
    state: &RuntimeState,
    username: &str,
    server_hash: &str,
    _login_timeout: Duration,
) -> Result<MojangHasJoinedProfile, MojangAuthError> {
    let circuit = state.auth_circuit();
    if !circuit.allow_request() {
        return Err(MojangAuthError::CircuitOpen);
    }

    let client = state.mojang_client();
    let base_url = state.mojang_session_base_url();
    match request_mojang_profile(client.as_ref(), base_url.as_str(), username, server_hash).await {
        Ok(profile) => {
            circuit.record_success();
            Ok(profile)
        }
        Err(MojangAuthError::AuthenticationFailed) => {
            circuit.record_success();
            Err(MojangAuthError::AuthenticationFailed)
        }
        Err(MojangAuthError::ServiceUnavailable) => {
            circuit.record_failure();
            if circuit.state() == CircuitState::Open {
                warn!("mojang auth circuit opened after failure");
            }
            Err(MojangAuthError::ServiceUnavailable)
        }
        Err(MojangAuthError::CircuitOpen) => Err(MojangAuthError::CircuitOpen),
    }
}

async fn request_mojang_profile(
    client: &reqwest::Client,
    base_url: &str,
    username: &str,
    server_hash: &str,
) -> Result<MojangHasJoinedProfile, MojangAuthError> {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let url = format!("{base_url}/session/minecraft/hasJoined");
        let response = client
            .get(url)
            .query(&[("username", username), ("serverId", server_hash)])
            .send()
            .await;

        match response {
            Ok(resp) if resp.status() == reqwest::StatusCode::OK => {
                let profile = resp
                    .json::<MojangHasJoinedProfile>()
                    .await
                    .map_err(|_| MojangAuthError::ServiceUnavailable)?;
                return Ok(profile);
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NO_CONTENT => {
                return Err(MojangAuthError::AuthenticationFailed);
            }
            Ok(resp) if resp.status().is_client_error() => {
                return Err(MojangAuthError::AuthenticationFailed);
            }
            Ok(resp) if resp.status().is_server_error() => {
                if attempt < 2 {
                    jitter_sleep().await;
                    continue;
                }
                return Err(MojangAuthError::ServiceUnavailable);
            }
            Ok(_) => {
                return Err(MojangAuthError::AuthenticationFailed);
            }
            Err(_err) => {
                if attempt < 2 {
                    jitter_sleep().await;
                    continue;
                }
                return Err(MojangAuthError::ServiceUnavailable);
            }
        }
    }
}

async fn jitter_sleep() {
    let millis = thread_rng().gen_range(100..=300);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

fn random_ascii(len: usize) -> String {
    Alphanumeric.sample_string(&mut thread_rng(), len)
}

fn compute_minecraft_server_hash(
    server_id: &str,
    shared_secret: &[u8],
    public_key_der: &[u8],
) -> String {
    let mut sha = Sha1::new();
    sha.update(server_id.as_bytes());
    sha.update(shared_secret);
    sha.update(public_key_der);
    let digest: [u8; 20] = sha.finalize().into();
    minecraft_signed_hex_digest(&digest)
}

fn minecraft_signed_hex_digest(digest: &[u8; 20]) -> String {
    let mut signed_bytes = digest.to_vec();
    let negative = (signed_bytes[0] & 0x80) != 0;
    if negative {
        for byte in &mut signed_bytes {
            *byte = !*byte;
        }
        let mut carry = true;
        for byte in signed_bytes.iter_mut().rev() {
            if carry {
                let (next, overflow) = byte.overflowing_add(1);
                *byte = next;
                carry = overflow;
            }
        }
    }

    let mut first_non_zero = 0usize;
    while first_non_zero < signed_bytes.len() && signed_bytes[first_non_zero] == 0 {
        first_non_zero += 1;
    }
    let mut hex = String::new();
    if first_non_zero == signed_bytes.len() {
        hex.push('0');
    } else {
        for byte in &signed_bytes[first_non_zero..] {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
    }

    if negative { format!("-{hex}") } else { hex }
}

fn parse_mojang_uuid_bytes(id: &str) -> Result<[u8; 16]> {
    if id.len() != 32 {
        bail!("mojang uuid id must be 32 hex chars");
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let chunk = &id[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(chunk, 16)
            .map_err(|_| anyhow::anyhow!("invalid mojang uuid hex"))?;
    }
    Ok(out)
}

async fn read_client_packet(
    client: &mut TcpStream,
    max_packet_size: usize,
    client_crypto: Option<&mut ClientCrypto>,
) -> Result<Vec<u8>> {
    let Some(client_crypto) = client_crypto else {
        return Ok(read_packet(client, max_packet_size).await?);
    };

    let mut raw_len = Vec::with_capacity(5);
    loop {
        let mut encrypted_byte = [0u8; 1];
        client.read_exact(&mut encrypted_byte).await?;
        client_crypto.decryptor.decrypt(&mut encrypted_byte);
        raw_len.push(encrypted_byte[0]);
        if encrypted_byte[0] & 0x80 == 0 {
            break;
        }
        if raw_len.len() > 5 {
            bail!("bad varint header");
        }
    }
    let (packet_len, _) = parse_varint(&raw_len)?;
    if packet_len <= 0 {
        bail!("packet length must be positive");
    }
    let packet_len = packet_len as usize;
    if packet_len > max_packet_size {
        bail!("packet too large");
    }

    let mut payload = vec![0u8; packet_len];
    client.read_exact(&mut payload).await?;
    client_crypto.decryptor.decrypt(&mut payload);
    Ok(payload)
}

async fn write_client_packet(
    client: &mut TcpStream,
    payload: &[u8],
    client_crypto: Option<&mut ClientCrypto>,
) -> Result<()> {
    let Some(client_crypto) = client_crypto else {
        write_packet(client, payload).await?;
        return Ok(());
    };

    let mut header = bytes::BytesMut::with_capacity(5);
    write_varint(payload.len() as i32, &mut header);
    let mut frame = Vec::with_capacity(header.len() + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    client_crypto.encryptor.encrypt(&mut frame);
    client.write_all(&frame).await?;
    Ok(())
}

fn player_compression_threshold(player: &ProxiedPlayer) -> Option<i32> {
    player.get_meta::<i32>("vex.compression_threshold")
}

fn encode_generated_play_packet_for_player(
    player: &ProxiedPlayer,
    payload: &[u8],
) -> Result<Vec<u8>> {
    encode_login_packet_for_backend(payload, player_compression_threshold(player))
}

fn build_internal_clientbound_message_packet(
    player: &ProxiedPlayer,
    channel: &str,
    data: &[u8],
) -> Option<Vec<u8>> {
    if channel.eq_ignore_ascii_case("vex:chat") || channel.eq_ignore_ascii_case("vex:broadcast") {
        let message = std::str::from_utf8(data).ok()?;
        return build_play_system_chat_packet(player.protocol_version, message, false);
    }

    build_play_plugin_message_packet(player.protocol_version, true, channel, data)
}

#[allow(clippy::too_many_arguments, unused_assignments)]
async fn relay_with_control_plain_client(
    client: &mut TcpStream,
    mut backend: TcpStream,
    shutdown_rx: &mut tokio::sync::watch::Receiver<Option<String>>,
    relay_control_rx: &mut mpsc::Receiver<RelayCommand>,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    initial_backend: &BackendRef,
    max_packet_size: usize,
    intercept_plugin_messages: bool,
) -> Result<RelayOutcome> {
    let mut current_backend = initial_backend.clone();
    let mut paused = false;
    let mut shutdown_requested = false;
    let mut disconnect_reason = None;
    let mut backend_disconnect_reason = None;
    let mut totals = RelayTraffic::default();
    let mut client_to_backend = vec![0u8; 16 * 1024];
    let mut backend_to_client = vec![0u8; 16 * 1024];
    if intercept_plugin_messages {
        loop {
            tokio::select! {
                Some(cmd) = relay_control_rx.recv() => {
                    match cmd {
                        RelayCommand::Pause { ack } => {
                            paused = true;
                            let _ = ack.send(());
                        }
                        RelayCommand::Resume => {
                            paused = false;
                        }
                        RelayCommand::SwitchBackend { stream, backend: to_backend, ack } => {
                            let switch_result = apply_backend_switch(
                                client,
                                &mut backend,
                                None,
                                stream,
                                to_backend,
                                plugin_runtime,
                                player,
                                &mut current_backend,
                            ).await;
                            let switched_ok = switch_result.is_ok();
                            let _ = ack.send(switch_result);
                            if switched_ok {
                                paused = false;
                            }
                        }
                        RelayCommand::Disconnect(reason) => {
                            let payload = build_login_disconnect(&reason);
                            let _ = write_packet(client, &payload).await;
                            let _ = client.shutdown().await;
                            let _ = backend.shutdown().await;
                            disconnect_reason = Some(DisconnectReason::PluginDisconnected);
                            break;
                        }
                        RelayCommand::PluginMessage { channel, data } => {
                            if let Some(packet) = build_internal_clientbound_message_packet(
                                player,
                                channel.as_ref(),
                                &data,
                            ) {
                                let encoded =
                                    encode_generated_play_packet_for_player(player, &packet)?;
                                write_packet(client, &encoded).await?;
                            }
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && shutdown_rx.borrow().is_some() {
                        shutdown_requested = true;
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        break;
                    }
                }
                packet = read_packet(client, max_packet_size), if !paused => {
                    match packet {
                        Ok(packet_vec) => {
                            let packet_bytes = bytes::Bytes::from(packet_vec);
                            if should_forward_plugin_message_event(
                                plugin_runtime,
                                player,
                                &packet_bytes,
                                false,
                                true,
                            ).await {
                                write_packet(&mut backend, packet_bytes.as_ref()).await?;
                                totals.to_backend = totals.to_backend.saturating_add(packet_bytes.len() as u64);
                            }
                        }
                        Err(err) if is_connection_closed_error(&err) => {
                            disconnect_reason = Some(DisconnectReason::ClientLeft);
                            break;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                packet = read_packet(&mut backend, max_packet_size), if !paused => {
                    match packet {
                        Ok(packet_vec) => {
                            let packet_bytes = bytes::Bytes::from(packet_vec);
                            if let Some(kick_message) =
                                parse_play_disconnect_message(packet_bytes.as_ref(), player.protocol_version)
                            {
                                let backend_before_kick = current_backend.clone();
                                let kick_event = Arc::new(OnBackendKick::new(
                                    player.clone(),
                                    current_backend.clone(),
                                    kick_message.clone(),
                                ));
                                let kick_event = dispatch_backend_kick_with_relay_plain(
                                    plugin_runtime,
                                    relay_control_rx,
                                    client,
                                    &mut backend,
                                    player,
                                    &mut current_backend,
                                    kick_event,
                                )
                                .await;
                                if kick_event.is_cancelled()
                                    || current_backend.name() != backend_before_kick.name()
                                {
                                    continue;
                                }
                                write_packet(client, packet_bytes.as_ref()).await?;
                                totals.from_backend =
                                    totals.from_backend.saturating_add(packet_bytes.len() as u64);
                                disconnect_reason = Some(DisconnectReason::BackendKicked(
                                    kick_message.clone(),
                                ));
                                backend_disconnect_reason = Some(kick_message);
                                break;
                            }
                            if should_forward_plugin_message_event(
                                plugin_runtime,
                                player,
                                &packet_bytes,
                                true,
                                true,
                            ).await {
                                write_packet(client, packet_bytes.as_ref()).await?;
                                totals.from_backend = totals.from_backend.saturating_add(packet_bytes.len() as u64);
                            }
                        }
                        Err(err) if is_connection_closed_error(&err) => {
                            disconnect_reason = Some(DisconnectReason::Timeout);
                            backend_disconnect_reason =
                                Some(format!("backend connection closed: {}", err.kind()));
                            break;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }
    } else {
        loop {
            tokio::select! {
                Some(cmd) = relay_control_rx.recv() => {
                    match cmd {
                        RelayCommand::Pause { ack } => {
                            paused = true;
                            let _ = ack.send(());
                        }
                        RelayCommand::Resume => {
                            paused = false;
                        }
                        RelayCommand::SwitchBackend { stream, backend: to_backend, ack } => {
                            let switch_result = apply_backend_switch(
                                client,
                                &mut backend,
                                None,
                                stream,
                                to_backend,
                                plugin_runtime,
                                player,
                                &mut current_backend,
                            ).await;
                            let switched_ok = switch_result.is_ok();
                            let _ = ack.send(switch_result);
                            if switched_ok {
                                paused = false;
                            }
                        }
                        RelayCommand::Disconnect(reason) => {
                            let payload = build_login_disconnect(&reason);
                            let _ = write_packet(client, &payload).await;
                            let _ = client.shutdown().await;
                            let _ = backend.shutdown().await;
                            disconnect_reason = Some(DisconnectReason::PluginDisconnected);
                            break;
                        }
                        RelayCommand::PluginMessage { channel, data } => {
                            if let Some(packet) = build_internal_clientbound_message_packet(
                                player,
                                channel.as_ref(),
                                &data,
                            ) {
                                let encoded =
                                    encode_generated_play_packet_for_player(player, &packet)?;
                                write_packet(client, &encoded).await?;
                            }
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && shutdown_rx.borrow().is_some() {
                        shutdown_requested = true;
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        break;
                    }
                }
                read = client.read(&mut client_to_backend), if !paused => {
                    let n = read?;
                    if n == 0 {
                        disconnect_reason = Some(DisconnectReason::ClientLeft);
                        break;
                    }
                    backend.write_all(&client_to_backend[..n]).await?;
                    totals.to_backend = totals.to_backend.saturating_add(n as u64);
                }
                read = backend.read(&mut backend_to_client), if !paused => {
                    let n = read?;
                    if n == 0 {
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        backend_disconnect_reason = Some("backend connection closed".to_string());
                        break;
                    }
                    client.write_all(&backend_to_client[..n]).await?;
                    totals.from_backend = totals.from_backend.saturating_add(n as u64);
                }
            }
        }
    }

    Ok(RelayOutcome {
        traffic: totals,
        shutdown_requested,
        disconnect_reason: disconnect_reason.unwrap_or(DisconnectReason::ClientLeft),
        backend_disconnect_reason,
    })
}

#[allow(clippy::too_many_arguments, unused_assignments)]
async fn relay_with_control_encrypted_client(
    client: &mut TcpStream,
    mut backend: TcpStream,
    mut client_crypto: ClientCrypto,
    shutdown_rx: &mut tokio::sync::watch::Receiver<Option<String>>,
    relay_control_rx: &mut mpsc::Receiver<RelayCommand>,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    initial_backend: &BackendRef,
    _max_packet_size: usize,
    intercept_plugin_messages: bool,
) -> Result<RelayOutcome> {
    let mut current_backend = initial_backend.clone();
    let mut paused = false;
    let mut shutdown_requested = false;
    let mut disconnect_reason = None;
    let mut backend_disconnect_reason = None;
    let mut totals = RelayTraffic::default();
    let mut client_to_backend = vec![0u8; 16 * 1024];
    let mut backend_to_client = vec![0u8; 16 * 1024];
    if intercept_plugin_messages {
        loop {
            tokio::select! {
                Some(cmd) = relay_control_rx.recv() => {
                    match cmd {
                        RelayCommand::Pause { ack } => {
                            paused = true;
                            let _ = ack.send(());
                        }
                        RelayCommand::Resume => {
                            paused = false;
                        }
                        RelayCommand::SwitchBackend { stream, backend: to_backend, ack } => {
                            let switch_result = apply_backend_switch(
                                client,
                                &mut backend,
                                Some(&mut client_crypto),
                                stream,
                                to_backend,
                                plugin_runtime,
                                player,
                                &mut current_backend,
                            ).await;
                            let switched_ok = switch_result.is_ok();
                            let _ = ack.send(switch_result);
                            if switched_ok {
                                paused = false;
                            }
                        }
                        RelayCommand::Disconnect(reason) => {
                            let payload = build_login_disconnect(&reason);
                            let _ = write_client_packet(client, &payload, Some(&mut client_crypto)).await;
                            let _ = client.shutdown().await;
                            let _ = backend.shutdown().await;
                            disconnect_reason = Some(DisconnectReason::PluginDisconnected);
                            break;
                        }
                        RelayCommand::PluginMessage { channel, data } => {
                            if let Some(packet) = build_internal_clientbound_message_packet(
                                player,
                                channel.as_ref(),
                                &data,
                            ) {
                                let encoded =
                                    encode_generated_play_packet_for_player(player, &packet)?;
                                write_client_packet(client, &encoded, Some(&mut client_crypto))
                                    .await?;
                            }
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && shutdown_rx.borrow().is_some() {
                        shutdown_requested = true;
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        break;
                    }
                }
                packet = read_client_packet(client, _max_packet_size, Some(&mut client_crypto)), if !paused => {
                    match packet {
                        Ok(packet_vec) => {
                            let packet_bytes = bytes::Bytes::from(packet_vec);
                            if should_forward_plugin_message_event(
                                plugin_runtime,
                                player,
                                &packet_bytes,
                                false,
                                true,
                            ).await {
                                write_packet(&mut backend, packet_bytes.as_ref()).await?;
                                totals.to_backend = totals.to_backend.saturating_add(packet_bytes.len() as u64);
                            }
                        }
                        Err(err) if is_connection_closed_anyhow(&err) => {
                            disconnect_reason = Some(DisconnectReason::ClientLeft);
                            break;
                        }
                        Err(err) => return Err(err),
                    }
                }
                packet = read_packet(&mut backend, _max_packet_size), if !paused => {
                    match packet {
                        Ok(packet_vec) => {
                            let packet_bytes = bytes::Bytes::from(packet_vec);
                            if let Some(kick_message) =
                                parse_play_disconnect_message(packet_bytes.as_ref(), player.protocol_version)
                            {
                                let backend_before_kick = current_backend.clone();
                                let kick_event = Arc::new(OnBackendKick::new(
                                    player.clone(),
                                    current_backend.clone(),
                                    kick_message.clone(),
                                ));
                                let kick_event = dispatch_backend_kick_with_relay_encrypted(
                                    plugin_runtime,
                                    relay_control_rx,
                                    client,
                                    &mut backend,
                                    &mut client_crypto,
                                    player,
                                    &mut current_backend,
                                    kick_event,
                                )
                                .await;
                                if kick_event.is_cancelled()
                                    || current_backend.name() != backend_before_kick.name()
                                {
                                    continue;
                                }
                                write_client_packet(client, packet_bytes.as_ref(), Some(&mut client_crypto)).await?;
                                totals.from_backend =
                                    totals.from_backend.saturating_add(packet_bytes.len() as u64);
                                disconnect_reason = Some(DisconnectReason::BackendKicked(
                                    kick_message.clone(),
                                ));
                                backend_disconnect_reason = Some(kick_message);
                                break;
                            }
                            if should_forward_plugin_message_event(
                                plugin_runtime,
                                player,
                                &packet_bytes,
                                true,
                                true,
                            ).await {
                                write_client_packet(client, packet_bytes.as_ref(), Some(&mut client_crypto)).await?;
                                totals.from_backend = totals.from_backend.saturating_add(packet_bytes.len() as u64);
                            }
                        }
                        Err(err) if is_connection_closed_error(&err) => {
                            disconnect_reason = Some(DisconnectReason::Timeout);
                            backend_disconnect_reason =
                                Some(format!("backend connection closed: {}", err.kind()));
                            break;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }
    } else {
        loop {
            tokio::select! {
                Some(cmd) = relay_control_rx.recv() => {
                    match cmd {
                        RelayCommand::Pause { ack } => {
                            paused = true;
                            let _ = ack.send(());
                        }
                        RelayCommand::Resume => {
                            paused = false;
                        }
                        RelayCommand::SwitchBackend { stream, backend: to_backend, ack } => {
                            let switch_result = apply_backend_switch(
                                client,
                                &mut backend,
                                Some(&mut client_crypto),
                                stream,
                                to_backend,
                                plugin_runtime,
                                player,
                                &mut current_backend,
                            ).await;
                            let switched_ok = switch_result.is_ok();
                            let _ = ack.send(switch_result);
                            if switched_ok {
                                paused = false;
                            }
                        }
                        RelayCommand::Disconnect(reason) => {
                            let payload = build_login_disconnect(&reason);
                            let _ = write_client_packet(client, &payload, Some(&mut client_crypto)).await;
                            let _ = client.shutdown().await;
                            let _ = backend.shutdown().await;
                            disconnect_reason = Some(DisconnectReason::PluginDisconnected);
                            break;
                        }
                        RelayCommand::PluginMessage { channel, data } => {
                            if let Some(packet) = build_internal_clientbound_message_packet(
                                player,
                                channel.as_ref(),
                                &data,
                            ) {
                                let encoded =
                                    encode_generated_play_packet_for_player(player, &packet)?;
                                write_client_packet(client, &encoded, Some(&mut client_crypto))
                                    .await?;
                            }
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && shutdown_rx.borrow().is_some() {
                        shutdown_requested = true;
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        break;
                    }
                }
                read = client.read(&mut client_to_backend), if !paused => {
                    let n = read?;
                    if n == 0 {
                        disconnect_reason = Some(DisconnectReason::ClientLeft);
                        break;
                    }
                    client_crypto.decryptor.decrypt(&mut client_to_backend[..n]);
                    backend.write_all(&client_to_backend[..n]).await?;
                    totals.to_backend = totals.to_backend.saturating_add(n as u64);
                }
                read = backend.read(&mut backend_to_client), if !paused => {
                    let n = read?;
                    if n == 0 {
                        disconnect_reason = Some(DisconnectReason::Timeout);
                        backend_disconnect_reason = Some("backend connection closed".to_string());
                        break;
                    }
                    client_crypto.encryptor.encrypt(&mut backend_to_client[..n]);
                    client.write_all(&backend_to_client[..n]).await?;
                    totals.from_backend = totals.from_backend.saturating_add(n as u64);
                }
            }
        }
    }

    Ok(RelayOutcome {
        traffic: totals,
        shutdown_requested,
        disconnect_reason: disconnect_reason.unwrap_or(DisconnectReason::ClientLeft),
        backend_disconnect_reason,
    })
}

#[allow(clippy::too_many_arguments)]
async fn apply_backend_switch(
    client: &mut TcpStream,
    backend: &mut TcpStream,
    client_crypto: Option<&mut ClientCrypto>,
    new_stream: TcpStream,
    to_backend: BackendRef,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    current_backend: &mut BackendRef,
) -> Result<(), String> {
    let _ = backend.shutdown().await;
    *backend = new_stream;

    let respawn = build_respawn_packet(player.protocol_version);
    if !respawn.is_empty() {
        if let Err(err) = write_client_packet(client, &respawn, client_crypto).await {
            return Err(format!("failed to send respawn packet: {err:#}"));
        }
    } else {
        let fallback = build_login_disconnect(&format!("Transferred to {}", to_backend.name()));
        if let Err(err) = write_client_packet(client, &fallback, client_crypto).await {
            return Err(format!("failed to send transfer fallback packet: {err:#}"));
        }
    }

    if let Some(session) = plugin_runtime.sessions.get(&player.uuid) {
        session.set_backend(Some(to_backend.clone()));
    }

    let switch_event = Arc::new(OnBackendSwitch {
        player: player.clone(),
        from: current_backend.clone(),
        to: to_backend.clone(),
    });
    let _ = plugin_runtime.events.dispatch(switch_event).await;
    *current_backend = to_backend;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_backend_kick_with_relay_plain(
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    relay_control_rx: &mut mpsc::Receiver<RelayCommand>,
    client: &mut TcpStream,
    backend: &mut TcpStream,
    player: &ProxiedPlayer,
    current_backend: &mut BackendRef,
    kick_event: Arc<OnBackendKick>,
) -> Arc<OnBackendKick> {
    let kick_timeout = Duration::from_millis(500);
    let fallback_event = kick_event.clone();
    let dispatch_events = plugin_runtime.events.clone();
    let dispatch_event = kick_event.clone();
    let mut dispatch_task = tokio::spawn(async move {
        dispatch_events
            .dispatch_with_timeout(dispatch_event, kick_timeout)
            .await
    });
    let timeout_duration = tokio::time::sleep(kick_timeout);
    tokio::pin!(timeout_duration);

    loop {
        tokio::select! {
            result = &mut dispatch_task => {
                return match result {
                    Ok(event) => event,
                    Err(_) => fallback_event,
                };
            }
            _ = &mut timeout_duration => {
                dispatch_task.abort();
                return fallback_event;
            }
            Some(cmd) = relay_control_rx.recv() => {
                handle_relay_command_during_kick_plain(
                    cmd,
                    client,
                    backend,
                    plugin_runtime,
                    player,
                    current_backend,
                )
                .await;
            }
            else => {
                return fallback_event;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_backend_kick_with_relay_encrypted(
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    relay_control_rx: &mut mpsc::Receiver<RelayCommand>,
    client: &mut TcpStream,
    backend: &mut TcpStream,
    client_crypto: &mut ClientCrypto,
    player: &ProxiedPlayer,
    current_backend: &mut BackendRef,
    kick_event: Arc<OnBackendKick>,
) -> Arc<OnBackendKick> {
    let kick_timeout = Duration::from_millis(500);
    let fallback_event = kick_event.clone();
    let dispatch_events = plugin_runtime.events.clone();
    let dispatch_event = kick_event.clone();
    let mut dispatch_task = tokio::spawn(async move {
        dispatch_events
            .dispatch_with_timeout(dispatch_event, kick_timeout)
            .await
    });
    let timeout_duration = tokio::time::sleep(kick_timeout);
    tokio::pin!(timeout_duration);

    loop {
        tokio::select! {
            result = &mut dispatch_task => {
                return match result {
                    Ok(event) => event,
                    Err(_) => fallback_event,
                };
            }
            _ = &mut timeout_duration => {
                dispatch_task.abort();
                return fallback_event;
            }
            Some(cmd) = relay_control_rx.recv() => {
                handle_relay_command_during_kick_encrypted(
                    cmd,
                    client,
                    backend,
                    client_crypto,
                    plugin_runtime,
                    player,
                    current_backend,
                )
                .await;
            }
            else => {
                return fallback_event;
            }
        }
    }
}

async fn handle_relay_command_during_kick_plain(
    cmd: RelayCommand,
    client: &mut TcpStream,
    backend: &mut TcpStream,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    current_backend: &mut BackendRef,
) {
    match cmd {
        RelayCommand::Pause { ack } => {
            let _ = ack.send(());
        }
        RelayCommand::Resume => {}
        RelayCommand::SwitchBackend {
            stream,
            backend: to_backend,
            ack,
        } => {
            let switch_result = apply_backend_switch(
                client,
                backend,
                None,
                stream,
                to_backend,
                plugin_runtime,
                player,
                current_backend,
            )
            .await;
            let _ = ack.send(switch_result);
        }
        RelayCommand::Disconnect(reason) => {
            let payload = build_login_disconnect(&reason);
            let _ = write_packet(client, &payload).await;
            let _ = client.shutdown().await;
            let _ = backend.shutdown().await;
        }
        RelayCommand::PluginMessage { channel, data } => {
            if let Some(packet) =
                build_internal_clientbound_message_packet(player, channel.as_ref(), &data)
            {
                if let Ok(encoded) = encode_generated_play_packet_for_player(player, &packet) {
                    let _ = write_packet(client, &encoded).await;
                }
            }
        }
    }
}

async fn handle_relay_command_during_kick_encrypted(
    cmd: RelayCommand,
    client: &mut TcpStream,
    backend: &mut TcpStream,
    client_crypto: &mut ClientCrypto,
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    current_backend: &mut BackendRef,
) {
    match cmd {
        RelayCommand::Pause { ack } => {
            let _ = ack.send(());
        }
        RelayCommand::Resume => {}
        RelayCommand::SwitchBackend {
            stream,
            backend: to_backend,
            ack,
        } => {
            let switch_result = apply_backend_switch(
                client,
                backend,
                Some(client_crypto),
                stream,
                to_backend,
                plugin_runtime,
                player,
                current_backend,
            )
            .await;
            let _ = ack.send(switch_result);
        }
        RelayCommand::Disconnect(reason) => {
            let payload = build_login_disconnect(&reason);
            let _ = write_client_packet(client, &payload, Some(client_crypto)).await;
            let _ = client.shutdown().await;
            let _ = backend.shutdown().await;
        }
        RelayCommand::PluginMessage { channel, data } => {
            if let Some(packet) =
                build_internal_clientbound_message_packet(player, channel.as_ref(), &data)
            {
                if let Ok(encoded) = encode_generated_play_packet_for_player(player, &packet) {
                    let _ = write_client_packet(client, &encoded, Some(client_crypto)).await;
                }
            }
        }
    }
}

async fn should_forward_plugin_message_event(
    plugin_runtime: &Arc<crate::state::PluginRuntime>,
    player: &ProxiedPlayer,
    packet: &bytes::Bytes,
    clientbound: bool,
    intercept_plugin_messages: bool,
) -> bool {
    if !intercept_plugin_messages {
        return true;
    }

    match parse_play_plugin_message_packet(packet.as_ref(), player.protocol_version, clientbound) {
        Ok(Some((channel, offset))) => {
            let data = packet.slice(offset..);
            let event = Arc::new(OnPluginMessage::new(player.clone(), channel, data));
            let dispatched = plugin_runtime
                .events
                .dispatch_with_timeout(event, Duration::from_millis(100))
                .await;
            !dispatched.cancellation.is_cancelled()
        }
        Ok(None) => true,
        Err(err) => {
            warn!(
                player = %player.username,
                error = %format!("{err:#}"),
                "failed to parse plugin message packet, forwarding packet unchanged"
            );
            true
        }
    }
}

fn is_connection_closed_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

fn is_connection_closed_anyhow(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(is_connection_closed_error)
    })
}

fn parse_disconnect_message(packet: &[u8]) -> Option<String> {
    let (packet_id, mut offset) = parse_varint(packet).ok()?;
    if packet_id != 0 {
        return None;
    }
    let (len, read) = parse_varint(&packet[offset..]).ok()?;
    if len < 0 {
        return None;
    }
    offset += read;
    let len = len as usize;
    if packet.len() < offset + len {
        return None;
    }
    let raw = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(text) = parsed.get("text").and_then(serde_json::Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(text) = parsed.as_str() {
            return Some(text.to_string());
        }
    }
    Some(raw.to_string())
}

fn parse_play_disconnect_message(packet: &[u8], protocol: u32) -> Option<String> {
    if protocol != 774 {
        return None;
    }

    let (packet_id, mut offset) = parse_varint(packet).ok()?;
    if packet_id != 0x1D {
        // Fallback for protocol tables that map disconnect to a different id:
        // only treat as disconnect when payload is exactly a single chat component.
        let (len, read) = parse_varint(&packet[offset..]).ok()?;
        if len < 0 {
            return None;
        }
        offset += read;
        let len = len as usize;
        let end = offset + len;
        if end != packet.len() {
            return None;
        }
        let raw = std::str::from_utf8(&packet[offset..end]).ok()?;
        return Some(parse_disconnect_text_component(raw));
    }

    let (len, read) = parse_varint(&packet[offset..]).ok()?;
    if len < 0 {
        return None;
    }
    offset += read;
    let len = len as usize;
    let end = offset + len;
    if packet.len() < end {
        return None;
    }
    let raw = std::str::from_utf8(&packet[offset..end]).ok()?;
    Some(parse_disconnect_text_component(raw))
}

fn parse_disconnect_text_component(raw: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(text) = parsed.get("text").and_then(serde_json::Value::as_str) {
            return text.to_string();
        }
        if let Some(text) = parsed.as_str() {
            return text.to_string();
        }
    }
    raw.to_string()
}

async fn relay_with_encrypted_client(
    client: &mut TcpStream,
    backend: &mut TcpStream,
    mut client_crypto: ClientCrypto,
    shutdown_rx: &mut tokio::sync::watch::Receiver<Option<String>>,
) -> Result<RelayTraffic> {
    let (mut client_reader, mut client_writer) = client.split();
    let (mut backend_reader, mut backend_writer) = backend.split();
    let mut client_to_backend = vec![0u8; 16 * 1024];
    let mut backend_to_client = vec![0u8; 16 * 1024];
    let mut totals = RelayTraffic::default();

    loop {
        tokio::select! {
            read = client_reader.read(&mut client_to_backend) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                client_crypto.decryptor.decrypt(&mut client_to_backend[..n]);
                backend_writer.write_all(&client_to_backend[..n]).await?;
                totals.to_backend = totals.to_backend.saturating_add(n as u64);
            }
            read = backend_reader.read(&mut backend_to_client) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                client_crypto.encryptor.encrypt(&mut backend_to_client[..n]);
                client_writer.write_all(&backend_to_client[..n]).await?;
                totals.from_backend = totals.from_backend.saturating_add(n as u64);
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && shutdown_rx.borrow().is_some() {
                    break;
                }
            }
        }
    }
    Ok(totals)
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::auth_circuit::AuthCircuitBreaker;
    use crate::backend::BackendPool;
    use crate::config::{BackendConfig, Config};
    use crate::mc::{
        build_handshake_packet, build_login_disconnect, build_login_plugin_request,
        build_login_start_packet, build_play_plugin_message_packet,
        decode_login_packet_from_backend, encode_login_packet_for_backend, offline_uuid,
        parse_login_plugin_response, parse_play_plugin_message_packet, parse_varint,
        parse_velocity_modern_forwarding_payload, sign_hmac_sha256, write_varint,
    };
    use crate::metrics::Metrics;
    use crate::protocol_map::ProtocolMap;
    use crate::state::RuntimeState;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn minecraft_hash_matches_known_notch_vector() {
        let mut sha = Sha1::new();
        sha.update(b"Notch");
        let digest: [u8; 20] = sha.finalize().into();
        assert_eq!(
            minecraft_signed_hex_digest(&digest),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );
    }

    #[test]
    fn parse_mojang_uuid_hyphenless_id() {
        let id = "069a79f444e94726a5befca90e38aaf5";
        let parsed = parse_mojang_uuid_bytes(id).expect("must parse uuid bytes");
        let expected = *Uuid::parse_str("069a79f4-44e9-4726-a5be-fca90e38aaf5")
            .expect("uuid parse")
            .as_bytes();
        assert_eq!(parsed, expected);
    }

    #[tokio::test]
    async fn mojang_mock_200_allows_authentication() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/session/minecraft/hasJoined"))
            .and(query_param("username", "Player"))
            .and(query_param("serverId", "hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "069a79f444e94726a5befca90e38aaf5",
                "name": "Player",
                "properties": [{
                    "name": "textures",
                    "value": "base64-texture",
                    "signature": "signed"
                }]
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(1))
            .build()?;
        let profile = request_mojang_profile(&client, &server.uri(), "Player", "hash")
            .await
            .expect("profile should be returned");
        assert_eq!(profile.name, "Player");
        assert_eq!(profile.id, "069a79f444e94726a5befca90e38aaf5");
        assert_eq!(profile.properties.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn mojang_mock_204_rejects_authentication() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/session/minecraft/hasJoined"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(1))
            .build()?;
        let result = request_mojang_profile(&client, &server.uri(), "Player", "hash").await;
        assert_eq!(result.unwrap_err(), MojangAuthError::AuthenticationFailed);
        Ok(())
    }

    #[tokio::test]
    async fn mojang_timeouts_open_circuit_after_three_failures() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/session/minecraft/hasJoined"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(50))
            .timeout(Duration::from_millis(80))
            .build()?;
        let circuit = AuthCircuitBreaker::new(3, Duration::from_secs(30));

        for _ in 0..3 {
            assert!(circuit.allow_request());
            let result = request_mojang_profile(&client, &server.uri(), "Player", "hash").await;
            assert_eq!(result.unwrap_err(), MojangAuthError::ServiceUnavailable);
            circuit.record_failure();
        }

        assert_eq!(circuit.state(), CircuitState::Open);
        assert!(!circuit.allow_request());
        Ok(())
    }

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
        let state = RuntimeState::new(config.clone(), protocol_map, metrics, pool)?;

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
            if !forwarded.properties.is_empty() {
                bail!("expected zero properties");
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

    #[tokio::test]
    async fn low_reputation_ip_is_blocked_with_suspicious_activity_message() -> Result<()> {
        let backend_probe = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_probe.local_addr()?;
        drop(backend_probe);

        let proxy_probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy_probe.local_addr()?;
        drop(proxy_probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state
            .reputation()
            .set_score_for_test(IpAddr::V4(Ipv4Addr::LOCALHOST), 5);

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let packet = timeout(
            Duration::from_secs(3),
            read_packet(&mut client, 8 * 1024 * 1024),
        )
        .await??;
        let text = parse_disconnect_text(&packet)?;
        assert!(
            text.contains("suspicious activity"),
            "unexpected disconnect message: {text}"
        );

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn medium_reputation_adds_connection_delay() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let proxy_probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy_probe.local_addr()?;
        drop(proxy_probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];
        config.forwarding.velocity.enabled = false;

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state
            .reputation()
            .set_score_for_test(IpAddr::V4(Ipv4Addr::LOCALHOST), 30);

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await?;
            let accepted = Instant::now();
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            Result::<Instant>::Ok(accepted)
        });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let start = Instant::now();
        let handshake = build_handshake_packet(767, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("DelayUser");
        write_packet(&mut client, &login_start).await?;

        let accepted_at = timeout(Duration::from_secs(5), backend_task).await???;
        let elapsed = accepted_at.saturating_duration_since(start);
        assert!(
            elapsed >= Duration::from_millis(180),
            "expected >=180ms delay, got {:?}",
            elapsed
        );

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn high_reputation_connection_has_no_artificial_delay() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let proxy_probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy_probe.local_addr()?;
        drop(proxy_probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];
        config.forwarding.velocity.enabled = false;

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state
            .reputation()
            .set_score_for_test(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await?;
            let accepted = Instant::now();
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            Result::<Instant>::Ok(accepted)
        });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let start = Instant::now();
        let handshake = build_handshake_packet(767, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("FastUser");
        write_packet(&mut client, &login_start).await?;

        let accepted_at = timeout(Duration::from_secs(5), backend_task).await???;
        let elapsed = accepted_at.saturating_duration_since(start);
        assert!(
            elapsed < Duration::from_millis(180),
            "expected <180ms without delay, got {:?}",
            elapsed
        );

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn attack_mode_change_event_fires_on_mode_transition() -> Result<()> {
        let mut config = Config::default();
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: "127.0.0.1:25566".to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;

        let (tx, rx) = oneshot::channel::<(bool, f64, f64)>();
        let sender = StdArc::new(tokio::sync::Mutex::new(Some(tx)));
        let sender_for_handler = sender.clone();
        state
            .plugin_runtime()
            .events
            .with_plugin("test-attack-mode")
            .on::<OnAttackModeChange, _, _>(move |event| {
                let sender_for_handler = sender_for_handler.clone();
                async move {
                    if let Some(tx) = sender_for_handler.lock().await.take() {
                        let _ = tx.send((event.active, event.cps, event.fail_ratio));
                    }
                }
            });

        apply_attack_update(
            &state,
            AttackUpdate {
                connections_per_second: 123,
                unique_ips_per_minute: 42,
                login_fail_ratio: 0.67,
                attack_mode_active: true,
                mode_changed: Some(true),
            },
        );

        let (active, cps, fail_ratio) = timeout(Duration::from_secs(1), rx).await??;
        assert!(active);
        assert_eq!(cps, 123.0);
        assert!((fail_ratio - 0.67).abs() < 0.000_001);
        Ok(())
    }

    #[tokio::test]
    async fn on_tcp_connect_cancel_closes_connection_silently() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);
        state
            .plugin_runtime()
            .events
            .with_plugin("test-tcp-connect-cancel")
            .on::<OnTcpConnect, _, _>(|event| async move {
                event.cancel("blocked");
            });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let mut buf = [0u8; 1];
        let read = timeout(Duration::from_secs(2), client.read(&mut buf)).await??;
        assert_eq!(read, 0, "expected silent close on tcp connect cancellation");

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn on_pre_login_cancel_returns_disconnect_reason() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);
        state
            .plugin_runtime()
            .events
            .with_plugin("test-pre-login-cancel")
            .on::<OnPreLogin, _, _>(|event| async move {
                event.cancel("Denied by pre-login plugin");
            });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let handshake = build_handshake_packet(774, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("DeniedUser");
        write_packet(&mut client, &login_start).await?;

        let packet = timeout(
            Duration::from_secs(5),
            read_packet(&mut client, 8 * 1024 * 1024),
        )
        .await??;
        let message = parse_disconnect_text(&packet)?;
        assert!(message.contains("Denied by pre-login plugin"));

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn backend_kick_event_handler_can_transfer_to_fallback() -> Result<()> {
        let backend1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend1_addr = backend1_listener.local_addr()?;
        let backend2_addr = backend2_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.plugins.intercept_plugin_messages = true;
        config.plugins.event_handler_timeout_ms = 1_000;
        config.routing.backends = vec![
            BackendConfig {
                name: "backend-1".to_string(),
                address: backend1_addr.to_string(),
                weight: 1.0,
            },
            BackendConfig {
                name: "backend-2".to_string(),
                address: backend2_addr.to_string(),
                weight: 1.0,
            },
        ];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);

        let kick_calls = StdArc::new(AtomicUsize::new(0));
        let kick_calls_handler = kick_calls.clone();
        let transfer_successes = StdArc::new(AtomicUsize::new(0));
        let transfer_successes_handler = transfer_successes.clone();
        let proxy = state.plugin_runtime().proxy.clone();
        state
            .plugin_runtime()
            .events
            .with_plugin("test-backend-kick")
            .on::<OnBackendKick, _, _>(move |event| {
                let kick_calls_handler = kick_calls_handler.clone();
                let transfer_successes_handler = transfer_successes_handler.clone();
                let proxy = proxy.clone();
                async move {
                    kick_calls_handler.fetch_add(1, Ordering::Relaxed);
                    if let Some(target) = proxy
                        .get_backends()
                        .into_iter()
                        .find(|backend| backend.name() == "backend-2")
                    {
                        let player = event.player.clone();
                        let transfer_result =
                            tokio::task::spawn_blocking(move || player.transfer(target))
                                .await
                                .unwrap_or(vex_sdk::player::TransferResult::Timeout);
                        if matches!(transfer_result, vex_sdk::player::TransferResult::Success) {
                            transfer_successes_handler.fetch_add(1, Ordering::Relaxed);
                            event.cancel("redirected to backend-2");
                        }
                    }
                }
            });

        let (kick_tx, kick_rx) = oneshot::channel::<()>();
        let backend1_task = tokio::spawn(async move {
            let (mut stream, _) = backend1_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = kick_rx.await;
            let disconnect_packet = build_play_disconnect_packet("kicked from backend-1");
            write_packet(&mut stream, &disconnect_packet).await?;
            sleep(Duration::from_millis(500)).await;
            anyhow::Result::<()>::Ok(())
        });

        let backend2_task = tokio::spawn(async move {
            let (mut stream, _) = backend2_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let packet = build_play_plugin_message_packet(774, true, "relay:after-kick", b"ok")
                .ok_or_else(|| anyhow::anyhow!("plugin packet build failed"))?;
            write_packet(&mut stream, &packet).await?;
            sleep(Duration::from_millis(500)).await;
            anyhow::Result::<()>::Ok(())
        });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let handshake = build_handshake_packet(774, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("KickRedirectUser");
        write_packet(&mut client, &login_start).await?;

        for _ in 0..30 {
            if state
                .plugin_runtime()
                .proxy
                .get_player("KickRedirectUser")
                .is_some()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }

        let _ = kick_tx.send(());

        let mut switched_backend = None;
        for _ in 0..40 {
            if let Some(player) = state.plugin_runtime().proxy.get_player("KickRedirectUser")
                && let Some(backend) = player.current_backend()
            {
                switched_backend = Some(backend.name().to_string());
                if backend.name() == "backend-2" {
                    break;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }

        assert!(
            switched_backend.as_deref() == Some("backend-2"),
            "expected backend switch to backend-2, kick_calls={}, transfer_successes={}, observed_backend={:?}",
            kick_calls.load(Ordering::Relaxed),
            transfer_successes.load(Ordering::Relaxed),
            switched_backend
        );
        sleep(Duration::from_millis(100)).await;
        assert_eq!(kick_calls.load(Ordering::Relaxed), 1);

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        backend1_task.await??;
        backend2_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn transfer_switches_live_relay_and_fires_backend_switch_event() -> Result<()> {
        let backend1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend1_addr = backend1_listener.local_addr()?;
        let backend2_addr = backend2_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.plugins.intercept_plugin_messages = false;
        config.routing.backends = vec![
            BackendConfig {
                name: "backend-1".to_string(),
                address: backend1_addr.to_string(),
                weight: 1.0,
            },
            BackendConfig {
                name: "backend-2".to_string(),
                address: backend2_addr.to_string(),
                weight: 1.0,
            },
        ];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);

        let switched_count = StdArc::new(AtomicUsize::new(0));
        let switched_count_clone = switched_count.clone();
        state
            .plugin_runtime()
            .events
            .with_plugin("test-transfer")
            .on::<OnBackendSwitch, _, _>(move |_event| {
                let switched_count_clone = switched_count_clone.clone();
                async move {
                    switched_count_clone.fetch_add(1, Ordering::Relaxed);
                }
            });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let backend1_task = tokio::spawn(async move {
            let (mut stream, _) = backend1_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let mut buf = [0u8; 1];
            let _ = timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
            anyhow::Result::<()>::Ok(())
        });

        let backend2_task = tokio::spawn(async move {
            let (mut stream, _) = backend2_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let packet = build_play_plugin_message_packet(774, true, "relay:switched", b"ok")
                .ok_or_else(|| anyhow::anyhow!("plugin packet build failed"))?;
            write_packet(&mut stream, &packet).await?;
            anyhow::Result::<()>::Ok(())
        });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let handshake = build_handshake_packet(774, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("TransferUser");
        write_packet(&mut client, &login_start).await?;

        let player = loop {
            if let Some(player) = state.plugin_runtime().proxy.get_player("TransferUser") {
                break player;
            }
            sleep(Duration::from_millis(50)).await;
        };

        let backend2_ref = state
            .plugin_runtime()
            .proxy
            .get_backends()
            .into_iter()
            .find(|backend| backend.name() == "backend-2")
            .ok_or_else(|| anyhow::anyhow!("backend-2 not found"))?;

        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || player.transfer(backend2_ref)).await?;
        assert_eq!(result, vex_sdk::player::TransferResult::Success);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "transfer exceeded 500ms: {:?}",
            started.elapsed()
        );

        let mut forwarded_payload = None;
        for _ in 0..3 {
            let packet = timeout(
                Duration::from_secs(5),
                read_packet(&mut client, 8 * 1024 * 1024),
            )
            .await??;
            if let Some((channel, offset)) = parse_play_plugin_message_packet(&packet, 774, true)? {
                forwarded_payload = Some((channel, packet[offset..].to_vec()));
                break;
            }
        }
        let (channel, payload) =
            forwarded_payload.ok_or_else(|| anyhow::anyhow!("expected plugin message packet"))?;
        assert_eq!(channel, "relay:switched");
        assert_eq!(payload.as_slice(), b"ok");

        sleep(Duration::from_millis(100)).await;
        assert_eq!(switched_count.load(Ordering::Relaxed), 1);

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        backend2_task.await??;
        backend1_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn transfer_timeout_keeps_original_backend_relay() -> Result<()> {
        let backend1_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend2_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend1_addr = backend1_listener.local_addr()?;
        let backend2_addr = backend2_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.plugins.intercept_plugin_messages = false;
        config.routing.backends = vec![
            BackendConfig {
                name: "backend-1".to_string(),
                address: backend1_addr.to_string(),
                weight: 1.0,
            },
            BackendConfig {
                name: "backend-2".to_string(),
                address: backend2_addr.to_string(),
                weight: 1.0,
            },
        ];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);

        let (backend1_send_tx, backend1_send_rx) = oneshot::channel::<()>();
        let backend1_task = tokio::spawn(async move {
            let (mut stream, _) = backend1_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = backend1_send_rx.await;
            let packet =
                build_play_plugin_message_packet(774, true, "relay:primary", b"still-here")
                    .ok_or_else(|| anyhow::anyhow!("plugin packet build failed"))?;
            write_packet(&mut stream, &packet).await?;
            anyhow::Result::<()>::Ok(())
        });

        let backend2_task = tokio::spawn(async move {
            let (mut stream, _) = backend2_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            anyhow::Result::<()>::Ok(())
        });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let handshake = build_handshake_packet(774, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("TimeoutTransferUser");
        write_packet(&mut client, &login_start).await?;

        let player = loop {
            if let Some(player) = state
                .plugin_runtime()
                .proxy
                .get_player("TimeoutTransferUser")
            {
                break player;
            }
            sleep(Duration::from_millis(50)).await;
        };
        let backend2_ref = state
            .plugin_runtime()
            .proxy
            .get_backends()
            .into_iter()
            .find(|backend| backend.name() == "backend-2")
            .ok_or_else(|| anyhow::anyhow!("backend-2 not found"))?;

        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || player.transfer(backend2_ref)).await?;
        assert_eq!(result, vex_sdk::player::TransferResult::Timeout);
        assert!(
            started.elapsed() <= Duration::from_millis(550),
            "timeout exceeded expected cap: {:?}",
            started.elapsed()
        );

        let _ = backend1_send_tx.send(());
        let packet = timeout(
            Duration::from_secs(5),
            read_packet(&mut client, 8 * 1024 * 1024),
        )
        .await??;
        let (channel, offset) = parse_play_plugin_message_packet(&packet, 774, true)?
            .ok_or_else(|| anyhow::anyhow!("expected plugin message packet"))?;
        assert_eq!(channel, "relay:primary");
        assert_eq!(&packet[offset..], b"still-here");

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        backend1_task.await??;
        backend2_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn plugin_message_interception_can_cancel_blocked_channels() -> Result<()> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_listener.local_addr()?;

        let probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = probe.local_addr()?;
        drop(probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.shutdown.drain_seconds = 0;
        config.forwarding.velocity.enabled = false;
        config.plugins.enabled = true;
        config.plugins.intercept_plugin_messages = true;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends)?;
        state.plugin_runtime().set_active_plugins(1);

        let observed_channels = StdArc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let observed_clone = observed_channels.clone();
        state
            .plugin_runtime()
            .events
            .with_plugin("test-intercept")
            .on::<OnPluginMessage, _, _>(move |event| {
                let observed_clone = observed_clone.clone();
                async move {
                    observed_clone.lock().await.push(event.channel.to_string());
                    if event.channel == "blocked:channel" {
                        event.cancellation.cancel();
                    }
                }
            });

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend_listener.accept().await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let _ = read_packet(&mut stream, 8 * 1024 * 1024).await?;
            let packet = timeout(
                Duration::from_secs(3),
                read_packet(&mut stream, 8 * 1024 * 1024),
            )
            .await??;
            anyhow::Result::<Vec<u8>>::Ok(packet)
        });

        let server_state = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(server_state).await });

        let mut client = TcpStream::connect(proxy_addr).await?;
        let handshake = build_handshake_packet(774, "localhost", proxy_addr.port(), 2);
        write_packet(&mut client, &handshake).await?;
        let login_start = build_login_start_packet("InterceptUser");
        write_packet(&mut client, &login_start).await?;
        sleep(Duration::from_millis(200)).await;

        let blocked = build_play_plugin_message_packet(774, false, "blocked:channel", b"deny")
            .ok_or_else(|| anyhow::anyhow!("failed to build blocked packet"))?;
        write_packet(&mut client, &blocked).await?;
        let allowed = build_play_plugin_message_packet(774, false, "allowed:channel", b"ok")
            .ok_or_else(|| anyhow::anyhow!("failed to build allowed packet"))?;
        write_packet(&mut client, &allowed).await?;

        let forwarded = backend_task.await??;
        let (channel, offset) = parse_play_plugin_message_packet(&forwarded, 774, false)?
            .ok_or_else(|| anyhow::anyhow!("expected forwarded plugin message"))?;
        assert_eq!(channel, "allowed:channel");
        assert_eq!(&forwarded[offset..], b"ok");

        let observed = observed_channels.lock().await.clone();
        assert!(observed.contains(&"blocked:channel".to_string()));
        assert!(observed.contains(&"allowed:channel".to_string()));

        state.shutdown.trigger("test complete".to_string());
        let _ = timeout(Duration::from_secs(5), server_task).await??;
        Ok(())
    }

    fn parse_disconnect_text(packet: &[u8]) -> Result<String> {
        let (packet_id, mut offset) = parse_varint(packet)?;
        if packet_id != 0 {
            bail!("expected login disconnect packet id 0, got {packet_id}");
        }
        let (len, read) = parse_varint(&packet[offset..])?;
        offset += read;
        let len = usize::try_from(len)?;
        let end = offset + len;
        let raw = std::str::from_utf8(&packet[offset..end])?;
        let parsed: serde_json::Value = serde_json::from_str(raw)?;
        Ok(parsed
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(raw)
            .to_string())
    }

    fn build_play_disconnect_packet(message: &str) -> Vec<u8> {
        let mut packet = BytesMut::new();
        write_varint(0x1D, &mut packet);
        let component = serde_json::json!({ "text": message }).to_string();
        write_varint(component.len() as i32, &mut packet);
        packet.extend_from_slice(component.as_bytes());
        packet.to_vec()
    }
}
