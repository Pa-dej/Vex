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
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::analytics::AttackUpdate;
use crate::auth_circuit::CircuitState;
use crate::config::AuthMode;
use crate::limiter::AcquireRejectReason;
use crate::mc::{
    EncryptionResponse, VelocityProperty, build_encryption_request, build_login_disconnect,
    build_login_plugin_response, build_signed_velocity_forwarding_data, build_status_ping_response,
    build_status_response, build_velocity_modern_forwarding_payload,
    decode_login_packet_from_backend, encode_login_packet_for_backend, offline_uuid,
    parse_encryption_response, parse_handshake, parse_login_plugin_request,
    parse_login_start_username, parse_packet_id, parse_set_compression_threshold, parse_varint,
    read_packet, write_packet, write_varint,
};
use crate::reputation::{ReputationAction, connection_block_message};
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

        let Some(lease) = snapshot.backends.choose_backend() else {
            state.metrics.inc_reject("no_healthy_backend");
            state.metrics.inc_login_failure("backend_unavailable");
            send_login_disconnect_best_effort(
                client,
                "No healthy backend available. Try again in a few seconds.",
                client_crypto.as_mut(),
            )
            .await?;
            return Ok(LoginOutcome::Rejected);
        };

        let backend = lease.backend().clone();
        let mut backend_stream =
            match timeout(login_timeout, TcpStream::connect(backend.address())).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    state
                        .metrics
                        .inc_backend_error(backend.name(), "connect_error");
                    state.metrics.inc_login_failure("backend_unavailable");
                    send_login_disconnect_best_effort(
                        client,
                        "Failed to connect backend",
                        client_crypto.as_mut(),
                    )
                    .await?;
                    return Err(anyhow::anyhow!("backend connect error: {err}"));
                }
                Err(_) => {
                    state
                        .metrics
                        .inc_backend_error(backend.name(), "connect_timeout");
                    state.metrics.inc_login_failure("backend_unavailable");
                    send_login_disconnect_best_effort(
                        client,
                        "Backend connection timeout",
                        client_crypto.as_mut(),
                    )
                    .await?;
                    return Err(anyhow::anyhow!("backend connect timeout"));
                }
            };

        let (host, port) = split_host_port(backend.address())?;
        let rewritten_handshake =
            crate::mc::build_handshake_packet(protocol_version, host, port, 2);
        write_packet(&mut backend_stream, &rewritten_handshake).await?;
        write_packet(&mut backend_stream, &login_start_packet).await?;
        tracing::debug!("forwarded login start to backend peer={}", peer);

        if snapshot.config.forwarding.velocity.enabled {
            tracing::debug!("entering velocity intercept loop peer={}", peer);
            let login_phase = run_velocity_login_intercept(
                client,
                client_crypto.as_mut(),
                &mut backend_stream,
                snapshot.config.limits.max_packet_size,
                client_ip,
                &identity,
                &snapshot.config.forwarding.velocity.secret,
                peer,
            )
            .await?;
            if matches!(login_phase, LoginPhaseOutcome::Terminated) {
                state.reputation().record_login_disconnect(peer.ip());
                return Ok(LoginOutcome::Rejected);
            }
        }

        let mut shutdown_rx = state.shutdown.subscribe();
        let shutdown_message = snapshot.config.shutdown.disconnect_message.clone();

        let mut shutdown_requested = false;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginPhaseOutcome {
    ContinueToRelay,
    Terminated,
}

#[derive(Default)]
struct RelayTraffic {
    to_backend: u64,
    from_backend: u64,
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

async fn run_velocity_login_intercept(
    client: &mut TcpStream,
    client_crypto: Option<&mut ClientCrypto>,
    backend: &mut TcpStream,
    max_packet_size: usize,
    client_ip: &str,
    identity: &AuthenticatedIdentity,
    secret: &str,
    peer: SocketAddr,
) -> Result<LoginPhaseOutcome> {
    let mut compression_threshold: Option<i32> = None;
    let mut client_crypto = client_crypto;
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
                let crypto = client_crypto.as_mut().map(|inner| &mut **inner);
                write_client_packet(client, &raw_packet, crypto).await?;
                continue;
            }
            0x04 => {
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
            }
            0x02 => {
                tracing::debug!("received login success from backend peer={}", peer);
                let crypto = client_crypto.as_mut().map(|inner| &mut **inner);
                write_client_packet(client, &raw_packet, crypto).await?;
                return Ok(LoginPhaseOutcome::ContinueToRelay);
            }
            0x00 => {
                let crypto = client_crypto.as_mut().map(|inner| &mut **inner);
                write_client_packet(client, &raw_packet, crypto).await?;
                return Ok(LoginPhaseOutcome::Terminated);
            }
            _ => {
                warn!(
                    "unexpected backend packet id={:#04x} peer={}",
                    packet_id, peer
                );
                let crypto = client_crypto.as_mut().map(|inner| &mut **inner);
                write_client_packet(client, &raw_packet, crypto).await?;
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
        (&mut client_crypto.decryptor).decrypt(&mut encrypted_byte);
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
    (&mut client_crypto.decryptor).decrypt(&mut payload);
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
    (&mut client_crypto.encryptor).encrypt(&mut frame);
    client.write_all(&frame).await?;
    Ok(())
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
                (&mut client_crypto.decryptor).decrypt(&mut client_to_backend[..n]);
                backend_writer.write_all(&client_to_backend[..n]).await?;
                totals.to_backend = totals.to_backend.saturating_add(n as u64);
            }
            read = backend_reader.read(&mut backend_to_client) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                (&mut client_crypto.encryptor).encrypt(&mut backend_to_client[..n]);
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
    use std::time::{Duration, Instant};

    use bytes::BytesMut;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::auth_circuit::AuthCircuitBreaker;
    use crate::backend::BackendPool;
    use crate::config::{BackendConfig, Config};
    use crate::mc::{
        build_handshake_packet, build_login_disconnect, build_login_plugin_request,
        build_login_start_packet, decode_login_packet_from_backend,
        encode_login_packet_for_backend, offline_uuid, parse_login_plugin_response, parse_varint,
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
}
