use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use flate2::read::ZlibDecoder;
use hmac::{Hmac, Mac};
use rand::random;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const LOGIN_START_ID: i32 = 0x00;
const LOGIN_PLUGIN_REQUEST_ID: i32 = 0x04;
const LOGIN_PLUGIN_RESPONSE_ID: i32 = 0x02;
const LOGIN_SET_COMPRESSION_ID: i32 = 0x03;
const LOGIN_SUCCESS_ID: i32 = 0x02;
const LOGIN_ACKNOWLEDGED_ID: i32 = 0x03;
const STATUS_REQUEST_ID: i32 = 0x00;
const STATUS_RESPONSE_ID: i32 = 0x00;
const STATUS_PING_REQUEST_ID: i32 = 0x01;
const STATUS_PING_RESPONSE_ID: i32 = 0x01;

const CONFIG_CLIENTBOUND_PLUGIN_MESSAGE_ID: i32 = 0x02;
const CONFIG_CLIENTBOUND_FEATURE_FLAGS_ID: i32 = 0x07;
const CONFIG_CLIENTBOUND_KNOWN_PACKS_ID: i32 = 0x0D;
const CONFIG_CLIENTBOUND_FINISH_CONFIGURATION_ID: i32 = 0x0C;
const CONFIG_SERVERBOUND_PLUGIN_MESSAGE_ID: i32 = 0x02;
const CONFIG_SERVERBOUND_KNOWN_PACKS_ID: i32 = 0x07;
const CONFIG_SERVERBOUND_FINISH_ACK_ID: i32 = 0x03;

const PLAY_CLIENTBOUND_KEEPALIVE_ID: i32 = 0x26;
const PLAY_SERVERBOUND_KEEPALIVE_ID: i32 = 0x18;

#[derive(Debug, Parser, Clone)]
#[command(name = "mock_backend")]
#[command(about = "Mock Minecraft backend for Vex benchmark workloads")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:25565")]
    bind: String,
    #[arg(long, default_value = "test-secret-123")]
    secret: String,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    velocity: bool,
    #[arg(long, default_value_t = 256)]
    compression: i32,
}

#[derive(Default)]
struct Stats {
    active_connections: AtomicU64,
    total_accepted: AtomicU64,
    total_disconnected: AtomicU64,
    login_failures: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }
}

struct ConnectionGuard {
    stats: Arc<Stats>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        self.stats
            .total_disconnected
            .fetch_add(1, Ordering::Relaxed);
    }
}

struct LoginPluginResponse {
    message_id: i32,
    successful: bool,
    data: Vec<u8>,
}

struct VelocityForwardedData {
    client_ip: String,
    username: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.compression < 0 {
        bail!("compression threshold must be >= 0");
    }

    let listener = TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("failed to bind {}", cli.bind))?;
    let stats = Arc::new(Stats::new());
    let secret = Arc::new(cli.secret);

    println!(
        "mock_backend listening on {} (compression={}, velocity_enabled={}, velocity_secret=***)",
        cli.bind, cli.compression, cli.velocity
    );

    let reporter_stats = stats.clone();
    tokio::spawn(async move {
        report_metrics(reporter_stats).await;
    });

    loop {
        let (stream, peer) = listener.accept().await.context("accept failed")?;
        let stats = stats.clone();
        let secret = secret.clone();
        let compression = cli.compression;
        let velocity = cli.velocity;
        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(stream, peer, secret, compression, velocity, stats.clone()).await
            {
                eprintln!("connection error peer={peer}: {err:#}");
            }
        });
    }
}

async fn report_metrics(stats: Arc<Stats>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        println!(
            "active_connections={} total_accepted={} total_disconnected={} login_failures={}",
            stats.active_connections.load(Ordering::Relaxed),
            stats.total_accepted.load(Ordering::Relaxed),
            stats.total_disconnected.load(Ordering::Relaxed),
            stats.login_failures.load(Ordering::Relaxed),
        );
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    secret: Arc<String>,
    compression_threshold: i32,
    velocity_enabled: bool,
    stats: Arc<Stats>,
) -> Result<()> {
    stats.total_accepted.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    let _conn_guard = ConnectionGuard {
        stats: stats.clone(),
    };

    let mut compression: Option<i32> = None;

    let handshake_packet = read_packet(&mut stream, compression)
        .await
        .context("failed reading handshake")?;
    let next_state = parse_handshake_next_state(&handshake_packet)
        .map_err(|err| login_failure(&stats, format!("bad handshake: {err:#}")))?;

    if next_state == 1 {
        handle_status_flow(&mut stream, compression)
            .await
            .context("status flow failed")?;
        return Ok(());
    }
    if next_state != 2 {
        return Ok(());
    }

    let login_start_packet = read_packet(&mut stream, compression)
        .await
        .context("failed reading login start")?;
    let username = parse_login_start(&login_start_packet)
        .map_err(|err| login_failure(&stats, format!("bad login start: {err:#}")))?;

    if velocity_enabled {
        let plugin_request = build_login_plugin_request(1, "velocity:player_info");
        write_packet(&mut stream, &plugin_request, compression)
            .await
            .context("failed sending velocity plugin request")?;

        let plugin_response_packet = read_packet(&mut stream, compression)
            .await
            .context("failed reading velocity plugin response")?;
        let plugin_response = parse_login_plugin_response(&plugin_response_packet)
            .map_err(|err| login_failure(&stats, format!("bad velocity response: {err:#}")))?;
        if plugin_response.message_id != 1 || !plugin_response.successful {
            return Err(login_failure(
                &stats,
                "velocity plugin response rejected".to_string(),
            ));
        }
        verify_velocity_forwarding_data(secret.as_bytes(), &plugin_response.data, &username)
            .map_err(|err| login_failure(&stats, format!("velocity verify failed: {err:#}")))?;
    }

    let set_compression = build_set_compression_packet(compression_threshold);
    write_packet(&mut stream, &set_compression, compression)
        .await
        .context("failed sending set compression")?;
    compression = Some(compression_threshold);

    let login_success = build_login_success_packet(&username);
    write_packet(&mut stream, &login_success, compression)
        .await
        .context("failed sending login success")?;

    let login_ack = read_packet(&mut stream, compression)
        .await
        .context("failed reading login acknowledged")?;
    expect_packet_id(&login_ack, LOGIN_ACKNOWLEDGED_ID)
        .map_err(|err| login_failure(&stats, format!("missing login ack: {err:#}")))?;

    let brand = build_configuration_brand_packet("mock");
    write_packet(&mut stream, &brand, compression)
        .await
        .context("failed sending config brand")?;

    let feature_flags = build_configuration_feature_flags_empty();
    write_packet(&mut stream, &feature_flags, compression)
        .await
        .context("failed sending config feature flags")?;

    let known_packs = build_configuration_known_packs_empty();
    write_packet(&mut stream, &known_packs, compression)
        .await
        .context("failed sending config known packs")?;

    wait_for_known_packs_response(&mut stream, compression)
        .await
        .context("failed waiting known packs response")?;

    let finish_config = build_finish_configuration_packet();
    write_packet(&mut stream, &finish_config, compression)
        .await
        .context("failed sending finish configuration")?;

    let finish_ack = read_packet(&mut stream, compression)
        .await
        .context("failed reading finish config ack")?;
    expect_packet_id(&finish_ack, CONFIG_SERVERBOUND_FINISH_ACK_ID)
        .context("bad finish configuration ack")?;

    run_play_phase(stream, compression, peer).await?;
    Ok(())
}

async fn handle_status_flow(stream: &mut TcpStream, compression: Option<i32>) -> Result<()> {
    let status_request = read_packet(stream, compression)
        .await
        .context("failed reading status request")?;
    expect_empty_status_request(&status_request).context("invalid status request packet")?;

    let status_response = build_status_response_packet();
    write_packet(stream, &status_response, compression)
        .await
        .context("failed sending status response")?;

    let ping_request = read_packet(stream, compression)
        .await
        .context("failed reading ping request")?;
    let ping_payload = parse_status_ping_request(&ping_request).context("invalid ping request")?;

    let ping_response = build_status_ping_response_packet(ping_payload);
    write_packet(stream, &ping_response, compression)
        .await
        .context("failed sending ping response")?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn login_failure(stats: &Arc<Stats>, message: String) -> anyhow::Error {
    stats.login_failures.fetch_add(1, Ordering::Relaxed);
    anyhow::anyhow!(message)
}

async fn wait_for_known_packs_response(
    stream: &mut TcpStream,
    compression: Option<i32>,
) -> Result<()> {
    for _ in 0..8 {
        let packet = read_packet(stream, compression).await?;
        let (packet_id, _) = decode_varint(&packet)?;
        if packet_id == CONFIG_SERVERBOUND_KNOWN_PACKS_ID {
            return Ok(());
        }
        if packet_id == CONFIG_SERVERBOUND_PLUGIN_MESSAGE_ID {
            continue;
        }
    }
    bail!("did not receive known packs response")
}

async fn run_play_phase(
    stream: TcpStream,
    compression: Option<i32>,
    peer: SocketAddr,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let outstanding = Arc::new(Mutex::new(VecDeque::<i64>::new()));
    let keepalive_outstanding = outstanding.clone();

    let keepalive_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let keepalive_id: i64 = random();
            {
                let mut q = keepalive_outstanding.lock().await;
                q.push_back(keepalive_id);
                if q.len() > 64 {
                    q.pop_front();
                }
            }
            let packet = build_keep_alive_packet(keepalive_id);
            if write_packet(&mut writer, &packet, compression)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    loop {
        let packet = match read_packet(&mut reader, compression).await {
            Ok(packet) => packet,
            Err(_) => break,
        };
        let (packet_id, read) = match decode_varint(&packet) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if packet_id == PLAY_SERVERBOUND_KEEPALIVE_ID {
            if packet.len() < read + 8 {
                continue;
            }
            let response_id = i64::from_be_bytes(
                packet[read..read + 8]
                    .try_into()
                    .context("keep alive response payload too short")?,
            );
            let mut q = outstanding.lock().await;
            if let Some(pos) = q.iter().position(|id| *id == response_id) {
                q.remove(pos);
            } else {
                eprintln!("peer={peer} unexpected keep_alive response id={response_id}");
            }
        }
    }

    keepalive_task.abort();
    println!("peer={peer} disconnected");
    Ok(())
}

fn parse_handshake_next_state(payload: &[u8]) -> Result<i32> {
    let (packet_id, mut offset) = decode_varint(payload)?;
    if packet_id != 0x00 {
        bail!("not handshake");
    }
    let (_, read) = decode_varint(&payload[offset..])?;
    offset += read;
    let (_, read) = parse_mc_string(&payload[offset..])?;
    offset += read;
    if payload.len() < offset + 2 {
        bail!("missing handshake port");
    }
    offset += 2;
    let (next_state, read) = decode_varint(&payload[offset..])?;
    offset += read;
    if offset != payload.len() {
        bail!("trailing handshake bytes");
    }
    Ok(next_state)
}

fn parse_login_start(payload: &[u8]) -> Result<String> {
    let (packet_id, offset) = decode_varint(payload)?;
    if packet_id != LOGIN_START_ID {
        bail!("expected login start, got packet id {packet_id}");
    }
    let (username, _) = parse_mc_string(&payload[offset..]).context("missing username")?;
    Ok(username)
}

fn parse_login_plugin_response(payload: &[u8]) -> Result<LoginPluginResponse> {
    let (packet_id, mut offset) = decode_varint(payload)?;
    if packet_id != LOGIN_PLUGIN_RESPONSE_ID {
        bail!("expected login plugin response, got packet id {packet_id}");
    }
    let (message_id, read) = decode_varint(&payload[offset..])?;
    offset += read;
    if payload.len() <= offset {
        bail!("missing success flag in plugin response");
    }
    let successful = payload[offset] != 0;
    offset += 1;
    let data = payload[offset..].to_vec();
    Ok(LoginPluginResponse {
        message_id,
        successful,
        data,
    })
}

fn verify_velocity_forwarding_data(
    secret: &[u8],
    data: &[u8],
    expected_username: &str,
) -> Result<()> {
    if data.len() < 32 {
        bail!("velocity payload too short for signature");
    }
    let signature = &data[..32];
    let payload = &data[32..];
    let mut mac = HmacSha256::new_from_slice(secret).context("invalid velocity secret")?;
    mac.update(payload);
    mac.verify_slice(signature)
        .map_err(|_| anyhow::anyhow!("velocity hmac verification failed"))?;
    let forwarded = parse_velocity_forwarding_payload(payload)?;
    if forwarded.username != expected_username {
        bail!(
            "velocity username mismatch: login='{}' forwarded='{}'",
            expected_username,
            forwarded.username
        );
    }
    let _ = forwarded.client_ip;
    Ok(())
}

fn parse_velocity_forwarding_payload(payload: &[u8]) -> Result<VelocityForwardedData> {
    let (version, mut offset) = decode_varint(payload)?;
    if version != 1 {
        bail!("unsupported velocity forwarding version {version}");
    }
    let (client_ip, read) = parse_mc_string(&payload[offset..]).context("missing client ip")?;
    offset += read;
    if payload.len() < offset + 16 {
        bail!("missing velocity uuid");
    }
    offset += 16;
    let (username, read) =
        parse_mc_string(&payload[offset..]).context("missing velocity username")?;
    offset += read;
    let (properties_count, read) =
        decode_varint(&payload[offset..]).context("missing properties count")?;
    offset += read;
    if properties_count < 0 {
        bail!("negative properties count");
    }
    for _ in 0..properties_count {
        let (_, read) = parse_mc_string(&payload[offset..]).context("missing property name")?;
        offset += read;
        let (_, read) = parse_mc_string(&payload[offset..]).context("missing property value")?;
        offset += read;
        if payload.len() <= offset {
            bail!("missing property signature flag");
        }
        let has_signature = payload[offset] != 0;
        offset += 1;
        if has_signature {
            let (_, read) =
                parse_mc_string(&payload[offset..]).context("missing property signature")?;
            offset += read;
        }
    }
    if offset != payload.len() {
        bail!("trailing bytes in velocity payload");
    }
    Ok(VelocityForwardedData {
        client_ip,
        username,
    })
}

fn expect_packet_id(payload: &[u8], expected_id: i32) -> Result<()> {
    let (packet_id, _) = decode_varint(payload)?;
    if packet_id != expected_id {
        bail!("expected packet id {expected_id:#04x}, got {packet_id:#04x}");
    }
    Ok(())
}

fn build_login_plugin_request(message_id: i32, channel: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&encode_varint(LOGIN_PLUGIN_REQUEST_ID));
    payload.extend_from_slice(&encode_varint(message_id));
    write_mc_string(channel, &mut payload);
    payload
}

fn build_status_response_packet() -> Vec<u8> {
    const STATUS_JSON: &str = "{\"version\":{\"name\":\"1.21.4\",\"protocol\":774},\"players\":{\"max\":10000,\"online\":0},\"description\":{\"text\":\"mock\"}}";
    let mut payload = Vec::with_capacity(STATUS_JSON.len() + 8);
    payload.extend_from_slice(&encode_varint(STATUS_RESPONSE_ID));
    write_mc_string(STATUS_JSON, &mut payload);
    payload
}

fn build_status_ping_response_packet(payload_i64: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&encode_varint(STATUS_PING_RESPONSE_ID));
    payload.extend_from_slice(&payload_i64.to_be_bytes());
    payload
}

fn build_set_compression_packet(threshold: i32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&encode_varint(LOGIN_SET_COMPRESSION_ID));
    payload.extend_from_slice(&encode_varint(threshold));
    payload
}

fn build_login_success_packet(username: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(username.len() + 32);
    payload.extend_from_slice(&encode_varint(LOGIN_SUCCESS_ID));
    payload.extend_from_slice(&offline_uuid(username));
    write_mc_string(username, &mut payload);
    payload.extend_from_slice(&encode_varint(0));
    payload
}

fn build_configuration_brand_packet(brand: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&encode_varint(CONFIG_CLIENTBOUND_PLUGIN_MESSAGE_ID));
    write_mc_string("minecraft:brand", &mut payload);

    let mut brand_data = Vec::with_capacity(brand.len() + 5);
    write_mc_string(brand, &mut brand_data);
    payload.extend_from_slice(&brand_data);
    payload
}

fn build_configuration_feature_flags_empty() -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&encode_varint(CONFIG_CLIENTBOUND_FEATURE_FLAGS_ID));
    payload.extend_from_slice(&encode_varint(0));
    payload
}

fn build_configuration_known_packs_empty() -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&encode_varint(CONFIG_CLIENTBOUND_KNOWN_PACKS_ID));
    payload.extend_from_slice(&encode_varint(0));
    payload
}

fn build_finish_configuration_packet() -> Vec<u8> {
    encode_varint(CONFIG_CLIENTBOUND_FINISH_CONFIGURATION_ID)
}

fn build_keep_alive_packet(keep_alive_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&encode_varint(PLAY_CLIENTBOUND_KEEPALIVE_ID));
    payload.extend_from_slice(&keep_alive_id.to_be_bytes());
    payload
}

fn offline_uuid(username: &str) -> [u8; 16] {
    let source = format!("OfflinePlayer:{username}");
    *Uuid::new_v3(&Uuid::NAMESPACE_DNS, source.as_bytes()).as_bytes()
}

async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    compression: Option<i32>,
) -> Result<()> {
    let body = encode_packet_payload(payload, compression)?;
    let header = encode_varint(body.len() as i32);
    writer.write_all(&header).await?;
    writer.write_all(&body).await?;
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    compression: Option<i32>,
) -> Result<Vec<u8>> {
    let frame_payload = read_raw_frame(reader).await?;
    decode_packet_payload(&frame_payload, compression)
}

async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut length_bytes = Vec::with_capacity(5);
    loop {
        let byte = reader.read_u8().await?;
        length_bytes.push(byte);
        if (byte & 0x80) == 0 {
            break;
        }
        if length_bytes.len() > 5 {
            bail!("frame length varint too large");
        }
    }
    let (frame_len, _) = decode_varint(&length_bytes)?;
    if frame_len <= 0 {
        bail!("invalid frame length {frame_len}");
    }
    let mut frame_payload = vec![0u8; frame_len as usize];
    reader.read_exact(&mut frame_payload).await?;
    Ok(frame_payload)
}

fn encode_packet_payload(payload: &[u8], compression: Option<i32>) -> Result<Vec<u8>> {
    let Some(threshold) = compression else {
        return Ok(payload.to_vec());
    };

    if threshold < 0 {
        return Ok(payload.to_vec());
    }

    if payload.len() < threshold as usize {
        let mut out = Vec::with_capacity(payload.len() + 5);
        out.extend_from_slice(&encode_varint(0));
        out.extend_from_slice(payload);
        return Ok(out);
    }

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;

    let mut out = Vec::with_capacity(compressed.len() + 5);
    out.extend_from_slice(&encode_varint(payload.len() as i32));
    out.extend_from_slice(&compressed);
    Ok(out)
}

fn decode_packet_payload(frame_payload: &[u8], compression: Option<i32>) -> Result<Vec<u8>> {
    if compression.is_none() {
        return Ok(frame_payload.to_vec());
    }
    let (data_length, read) = decode_varint(frame_payload)?;
    if data_length < 0 {
        bail!("negative compressed data length");
    }
    if data_length == 0 {
        return Ok(frame_payload[read..].to_vec());
    }

    let mut decoder = ZlibDecoder::new(&frame_payload[read..]);
    let mut out = Vec::with_capacity(data_length as usize);
    decoder.read_to_end(&mut out)?;
    if out.len() != data_length as usize {
        bail!(
            "compressed payload size mismatch: expected={}, got={}",
            data_length,
            out.len()
        );
    }
    Ok(out)
}

fn parse_mc_string(input: &[u8]) -> Result<(String, usize)> {
    let (len, read) = decode_varint(input).context("bad string length varint")?;
    if len < 0 {
        bail!("negative string length");
    }
    let len = len as usize;
    let start = read;
    let end = start + len;
    if input.len() < end {
        bail!("string payload truncated");
    }
    let s = std::str::from_utf8(&input[start..end]).context("string is not utf-8")?;
    Ok((s.to_string(), read + len))
}

fn expect_empty_status_request(payload: &[u8]) -> Result<()> {
    let (packet_id, read) = decode_varint(payload)?;
    if packet_id != STATUS_REQUEST_ID {
        bail!("expected status request, got packet id {packet_id:#04x}");
    }
    if payload.len() != read {
        bail!("status request should be empty");
    }
    Ok(())
}

fn parse_status_ping_request(payload: &[u8]) -> Result<i64> {
    let (packet_id, read) = decode_varint(payload)?;
    if packet_id != STATUS_PING_REQUEST_ID {
        bail!("expected ping request, got packet id {packet_id:#04x}");
    }
    if payload.len() != read + 8 {
        bail!("invalid ping payload length");
    }
    Ok(i64::from_be_bytes(
        payload[read..read + 8]
            .try_into()
            .context("ping request payload malformed")?,
    ))
}

fn write_mc_string(value: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&encode_varint(value.len() as i32));
    out.extend_from_slice(value.as_bytes());
}

fn encode_varint(mut value: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        if (value & !0x7F) == 0 {
            out.push(value as u8);
            return out;
        }
        out.push(((value & 0x7F) | 0x80) as u8);
        value = ((value as u32) >> 7) as i32;
    }
}

fn decode_varint(input: &[u8]) -> Result<(i32, usize)> {
    let mut num_read = 0usize;
    let mut result = 0i32;

    loop {
        if num_read >= input.len() {
            bail!("incomplete varint");
        }
        let byte = input[num_read];
        let value = (byte & 0x7F) as i32;
        result |= value << (7 * num_read);
        num_read += 1;
        if num_read > 5 {
            bail!("varint too large");
        }
        if (byte & 0x80) == 0 {
            break;
        }
    }

    Ok((result, num_read))
}
