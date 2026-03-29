use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use flate2::read::ZlibDecoder;
use hdrhistogram::Histogram;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};

const LOGIN_ENCRYPTION_REQUEST_ID: u8 = 0x01;
const LOGIN_SUCCESS_ID: u8 = 0x02;
const LOGIN_SET_COMPRESSION_ID: u8 = 0x03;
const LOGIN_DISCONNECT_ID: u8 = 0x00;
const LOGIN_ACKNOWLEDGED_ID: i32 = 0x03;
const CONFIG_CLIENTBOUND_PLUGIN_MESSAGE_ID: i32 = 0x02;
const CONFIG_CLIENTBOUND_FEATURE_FLAGS_ID: i32 = 0x07;
const CONFIG_CLIENTBOUND_KNOWN_PACKS_ID: i32 = 0x0D;
const CONFIG_CLIENTBOUND_FINISH_CONFIGURATION_ID: i32 = 0x0C;
const CONFIG_SERVERBOUND_PLUGIN_MESSAGE_ID: i32 = 0x02;
const CONFIG_SERVERBOUND_KNOWN_PACKS_ID: i32 = 0x07;
const CONFIG_SERVERBOUND_FINISH_ACK_ID: i32 = 0x03;
const CLIENTBOUND_KEEPALIVE_ID: u8 = 0x26;
const SERVERBOUND_KEEPALIVE_ID: i32 = 0x18;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const CONFIG_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser, Debug, Clone)]
#[command(name = "bench")]
#[command(about = "Load benchmark tool for Vex Minecraft proxy")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:25577")]
    target: String,
    /// Host to use in handshake packet (must match Gate route)
    #[arg(long, default_value = "127.0.0.1")]
    handshake_host: String,
    #[arg(long, default_value_t = 200)]
    players: u32,
    #[arg(long, default_value_t = 10)]
    ramp_up_secs: u64,
    #[arg(long, default_value_t = 30)]
    hold_secs: u64,
    #[arg(long, default_value = "bench_")]
    username_prefix: String,
    #[arg(long, default_value_t = 764)]
    protocol: i32,
}

struct Stats {
    active: AtomicU64,
    connecting: AtomicU64,
    logged_in: AtomicU64,
    success_total: AtomicU64,
    peak_logged_in: AtomicU64,
    failed: AtomicU64,
    disconnected: AtomicU64,
    rejected: AtomicU64,
    timed_out: AtomicU64,
    bytes_recv_total: AtomicU64,
    bytes_sent_total: AtomicU64,
    latency_hist: Mutex<Histogram<u64>>,
    rejection_reasons: Mutex<HashMap<String, u64>>,
}

impl Stats {
    fn new() -> Result<Self> {
        Ok(Self {
            active: AtomicU64::new(0),
            connecting: AtomicU64::new(0),
            logged_in: AtomicU64::new(0),
            success_total: AtomicU64::new(0),
            peak_logged_in: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            disconnected: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
            bytes_recv_total: AtomicU64::new(0),
            bytes_sent_total: AtomicU64::new(0),
            latency_hist: Mutex::new(Histogram::<u64>::new_with_bounds(1, 120_000, 3)?),
            rejection_reasons: Mutex::new(HashMap::new()),
        })
    }

    fn inc_active(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_active(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    fn inc_connecting(&self) {
        self.connecting.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_connecting(&self) {
        self.connecting.fetch_sub(1, Ordering::Relaxed);
    }

    fn inc_logged_in(&self) {
        let now = self.logged_in.fetch_add(1, Ordering::Relaxed) + 1;
        loop {
            let peak = self.peak_logged_in.load(Ordering::Relaxed);
            if now <= peak {
                break;
            }
            if self
                .peak_logged_in
                .compare_exchange(peak, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn dec_logged_in(&self) {
        self.logged_in.fetch_sub(1, Ordering::Relaxed);
    }

    fn inc_success_total(&self) {
        self.success_total.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_disconnected(&self) {
        self.disconnected.fetch_add(1, Ordering::Relaxed);
    }

    async fn record_rejection_reason(&self, reason: String) {
        let mut reasons = self.rejection_reasons.lock().await;
        *reasons.entry(reason).or_insert(0) += 1;
    }

    async fn record_latency_ms(&self, latency_ms: u64) {
        let mut hist = self.latency_hist.lock().await;
        let _ = hist.record(latency_ms.max(1));
    }
}

struct ActiveConnectionGuard {
    stats: Arc<Stats>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.stats.dec_active();
    }
}

struct LoggedInGuard {
    stats: Arc<Stats>,
}

impl Drop for LoggedInGuard {
    fn drop(&mut self) {
        self.stats.dec_logged_in();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let stats = Arc::new(Stats::new()?);
    let bench_started = Instant::now();
    let hold_until = bench_started + Duration::from_secs(cli.ramp_up_secs + cli.hold_secs);

    let (stop_tx, stop_rx) = watch::channel(false);
    let reporter_stats = stats.clone();
    let reporter = tokio::spawn(async move {
        reporter_loop(reporter_stats, stop_rx).await;
    });

    let mut handles = Vec::with_capacity(cli.players as usize);
    let spawn_interval_ms = if cli.players == 0 {
        0
    } else {
        (cli.ramp_up_secs * 1000) / u64::from(cli.players)
    };

    for i in 0..cli.players {
        let username = format!("{}{}", cli.username_prefix, i);
        let stats_clone = stats.clone();
        let cli_clone = cli.clone();
        handles.push(tokio::spawn(async move {
            let _ = run_player(
                i,
                username,
                cli_clone.protocol,
                &cli_clone.target,
                &cli_clone.handshake_host,
                hold_until,
                stats_clone,
            )
            .await;
        }));
        if spawn_interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(spawn_interval_ms)).await;
        }
    }

    for handle in handles {
        let _ = handle.await;
    }

    let _ = stop_tx.send(true);
    let _ = reporter.await;

    print_final_report(&cli, bench_started, stats).await;
    Ok(())
}

async fn reporter_loop(stats: Arc<Stats>, mut stop_rx: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let active = stats.active.load(Ordering::Relaxed);
                let connecting = stats.connecting.load(Ordering::Relaxed);
                let logged_in = stats.logged_in.load(Ordering::Relaxed);
                let failed = stats.failed.load(Ordering::Relaxed);
                let disconnected = stats.disconnected.load(Ordering::Relaxed);
                let rejected = stats.rejected.load(Ordering::Relaxed);
                let timed_out = stats.timed_out.load(Ordering::Relaxed);
                let bytes_recv = stats.bytes_recv_total.load(Ordering::Relaxed);
                let bytes_sent = stats.bytes_sent_total.load(Ordering::Relaxed);

                let (p50, p99, p999) = {
                    let hist = stats.latency_hist.lock().await;
                    if hist.len() == 0 {
                        (0_u64, 0_u64, 0_u64)
                    } else {
                        (
                            hist.value_at_quantile(0.50),
                            hist.value_at_quantile(0.99),
                            hist.value_at_quantile(0.999),
                        )
                    }
                };

                println!(
                    "active={} connecting={} logged_in={} failed={} disconnected={} rejected={} timed_out={} keep_alive_rtt_p50_ms={} p99_ms={} p999_ms={} bytes_recv_total={} bytes_sent_total={}",
                    active, connecting, logged_in, failed, disconnected, rejected, timed_out, p50, p99, p999, bytes_recv, bytes_sent
                );
            }
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn run_player(
    _player_index: u32,
    username: String,
    protocol: i32,
    target: &str,
    handshake_host: &str,
    hold_until: Instant,
    stats: Arc<Stats>,
) -> Result<()> {
    stats.inc_connecting();

    let (connect_target, _, handshake_port) = resolve_target(target)?;
    let connect_result = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(connect_target.as_str()),
    )
    .await;
    let mut stream = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) | Err(_) => {
            stats.dec_connecting();
            stats.failed.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };

    stats.inc_active();
    let _active_guard = ActiveConnectionGuard {
        stats: stats.clone(),
    };

    write_packet(
        &mut stream,
        &build_handshake(protocol, handshake_host, handshake_port, 2),
        None,
        &stats,
    )
    .await?;
    write_packet(
        &mut stream,
        &build_login_start(&username, protocol),
        None,
        &stats,
    )
    .await?;

    let mut compression_threshold: Option<i32> = None;
    loop {
        let raw = match read_frame(&mut stream, READ_TIMEOUT, &stats).await {
            Ok(raw) => raw,
            Err(FrameReadError::Timeout) => {
                stats.dec_connecting();
                stats.timed_out.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Err(FrameReadError::Io) | Err(FrameReadError::Malformed) => {
                stats.dec_connecting();
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                stats
                    .record_rejection_reason("connection closed during login".to_string())
                    .await;
                return Ok(());
            }
        };

        let payload = match decode_packet_payload(&raw, compression_threshold) {
            Ok(payload) => payload,
            Err(_) => {
                stats.dec_connecting();
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                stats
                    .record_rejection_reason("malformed login payload".to_string())
                    .await;
                return Ok(());
            }
        };

        let (packet_id, packet_id_size) = match decode_varint(&payload) {
            Ok(v) => v,
            Err(_) => {
                stats.dec_connecting();
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                stats
                    .record_rejection_reason("invalid login packet id".to_string())
                    .await;
                return Ok(());
            }
        };
        if packet_id == LOGIN_DISCONNECT_ID as i32 {
            stats.dec_connecting();
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            let reason =
                parse_disconnect_reason(&payload).unwrap_or_else(|| "disconnect".to_string());
            stats.record_rejection_reason(reason).await;
            return Ok(());
        }
        if packet_id == LOGIN_ENCRYPTION_REQUEST_ID as i32 {
            stats.dec_connecting();
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            stats
                .record_rejection_reason("online mode detected, skipping".to_string())
                .await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        if packet_id == LOGIN_SET_COMPRESSION_ID as i32 {
            let threshold = decode_varint(&payload[packet_id_size..])
                .ok()
                .map(|(v, _)| v)
                .unwrap_or(0);
            compression_threshold = Some(threshold);
            continue;
        }
        if packet_id == LOGIN_SUCCESS_ID as i32 {
            stats.dec_connecting();
            stats.inc_success_total();
            stats.inc_logged_in();
            let _logged_in_guard = LoggedInGuard {
                stats: stats.clone(),
            };
            let pending_play_frame = if protocol >= 767 {
                write_packet(
                    &mut stream,
                    &encode_varint(LOGIN_ACKNOWLEDGED_ID),
                    compression_threshold,
                    &stats,
                )
                .await?;
                match run_configuration_phase(&mut stream, &stats, &mut compression_threshold).await
                {
                    Ok(frame) => frame,
                    Err(PlayExitReason::TimedOut) => {
                        stats.timed_out.fetch_add(1, Ordering::Relaxed);
                        stats.inc_disconnected();
                        return Ok(());
                    }
                    Err(PlayExitReason::Disconnected) | Err(PlayExitReason::Completed) => {
                        stats.inc_disconnected();
                        return Ok(());
                    }
                }
            } else {
                None
            };

            let play_result = run_play_loop(
                &mut stream,
                hold_until,
                &stats,
                &mut compression_threshold,
                pending_play_frame,
            )
            .await?;
            if matches!(play_result, PlayExitReason::TimedOut) {
                stats.timed_out.fetch_add(1, Ordering::Relaxed);
            }
            stats.inc_disconnected();
            return Ok(());
        }
    }
}

async fn run_play_loop(
    stream: &mut TcpStream,
    hold_until: Instant,
    stats: &Arc<Stats>,
    compression_threshold: &mut Option<i32>,
    mut pending_frame: Option<Vec<u8>>,
) -> Result<PlayExitReason> {
    let mut last_keepalive_time: Option<Instant> = None;

    while Instant::now() < hold_until {
        let raw = if let Some(raw) = pending_frame.take() {
            raw
        } else {
            match read_frame(stream, READ_TIMEOUT, stats).await {
                Ok(raw) => raw,
                Err(FrameReadError::Timeout) => return Ok(PlayExitReason::TimedOut),
                Err(FrameReadError::Io) | Err(FrameReadError::Malformed) => {
                    return Ok(PlayExitReason::Disconnected);
                }
            }
        };

        let payload = match decode_packet_payload(&raw, *compression_threshold) {
            Ok(payload) => payload,
            Err(_) => return Ok(PlayExitReason::Disconnected),
        };

        let (packet_id, read) = match decode_varint(&payload) {
            Ok(v) => v,
            Err(_) => return Ok(PlayExitReason::Disconnected),
        };

        if packet_id == LOGIN_SET_COMPRESSION_ID as i32 {
            let threshold = decode_varint(&payload[read..])
                .ok()
                .map(|(v, _)| v)
                .unwrap_or(0);
            *compression_threshold = Some(threshold);
            continue;
        }

        if packet_id == CLIENTBOUND_KEEPALIVE_ID as i32 {
            if payload.len() < read + 8 {
                continue;
            }
            let keepalive_id = i64::from_be_bytes(
                payload[read..read + 8]
                    .try_into()
                    .context("keep alive payload too short")?,
            );

            let now = Instant::now();
            if let Some(last) = last_keepalive_time {
                let elapsed_ms = now.saturating_duration_since(last).as_millis() as u64;
                stats.record_latency_ms(elapsed_ms).await;
            }
            last_keepalive_time = Some(now);

            let mut keepalive_response = Vec::with_capacity(1 + 8);
            keepalive_response.extend_from_slice(&encode_varint(SERVERBOUND_KEEPALIVE_ID));
            keepalive_response.extend_from_slice(&keepalive_id.to_be_bytes());
            write_packet(stream, &keepalive_response, *compression_threshold, stats).await?;
        }
    }

    let _ = stream.shutdown().await;
    Ok(PlayExitReason::Completed)
}

async fn run_configuration_phase(
    stream: &mut TcpStream,
    stats: &Arc<Stats>,
    compression_threshold: &mut Option<i32>,
) -> std::result::Result<Option<Vec<u8>>, PlayExitReason> {
    let deadline = Instant::now() + CONFIG_FALLBACK_TIMEOUT;
    let mut saw_configuration_packet = false;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(now);
        let raw = match read_frame(stream, remaining, stats).await {
            Ok(raw) => raw,
            Err(FrameReadError::Timeout) => return Ok(None),
            Err(FrameReadError::Io) | Err(FrameReadError::Malformed) => {
                return Err(PlayExitReason::Disconnected);
            }
        };

        let payload = match decode_packet_payload(&raw, *compression_threshold) {
            Ok(payload) => payload,
            Err(_) => return Err(PlayExitReason::Disconnected),
        };
        let (packet_id, read) = match decode_varint(&payload) {
            Ok(v) => v,
            Err(_) => return Err(PlayExitReason::Disconnected),
        };

        if packet_id == CONFIG_CLIENTBOUND_PLUGIN_MESSAGE_ID {
            saw_configuration_packet = true;
            if let Some(channel) = parse_prefixed_string(&payload[read..]) {
                if channel == "minecraft:brand" {
                    let response = build_configuration_brand_response("vanilla");
                    if write_packet(stream, &response, *compression_threshold, stats)
                        .await
                        .is_err()
                    {
                        return Err(PlayExitReason::Disconnected);
                    }
                }
            }
            continue;
        }

        if packet_id == CONFIG_CLIENTBOUND_FEATURE_FLAGS_ID {
            saw_configuration_packet = true;
            continue;
        }

        if packet_id == CONFIG_CLIENTBOUND_KNOWN_PACKS_ID {
            saw_configuration_packet = true;
            let response = build_configuration_known_packs_empty();
            if write_packet(stream, &response, *compression_threshold, stats)
                .await
                .is_err()
            {
                return Err(PlayExitReason::Disconnected);
            }
            continue;
        }

        if packet_id == CONFIG_CLIENTBOUND_FINISH_CONFIGURATION_ID {
            if write_packet(
                stream,
                &encode_varint(CONFIG_SERVERBOUND_FINISH_ACK_ID),
                *compression_threshold,
                stats,
            )
            .await
            .is_err()
            {
                return Err(PlayExitReason::Disconnected);
            }
            return Ok(None);
        }

        if !saw_configuration_packet {
            return Ok(Some(raw));
        }
    }
}

async fn print_final_report(cli: &Cli, started: Instant, stats: Arc<Stats>) {
    let elapsed = started.elapsed().as_secs_f64();
    let attempted = u64::from(cli.players);
    let success = stats.success_total.load(Ordering::Relaxed);
    let peak_logged_in = stats.peak_logged_in.load(Ordering::Relaxed);
    let failed = stats.failed.load(Ordering::Relaxed);
    let disconnected = stats.disconnected.load(Ordering::Relaxed);
    let rejected = stats.rejected.load(Ordering::Relaxed);
    let timed_out = stats.timed_out.load(Ordering::Relaxed);
    let bytes_recv = stats.bytes_recv_total.load(Ordering::Relaxed);
    let bytes_sent = stats.bytes_sent_total.load(Ordering::Relaxed);

    let (min, p50, p99, p999, max) = {
        let hist = stats.latency_hist.lock().await;
        if hist.len() == 0 {
            (0, 0, 0, 0, 0)
        } else {
            (
                hist.min(),
                hist.value_at_quantile(0.50),
                hist.value_at_quantile(0.99),
                hist.value_at_quantile(0.999),
                hist.max(),
            )
        }
    };

    let success_rate = if attempted == 0 {
        0.0
    } else {
        (success as f64 / attempted as f64) * 100.0
    };

    println!();
    println!("=== Vex Bench Summary ===");
    println!("elapsed_secs: {:.2}", elapsed);
    println!("total_players_attempted: {}", attempted);
    println!("success_rate_percent: {:.2}", success_rate);
    println!("peak_concurrent_logged_in: {}", peak_logged_in);
    println!(
        "keep_alive_rtt_ms: min={} p50={} p99={} p999={} max={}",
        min, p50, p99, p999, max
    );
    println!(
        "bytes_transferred: recv_total={} sent_total={}",
        bytes_recv, bytes_sent
    );
    println!(
        "errors: failed={} disconnected={} rejected={} timed_out={}",
        failed, disconnected, rejected, timed_out
    );

    let mut reasons: Vec<(String, u64)> = stats
        .rejection_reasons
        .lock()
        .await
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    reasons.sort_by(|a, b| b.1.cmp(&a.1));
    if reasons.is_empty() {
        println!("rejection_reasons: none");
    } else {
        println!("rejection_reasons (top 10):");
        for (reason, count) in reasons.into_iter().take(10) {
            println!("  {} => {}", reason, count);
        }
    }
}

fn resolve_target(target: &str) -> Result<(String, String, u16)> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((target.to_string(), addr.ip().to_string(), addr.port()));
    }

    let Some((host, port_str)) = target.rsplit_once(':') else {
        bail!("target must be host:port");
    };
    let port: u16 = port_str.parse().context("invalid target port")?;
    Ok((target.to_string(), host.to_string(), port))
}

fn build_handshake(protocol: i32, host: &str, port: u16, next_state: i32) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut payload = Vec::with_capacity(16 + host_bytes.len());
    payload.extend_from_slice(&encode_varint(0));
    payload.extend_from_slice(&encode_varint(protocol));
    payload.extend_from_slice(&encode_varint(host_bytes.len() as i32));
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&port.to_be_bytes());
    payload.extend_from_slice(&encode_varint(next_state));
    payload
}

fn build_login_start(username: &str, protocol: i32) -> Vec<u8> {
    let username_bytes = username.as_bytes();
    let mut payload = Vec::with_capacity(username_bytes.len() + 10);
    payload.extend_from_slice(&encode_varint(0));
    payload.extend_from_slice(&encode_varint(username_bytes.len() as i32));
    payload.extend_from_slice(username_bytes);
    if protocol >= 764 {
        payload.push(0);
    } else if protocol == 763 {
        payload.push(0);
    }
    payload
}

async fn write_packet(
    stream: &mut TcpStream,
    payload: &[u8],
    compression_threshold: Option<i32>,
    stats: &Arc<Stats>,
) -> Result<()> {
    let body = encode_packet_payload(payload, compression_threshold)?;
    let header = encode_varint(body.len() as i32);
    stream.write_all(&header).await?;
    stream.write_all(&body).await?;
    stats
        .bytes_sent_total
        .fetch_add((header.len() + body.len()) as u64, Ordering::Relaxed);
    Ok(())
}

fn encode_packet_payload(payload: &[u8], compression_threshold: Option<i32>) -> Result<Vec<u8>> {
    let Some(threshold) = compression_threshold else {
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
    use std::io::Write;
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;
    let mut out = Vec::with_capacity(compressed.len() + 5);
    out.extend_from_slice(&encode_varint(payload.len() as i32));
    out.extend_from_slice(&compressed);
    Ok(out)
}

#[derive(Debug)]
enum FrameReadError {
    Timeout,
    Malformed,
    Io,
}

enum PlayExitReason {
    Completed,
    TimedOut,
    Disconnected,
}

async fn read_frame(
    stream: &mut TcpStream,
    timeout_dur: Duration,
    stats: &Arc<Stats>,
) -> std::result::Result<Vec<u8>, FrameReadError> {
    let mut len_buf = Vec::with_capacity(5);
    loop {
        let mut one = [0u8; 1];
        match tokio::time::timeout(timeout_dur, stream.read_exact(&mut one)).await {
            Ok(Ok(_)) => {
                len_buf.push(one[0]);
            }
            Ok(Err(_)) => return Err(FrameReadError::Io),
            Err(_) => return Err(FrameReadError::Timeout),
        }
        if (one[0] & 0x80) == 0 {
            break;
        }
        if len_buf.len() > 5 {
            return Err(FrameReadError::Malformed);
        }
    }
    let (packet_len, _) = decode_varint(&len_buf).map_err(|_| FrameReadError::Malformed)?;
    if packet_len <= 0 {
        return Err(FrameReadError::Malformed);
    }
    let packet_len = packet_len as usize;
    let mut payload = vec![0u8; packet_len];
    match tokio::time::timeout(timeout_dur, stream.read_exact(&mut payload)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return Err(FrameReadError::Io),
        Err(_) => return Err(FrameReadError::Timeout),
    }
    stats
        .bytes_recv_total
        .fetch_add((len_buf.len() + payload.len()) as u64, Ordering::Relaxed);
    Ok(payload)
}

fn decode_packet_payload(
    frame_payload: &[u8],
    compression_threshold: Option<i32>,
) -> Result<Vec<u8>> {
    if compression_threshold.is_none() {
        return Ok(frame_payload.to_vec());
    }

    let (data_length, read) = decode_varint(frame_payload)?;
    if data_length < 0 {
        bail!("negative data length in compressed frame");
    }
    if data_length == 0 {
        return Ok(frame_payload[read..].to_vec());
    }

    let mut decoder = ZlibDecoder::new(&frame_payload[read..]);
    let mut out = Vec::with_capacity(data_length as usize);
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn parse_disconnect_reason(payload: &[u8]) -> Option<String> {
    let (packet_id, mut offset) = decode_varint(payload).ok()?;
    if packet_id != LOGIN_DISCONNECT_ID as i32 {
        return None;
    }
    let (len, read) = decode_varint(&payload[offset..]).ok()?;
    if len < 0 {
        return None;
    }
    offset += read;
    let len = len as usize;
    if payload.len() < offset + len {
        return None;
    }
    let raw = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        if let Some(text) = value.get("text").and_then(Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(s) = value.as_str() {
            return Some(s.to_string());
        }
    }
    Some(raw.to_string())
}

fn parse_prefixed_string(input: &[u8]) -> Option<String> {
    let (len, read) = decode_varint(input).ok()?;
    if len < 0 {
        return None;
    }
    let len = len as usize;
    if input.len() < read + len {
        return None;
    }
    std::str::from_utf8(&input[read..read + len])
        .ok()
        .map(ToString::to_string)
}

fn build_configuration_brand_response(brand: &str) -> Vec<u8> {
    let channel = "minecraft:brand";
    let channel_bytes = channel.as_bytes();
    let brand_bytes = brand.as_bytes();

    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&encode_varint(CONFIG_SERVERBOUND_PLUGIN_MESSAGE_ID));
    payload.extend_from_slice(&encode_varint(channel_bytes.len() as i32));
    payload.extend_from_slice(channel_bytes);
    payload.extend_from_slice(&encode_varint(brand_bytes.len() as i32));
    payload.extend_from_slice(brand_bytes);
    payload
}

fn build_configuration_known_packs_empty() -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&encode_varint(CONFIG_SERVERBOUND_KNOWN_PACKS_ID));
    payload.extend_from_slice(&encode_varint(0));
    payload
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
            bail!("varint too big");
        }
        if (byte & 0x80) == 0 {
            break;
        }
    }
    Ok((result, num_read))
}
