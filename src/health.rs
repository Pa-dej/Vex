use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::mc::{
    build_handshake_packet, build_status_request, parse_packet_id, read_packet, write_packet,
};
use crate::state::RuntimeState;

pub fn spawn_health_checker(state: RuntimeState) {
    tokio::spawn(async move {
        loop {
            if state.shutdown.is_draining() {
                return;
            }

            let snapshot = state.snapshot();
            let cfg = snapshot.config.health.clone();

            for backend in snapshot.backends.backends() {
                let previous_state = backend.health();
                let status_probe = probe_status(
                    backend.address(),
                    snapshot.protocol_map.max_supported_id(),
                    cfg.status_timeout_ms,
                    snapshot.config.listener.max_packet_size,
                )
                .await;

                let mut status_ok = false;
                let mut tcp_ok = false;
                match status_probe {
                    Ok(status_latency) => {
                        status_ok = true;
                        state.metrics.observe_backend_latency(
                            backend.name(),
                            "status",
                            status_latency,
                        );
                    }
                    Err(err) => {
                        debug!(
                            backend = backend.name(),
                            error = %err,
                            "status probe failed, trying tcp fallback"
                        );
                        match probe_tcp(backend.address(), cfg.tcp_timeout_ms).await {
                            Ok(tcp_latency) => {
                                tcp_ok = true;
                                state.metrics.observe_backend_latency(
                                    backend.name(),
                                    "tcp_fallback",
                                    tcp_latency,
                                );
                            }
                            Err(tcp_err) => {
                                state
                                    .metrics
                                    .inc_backend_error(backend.name(), "probe_unreachable");
                                warn!(
                                    backend = backend.name(),
                                    status_error = %err,
                                    tcp_error = %tcp_err,
                                    "backend probe failed"
                                );
                            }
                        }
                    }
                }

                let new_state = backend.record_probe(
                    status_ok,
                    tcp_ok,
                    cfg.unhealthy_fail_threshold,
                    cfg.recovery_success_threshold,
                );
                if previous_state == crate::backend::BackendHealth::Unhealthy
                    && new_state == crate::backend::BackendHealth::Healthy
                {
                    state.metrics.inc_backend_reconnect(backend.name());
                }
                state
                    .metrics
                    .set_backend_health_state(backend.name(), new_state.encoded());
            }

            tokio::time::sleep(Duration::from_millis(cfg.interval_ms)).await;
        }
    });
}

async fn probe_status(
    backend_addr: &str,
    protocol_version: i32,
    timeout_ms: u64,
    max_packet_size: usize,
) -> anyhow::Result<f64> {
    let start = Instant::now();
    let mut stream = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(backend_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("status connect timeout"))?
    .map_err(|e| anyhow::anyhow!("status connect error: {e}"))?;

    let (host, port) = split_host_port(backend_addr)?;
    let hs = build_handshake_packet(protocol_version, host, port, 1);
    write_packet(&mut stream, &hs).await?;
    let req = build_status_request();
    write_packet(&mut stream, &req).await?;

    let response = timeout(
        Duration::from_millis(timeout_ms),
        read_packet(&mut stream, max_packet_size),
    )
    .await
    .map_err(|_| anyhow::anyhow!("status read timeout"))??;

    let (packet_id, _) = parse_packet_id(&response)?;
    if packet_id != 0 {
        anyhow::bail!("unexpected status response packet id {packet_id}");
    }

    Ok(start.elapsed().as_secs_f64())
}

async fn probe_tcp(backend_addr: &str, timeout_ms: u64) -> anyhow::Result<f64> {
    let start = Instant::now();
    let stream = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(backend_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("tcp fallback timeout"))?
    .map_err(|e| anyhow::anyhow!("tcp fallback connect error: {e}"))?;
    drop(stream);
    Ok(start.elapsed().as_secs_f64())
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
