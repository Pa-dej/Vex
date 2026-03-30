use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const STALE_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireRejectReason {
    GlobalCap,
    IpRateLimit,
    SubnetRateLimit,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: f64,
    refill_per_second: f64,
    tokens: f64,
    last_refill: Instant,
    last_touched: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_second: u32, now: Instant) -> Self {
        let capacity = capacity as f64;
        Self {
            capacity,
            refill_per_second: refill_per_second as f64,
            tokens: capacity,
            last_refill: now,
            last_touched: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.last_touched = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn is_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_touched) > STALE_AFTER
    }

    fn refill(&mut self, now: Instant) {
        if self.capacity <= 0.0 || self.refill_per_second <= 0.0 {
            self.tokens = 0.0;
            self.last_refill = now;
            return;
        }
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.last_refill = now;
    }
}

pub struct ConnectionLimiter {
    max_connections_total: u32,
    per_ip_rate_limit: u32,
    per_subnet_rate_limit: u32,
    rate_limit_scale_bps: AtomicU32,
    active_connections: AtomicU32,
    ip_buckets: DashMap<IpAddr, TokenBucket>,
    subnet_buckets: DashMap<[u8; 3], TokenBucket>,
}

impl ConnectionLimiter {
    pub fn new(
        max_connections_total: u32,
        per_ip_rate_limit: u32,
        per_subnet_rate_limit: u32,
    ) -> Self {
        Self {
            max_connections_total,
            per_ip_rate_limit,
            per_subnet_rate_limit,
            rate_limit_scale_bps: AtomicU32::new(10_000),
            active_connections: AtomicU32::new(0),
            ip_buckets: DashMap::new(),
            subnet_buckets: DashMap::new(),
        }
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<ConnectionLease, AcquireRejectReason> {
        let previous = self.active_connections.fetch_add(1, Ordering::AcqRel);
        if previous >= self.max_connections_total {
            self.active_connections.fetch_sub(1, Ordering::AcqRel);
            return Err(AcquireRejectReason::GlobalCap);
        }

        let now = Instant::now();
        if !self.take_ip_token(ip, now) {
            self.active_connections.fetch_sub(1, Ordering::AcqRel);
            return Err(AcquireRejectReason::IpRateLimit);
        }

        if !self.take_subnet_token(subnet_key(ip), now) {
            self.active_connections.fetch_sub(1, Ordering::AcqRel);
            return Err(AcquireRejectReason::SubnetRateLimit);
        }

        Ok(ConnectionLease {
            limiter: self.clone(),
        })
    }

    #[cfg(test)]
    pub fn active_connections(&self) -> u32 {
        self.active_connections.load(Ordering::Acquire)
    }

    pub fn cleanup_stale(&self) {
        let now = Instant::now();
        self.ip_buckets.retain(|_, bucket| !bucket.is_stale(now));
        self.subnet_buckets
            .retain(|_, bucket| !bucket.is_stale(now));
    }

    pub fn set_attack_mode(&self, active: bool) {
        let bps = if active { 5_000 } else { 10_000 };
        self.rate_limit_scale_bps.store(bps, Ordering::Release);
    }

    pub fn spawn_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLEANUP_INTERVAL).await;
                self.cleanup_stale();
            }
        })
    }

    fn take_ip_token(&self, ip: IpAddr, now: Instant) -> bool {
        let effective = self.scaled_rate_limit(self.per_ip_rate_limit);
        self.take_token(&self.ip_buckets, ip, effective, now)
    }

    fn take_subnet_token(&self, key: [u8; 3], now: Instant) -> bool {
        let effective = self.scaled_rate_limit(self.per_subnet_rate_limit);
        self.take_token(&self.subnet_buckets, key, effective, now)
    }

    fn take_token<K>(
        &self,
        map: &DashMap<K, TokenBucket>,
        key: K,
        rate_limit: u32,
        now: Instant,
    ) -> bool
    where
        K: Eq + Hash + Copy,
    {
        if rate_limit == 0 {
            return false;
        }
        let mut bucket = map
            .entry(key)
            .or_insert_with(|| TokenBucket::new(rate_limit, rate_limit, now));
        bucket.capacity = rate_limit as f64;
        bucket.refill_per_second = rate_limit as f64;
        bucket.tokens = bucket.tokens.min(bucket.capacity);
        bucket.try_take(now)
    }

    fn scaled_rate_limit(&self, base: u32) -> u32 {
        if base == 0 {
            return 0;
        }
        let scale = self.rate_limit_scale_bps.load(Ordering::Acquire) as u64;
        let scaled = ((base as u64 * scale) / 10_000) as u32;
        scaled.max(1)
    }
}

pub struct ConnectionLease {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.limiter
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn subnet_key(ip: IpAddr) -> [u8; 3] {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            [octets[0], octets[1], octets[2]]
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            [octets[0], octets[1], octets[2]]
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    use anyhow::{Result, bail};
    use serde_json::Value;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::*;
    use crate::backend::BackendPool;
    use crate::config::{BackendConfig, Config};
    use crate::mc::{parse_varint, read_packet};
    use crate::metrics::Metrics;
    use crate::protocol_map::ProtocolMap;
    use crate::server::run_proxy_server;
    use crate::state::RuntimeState;

    #[test]
    fn token_bucket_refill_math_respects_capacity_and_rate() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(2, 2, now);
        assert!(bucket.try_take(now));
        assert!(bucket.try_take(now));
        assert!(!bucket.try_take(now));

        let half_second = now + Duration::from_millis(500);
        assert!(bucket.try_take(half_second));
        assert!(!bucket.try_take(half_second));

        let one_and_half_second = now + Duration::from_millis(1500);
        assert!(bucket.try_take(one_and_half_second));
        assert!(bucket.try_take(one_and_half_second));
        assert!(!bucket.try_take(one_and_half_second));
    }

    #[test]
    fn subnet_key_extraction_ipv4_and_ipv6() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13));
        assert_eq!(subnet_key(ipv4), [10, 11, 12]);

        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1);
        let octets = ipv6.octets();
        assert_eq!(
            subnet_key(IpAddr::V6(ipv6)),
            [octets[0], octets[1], octets[2]]
        );
    }

    #[test]
    fn global_cap_counter_increments_and_decrements() {
        let limiter = Arc::new(ConnectionLimiter::new(1, 100, 100));
        assert_eq!(limiter.active_connections(), 0);
        let lease = limiter
            .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("first acquire");
        assert_eq!(limiter.active_connections(), 1);
        assert_eq!(
            limiter.try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST)).err(),
            Some(AcquireRejectReason::GlobalCap)
        );
        drop(lease);
        assert_eq!(limiter.active_connections(), 0);
    }

    #[tokio::test]
    async fn integration_rejects_connection_when_global_cap_reached() -> Result<()> {
        let backend_probe = TcpListener::bind("127.0.0.1:0").await?;
        let backend_addr = backend_probe.local_addr()?;
        drop(backend_probe);

        let proxy_probe = TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy_probe.local_addr()?;
        drop(proxy_probe);

        let mut config = Config::default();
        config.listener.bind = proxy_addr.to_string();
        config.limits.max_connections_total = 2;
        config.limits.max_connections = 100;
        config.limits.handshake_timeout_ms = 10_000;
        config.shutdown.drain_seconds = 0;
        config.routing.backends = vec![BackendConfig {
            name: "backend".to_string(),
            address: backend_addr.to_string(),
            weight: 1.0,
        }];

        let protocol_map = ProtocolMap::load(Path::new("config/protocol_ids.toml"))?;
        let metrics = Arc::new(Metrics::new()?);
        let backends = BackendPool::from_config(&config.routing, metrics.clone())?;
        let state = RuntimeState::new(config, protocol_map, metrics, backends).await?;

        let state_for_server = state.clone();
        let server_task = tokio::spawn(async move { run_proxy_server(state_for_server).await });

        let conn_a = TcpStream::connect(proxy_addr).await?;
        let conn_b = TcpStream::connect(proxy_addr).await?;
        let mut conn_c = TcpStream::connect(proxy_addr).await?;

        let packet = timeout(
            Duration::from_secs(2),
            read_packet(&mut conn_c, 8 * 1024 * 1024),
        )
        .await??;
        let text = parse_disconnect_text(&packet)?;
        if !text.contains("Server is full") {
            bail!("expected 'Server is full', got '{text}'");
        }

        drop(conn_a);
        drop(conn_b);
        drop(conn_c);
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
        let parsed: Value = serde_json::from_str(raw)?;
        Ok(parsed
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or(raw)
            .to_string())
    }
}
