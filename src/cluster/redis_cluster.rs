use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use redis::AsyncCommands;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

use crate::cluster::node_registry::{
    NODE_TTL_SECS, SESSION_TTL_SECS, events_channel, node_key, node_list_key, ratelimit_key,
    reputation_channel, sessions_key,
};
use crate::cluster::pubsub::ClusterEvent;
use crate::config::ClusterRedisConfig;
use crate::metrics::Metrics;
use crate::shutdown::ShutdownManager;

type EventHandler = Arc<dyn Fn(ClusterEvent) + Send + Sync>;
type PlayersProvider = Arc<dyn Fn() -> Vec<RemotePlayerInfo> + Send + Sync>;
type OnlineProvider = Arc<dyn Fn() -> usize + Send + Sync>;
type BroadcastFn = Arc<dyn Fn(&str) + Send + Sync>;
type NodeProvider = Arc<dyn Fn() -> NodeInfo + Send + Sync>;

type RedisOpFuture<'a, T> = Pin<Box<dyn Future<Output = redis::RedisResult<T>> + Send + 'a>>;

#[derive(Clone)]
pub struct RedisClusterHandle {
    node_id: Arc<str>,
    prefix: Arc<str>,
    client: redis::Client,
    manager: redis::aio::ConnectionManager,
    connect_timeout: Duration,
    op_timeout: Duration,
    node_announce_interval: Duration,
    players_provider: PlayersProvider,
    online_provider: OnlineProvider,
    broadcast_fn: BroadcastFn,
    node_provider: NodeProvider,
    metrics: Arc<Metrics>,
    handlers: Arc<RwLock<Vec<EventHandler>>>,
    circuit_breaker: Arc<RedisCircuitBreaker>,
    degrade_state: Arc<DegradeState>,
    background_started: Arc<AtomicBool>,
}

impl RedisClusterHandle {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        node_id: Arc<str>,
        redis_cfg: &ClusterRedisConfig,
        node_announce_interval: Duration,
        players_provider: PlayersProvider,
        online_provider: OnlineProvider,
        broadcast_fn: BroadcastFn,
        node_provider: NodeProvider,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let connect_timeout = Duration::from_millis(redis_cfg.connect_timeout_ms.max(1));
        let client = redis::Client::open(redis_cfg.url.as_str())?;
        let manager = timeout(
            connect_timeout,
            redis::aio::ConnectionManager::new(client.clone()),
        )
        .await
        .map_err(|_| anyhow!("redis connect timeout"))??;
        Ok(Self {
            node_id,
            prefix: Arc::from(redis_cfg.prefix.clone()),
            client,
            manager,
            connect_timeout,
            op_timeout: Duration::from_millis(redis_cfg.operation_timeout_ms.max(1)),
            node_announce_interval,
            players_provider,
            online_provider,
            broadcast_fn,
            node_provider,
            metrics,
            handlers: Arc::new(RwLock::new(Vec::new())),
            circuit_breaker: Arc::new(RedisCircuitBreaker::new()),
            degrade_state: Arc::new(DegradeState::default()),
            background_started: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn redis_connected(&self) -> bool {
        !self.degrade_state.degraded.load(Ordering::Relaxed)
    }

    pub fn start_background_tasks(&self, shutdown: ShutdownManager) {
        if self
            .background_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let heartbeat = self.clone();
        let mut heartbeat_shutdown = shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                if heartbeat_shutdown.borrow().is_some() {
                    break;
                }
                let cycle_started = Instant::now();
                let node_info = (heartbeat.node_provider)();
                let sessions = (heartbeat.players_provider)();
                let _ = heartbeat.announce_node(&node_info).await;
                let _ = heartbeat.write_sessions(&sessions).await;
                heartbeat
                    .metrics
                    .observe_cluster_sync_duration(cycle_started.elapsed().as_secs_f64());
                tokio::select! {
                    _ = tokio::time::sleep(heartbeat.node_announce_interval) => {}
                    changed = heartbeat_shutdown.changed() => {
                        if changed.is_ok() && heartbeat_shutdown.borrow().is_some() {
                            break;
                        }
                    }
                }
            }
            let _ = heartbeat.remove_self().await;
        });

        let subscriber = self.clone();
        let mut subscribe_shutdown = shutdown.subscribe();
        tokio::spawn(async move {
            let channel = events_channel(&subscriber.prefix);
            loop {
                if subscribe_shutdown.borrow().is_some() {
                    break;
                }

                let connection = timeout(
                    subscriber.connect_timeout,
                    subscriber.client.get_async_pubsub(),
                )
                .await;
                let Ok(Ok(mut pubsub)) = connection else {
                    subscriber.on_redis_failure("connect_subscribe");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                };
                if pubsub.subscribe(&channel).await.is_err() {
                    subscriber.on_redis_failure("subscribe");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                let mut stream = pubsub.on_message();

                loop {
                    tokio::select! {
                        changed = subscribe_shutdown.changed() => {
                            if changed.is_ok() && subscribe_shutdown.borrow().is_some() {
                                return;
                            }
                        }
                        message = stream.next() => {
                            let Some(message) = message else {
                                break;
                            };
                            let payload: redis::RedisResult<String> = message.get_payload();
                            let Ok(payload) = payload else {
                                subscriber.on_redis_failure("pubsub_payload");
                                continue;
                            };
                            let parsed: serde_json::Result<ClusterEvent> = serde_json::from_str(&payload);
                            let Ok(event) = parsed else {
                                continue;
                            };

                            if let ClusterEvent::Broadcast { source_node, message } = &event
                                && source_node != subscriber.node_id()
                            {
                                (subscriber.broadcast_fn)(message);
                            }

                            subscriber.metrics.inc_cluster_events_received();
                            let handlers = subscriber.handlers.read().await.clone();
                            for handler in handlers {
                                handler(event.clone());
                            }
                        }
                    }
                }
            }
        });
    }

    pub async fn get_global_players(&self) -> Vec<RemotePlayerInfo> {
        let local = (self.players_provider)();
        let mut remote = self.get_remote_players().await.unwrap_or_default();
        remote.retain(|player| player.node_id != self.node_id());
        let mut merged = crate::cluster::shared_state::merge_players(local, remote);
        self.metrics.set_cluster_global_players(merged.len() as i64);
        merged.sort_by(|a, b| a.username.cmp(&b.username));
        merged
    }

    pub async fn get_global_online_count(&self) -> usize {
        let local_online = (self.online_provider)();
        let remote_online = self
            .get_remote_players()
            .await
            .map(|players| players.len())
            .unwrap_or(0);
        local_online + remote_online
    }

    pub async fn broadcast_cluster(&self, message: &str) {
        (self.broadcast_fn)(message);
        let event = ClusterEvent::Broadcast {
            message: message.to_string(),
            source_node: self.node_id.to_string(),
        };
        let _ = self.publish_event(event).await;
    }

    pub async fn publish_event(&self, event: ClusterEvent) -> Result<()> {
        let payload = serde_json::to_string(&event)?;
        let channel = events_channel(&self.prefix);
        let publish_result: Result<i64> = self
            .with_redis("publish", move |conn| {
                let channel = channel.clone();
                let payload = payload.clone();
                Box::pin(async move {
                    redis::cmd("PUBLISH")
                        .arg(channel)
                        .arg(payload)
                        .query_async(conn)
                        .await
                })
            })
            .await;

        if publish_result.is_ok() {
            self.metrics.inc_cluster_events_published();
        }
        publish_result.map(|_| ())
    }

    pub async fn subscribe(&self, handler: EventHandler) {
        self.handlers.write().await.push(handler);
    }

    pub async fn get_node_list(&self) -> Vec<NodeInfo> {
        self.fetch_nodes().await.unwrap_or_else(|_| {
            let node = (self.node_provider)();
            vec![node]
        })
    }

    pub async fn check_global_rate_limit(&self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let now_second = unix_ts();
        let key = ratelimit_key(&self.prefix, &ip.to_string(), now_second);
        let result: Result<i64> = self
            .with_redis("ratelimit_incr", move |conn| {
                let key = key.clone();
                Box::pin(async move {
                    let count: i64 = redis::cmd("INCR").arg(&key).query_async(conn).await?;
                    let _: i64 = redis::cmd("EXPIRE")
                        .arg(&key)
                        .arg(2)
                        .query_async(conn)
                        .await?;
                    Ok(count)
                })
            })
            .await;
        match result {
            Ok(count) => count <= i64::from(limit),
            Err(_) => true,
        }
    }

    pub async fn publish_reputation_delta(&self, ip: IpAddr, delta: i32) {
        let _ = self
            .publish_event(crate::cluster::shared_state::build_reputation_delta(
                ip,
                delta,
                self.node_id.to_string(),
            ))
            .await;
        let reputation_key =
            crate::cluster::node_registry::reputation_key(&self.prefix, &ip.to_string());
        let _: Result<i64> = self
            .with_redis("reputation_set", move |conn| {
                let reputation_key = reputation_key.clone();
                Box::pin(async move {
                    redis::cmd("SET")
                        .arg(&reputation_key)
                        .arg(delta)
                        .arg("EX")
                        .arg(3600)
                        .query_async(conn)
                        .await
                })
            })
            .await;
        let _ = reputation_channel(&self.prefix);
    }

    async fn announce_node(&self, node_info: &NodeInfo) -> Result<()> {
        let node_key = node_key(&self.prefix, self.node_id());
        let node_list = node_list_key(&self.prefix);
        let payload = serde_json::to_string(node_info)?;
        let _: () = self
            .with_redis("announce_node", move |conn| {
                let node_key = node_key.clone();
                let node_list = node_list.clone();
                let payload = payload.clone();
                let node_id = node_info.node_id.clone();
                Box::pin(async move {
                    let _: () = redis::pipe()
                        .cmd("SET")
                        .arg(&node_key)
                        .arg(payload)
                        .arg("EX")
                        .arg(NODE_TTL_SECS)
                        .ignore()
                        .cmd("SADD")
                        .arg(&node_list)
                        .arg(node_id)
                        .ignore()
                        .query_async(conn)
                        .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn write_sessions(&self, players: &[RemotePlayerInfo]) -> Result<()> {
        let key = sessions_key(&self.prefix, self.node_id());
        let payload = serde_json::to_string(players)?;
        let _: () = self
            .with_redis("write_sessions", move |conn| {
                let key = key.clone();
                let payload = payload.clone();
                Box::pin(async move {
                    redis::cmd("SET")
                        .arg(&key)
                        .arg(payload)
                        .arg("EX")
                        .arg(SESSION_TTL_SECS)
                        .query_async(conn)
                        .await
                })
            })
            .await?;
        Ok(())
    }

    async fn remove_self(&self) -> Result<()> {
        let key = node_key(&self.prefix, self.node_id());
        let node_list = node_list_key(&self.prefix);
        let sessions_key = sessions_key(&self.prefix, self.node_id());
        let _: () = self
            .with_redis("remove_node", move |conn| {
                let key = key.clone();
                let node_list = node_list.clone();
                let sessions_key = sessions_key.clone();
                let node_id = self.node_id.to_string();
                Box::pin(async move {
                    let _: () = redis::pipe()
                        .cmd("DEL")
                        .arg(&key)
                        .ignore()
                        .cmd("DEL")
                        .arg(&sessions_key)
                        .ignore()
                        .cmd("SREM")
                        .arg(&node_list)
                        .arg(node_id)
                        .ignore()
                        .query_async(conn)
                        .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn fetch_nodes(&self) -> Result<Vec<NodeInfo>> {
        let node_list_key = node_list_key(&self.prefix);
        let node_ids: Vec<String> = self
            .with_redis("nodes_list", move |conn| {
                let node_list_key = node_list_key.clone();
                Box::pin(async move { conn.smembers(node_list_key).await })
            })
            .await?;

        if node_ids.is_empty() {
            return Ok(vec![(self.node_provider)()]);
        }

        let mut nodes = Vec::with_capacity(node_ids.len());
        for node_id in node_ids {
            let key = node_key(&self.prefix, &node_id);
            let raw: Option<String> = self
                .with_redis("node_get", move |conn| {
                    let key = key.clone();
                    Box::pin(async move { conn.get(key).await })
                })
                .await
                .ok();
            let Some(raw) = raw else {
                continue;
            };
            if let Ok(node) = serde_json::from_str::<NodeInfo>(&raw) {
                nodes.push(node);
            }
        }
        if nodes.is_empty() {
            nodes.push((self.node_provider)());
        }
        self.metrics.set_cluster_nodes_active(nodes.len() as i64);
        Ok(nodes)
    }

    async fn get_remote_players(&self) -> Result<Vec<RemotePlayerInfo>> {
        let nodes = self.fetch_nodes().await?;
        let mut players = Vec::new();
        for node in nodes {
            if node.node_id == self.node_id() {
                continue;
            }
            let key = sessions_key(&self.prefix, &node.node_id);
            let raw: Option<String> = self
                .with_redis("sessions_get", move |conn| {
                    let key = key.clone();
                    Box::pin(async move { conn.get(key).await })
                })
                .await
                .ok();
            let Some(raw) = raw else {
                continue;
            };
            if let Ok(mut node_players) = serde_json::from_str::<Vec<RemotePlayerInfo>>(&raw) {
                players.append(&mut node_players);
            }
        }
        Ok(players)
    }

    async fn with_redis<T, F>(&self, op_type: &'static str, op: F) -> Result<T>
    where
        F: for<'a> FnOnce(&'a mut redis::aio::ConnectionManager) -> RedisOpFuture<'a, T>,
    {
        if self.circuit_breaker.is_open() {
            self.metrics.inc_cluster_redis_error("circuit_open");
            return Err(anyhow!("redis circuit open"));
        }

        let mut conn = self.manager.clone();

        let result = timeout(self.op_timeout, op(&mut conn)).await;
        match result {
            Ok(Ok(value)) => {
                self.circuit_breaker.record_success();
                self.on_redis_success();
                self.metrics.inc_cluster_redis_op(op_type);
                Ok(value)
            }
            Ok(Err(err)) => {
                self.on_redis_failure(op_type);
                Err(err.into())
            }
            Err(_) => {
                self.on_redis_failure("operation_timeout");
                Err(anyhow!("redis operation timeout"))
            }
        }
    }

    fn on_redis_failure(&self, operation: &str) {
        self.circuit_breaker.record_failure();
        self.metrics.inc_cluster_redis_error(operation);
        self.degrade_state.warn_once();
    }

    fn on_redis_success(&self) {
        self.degrade_state.restore_once();
    }
}

#[derive(Default)]
struct DegradeState {
    degraded: AtomicBool,
    last_warn_at: AtomicU64,
}

impl DegradeState {
    fn warn_once(&self) {
        self.degraded.store(true, Ordering::Relaxed);
        let now = unix_ts();
        let last = self.last_warn_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= 60
            && self
                .last_warn_at
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            warn!("cluster degraded: Redis unreachable");
        }
    }

    fn restore_once(&self) {
        if self
            .degraded
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            info!("cluster restored");
        }
    }
}

#[derive(Default)]
pub struct RedisCircuitBreaker {
    consecutive_failures: AtomicU32,
    open_until: AtomicU64,
}

impl RedisCircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_open(&self) -> bool {
        let now = unix_ts();
        now < self.open_until.load(Ordering::Relaxed)
    }

    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= 3 {
            self.open_until.store(unix_ts() + 10, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);
            debug!("redis circuit breaker opened for 10s");
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.open_until.store(0, Ordering::Relaxed);
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::time::timeout;
    use vex_proxy_sdk::server::NodeInfo;

    use super::RedisCircuitBreaker;
    use crate::cluster::RedisClusterHandle;
    use crate::config::ClusterRedisConfig;
    use crate::metrics::Metrics;
    use crate::shutdown::ShutdownManager;

    #[test]
    fn circuit_breaker_opens_after_three_failures() {
        let breaker = Arc::new(RedisCircuitBreaker::new());
        assert!(!breaker.is_open());
        breaker.record_failure();
        breaker.record_failure();
        assert!(!breaker.is_open());
        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "integration"), ignore)]
    async fn node_heartbeat_appears_in_registry() -> Result<()> {
        let redis_cfg = ClusterRedisConfig::default();
        let metrics = Arc::new(Metrics::new()?);
        let handle = RedisClusterHandle::new(
            Arc::from("node-test"),
            &redis_cfg,
            Duration::from_millis(500),
            Arc::new(Vec::new),
            Arc::new(|| 0),
            Arc::new(|_| {}),
            Arc::new(|| NodeInfo {
                node_id: "node-test".to_string(),
                bind_addr: "127.0.0.1:25577".to_string(),
                online_players: 0,
                started_at: 1,
                version: "test".to_string(),
            }),
            metrics,
        )
        .await?;
        let shutdown = ShutdownManager::new();
        handle.start_background_tasks(shutdown.clone());
        let nodes = timeout(Duration::from_secs(3), async {
            loop {
                let nodes = handle.get_node_list().await;
                if nodes.iter().any(|n| n.node_id == "node-test") {
                    return nodes;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        assert!(nodes.iter().any(|node| node.node_id == "node-test"));
        shutdown.trigger("test done".to_string());
        Ok(())
    }
}
