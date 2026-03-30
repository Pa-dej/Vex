pub mod local_cluster;
pub mod node_registry;
pub mod pubsub;
pub mod redis_cluster;
pub mod shared_state;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

use crate::cluster::local_cluster::LocalClusterHandle;
use crate::cluster::pubsub::ClusterEvent;
use crate::cluster::redis_cluster::RedisClusterHandle;
use crate::config::ClusterConfig;
use crate::metrics::Metrics;
use crate::shutdown::ShutdownManager;

type EventHandler = Arc<dyn Fn(ClusterEvent) + Send + Sync>;
type PlayersProvider = Arc<dyn Fn() -> Vec<RemotePlayerInfo> + Send + Sync>;
type OnlineProvider = Arc<dyn Fn() -> usize + Send + Sync>;
type BroadcastFn = Arc<dyn Fn(&str) + Send + Sync>;
type NodeProvider = Arc<dyn Fn() -> NodeInfo + Send + Sync>;

#[derive(Clone)]
pub enum ClusterMode {
    Local(LocalClusterHandle),
    Redis(Box<RedisClusterHandle>),
}

#[derive(Clone)]
pub struct ClusterHandle {
    mode: ClusterMode,
    node_id: Arc<str>,
}

impl ClusterHandle {
    pub async fn new(
        config: &ClusterConfig,
        players_provider: PlayersProvider,
        online_provider: OnlineProvider,
        broadcast_fn: BroadcastFn,
        node_provider: NodeProvider,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let node_id: Arc<str> = Arc::from(config.node_id.clone());
        if !config.enabled {
            return Ok(Self {
                mode: ClusterMode::Local(LocalClusterHandle::new(
                    players_provider,
                    online_provider,
                    broadcast_fn,
                    node_provider,
                )),
                node_id,
            });
        }

        let redis = RedisClusterHandle::new(
            node_id.clone(),
            &config.redis,
            Duration::from_millis(config.node_announce_interval_ms.max(250)),
            players_provider,
            online_provider,
            broadcast_fn,
            node_provider,
            metrics,
        )
        .await?;

        Ok(Self {
            mode: ClusterMode::Redis(Box::new(redis)),
            node_id,
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn start_background_tasks(&self, shutdown: ShutdownManager) {
        if let ClusterMode::Redis(redis) = &self.mode {
            redis.start_background_tasks(shutdown);
        }
    }

    pub async fn get_global_players(&self) -> Vec<RemotePlayerInfo> {
        match &self.mode {
            ClusterMode::Local(local) => local.get_global_players(),
            ClusterMode::Redis(redis) => redis.get_global_players().await,
        }
    }

    pub async fn get_global_online_count(&self) -> usize {
        match &self.mode {
            ClusterMode::Local(local) => local.get_global_online_count(),
            ClusterMode::Redis(redis) => redis.get_global_online_count().await,
        }
    }

    pub async fn broadcast_cluster(&self, message: &str) {
        match &self.mode {
            ClusterMode::Local(local) => local.broadcast_cluster(message),
            ClusterMode::Redis(redis) => redis.broadcast_cluster(message).await,
        }
    }

    pub async fn publish_event(&self, event: ClusterEvent) {
        match &self.mode {
            ClusterMode::Local(local) => local.publish_event(event).await,
            ClusterMode::Redis(redis) => {
                let _ = redis.publish_event(event).await;
            }
        }
    }

    pub async fn subscribe(&self, handler: EventHandler) {
        match &self.mode {
            ClusterMode::Local(local) => local.subscribe(handler).await,
            ClusterMode::Redis(redis) => redis.subscribe(handler).await,
        }
    }

    pub async fn get_node_list(&self) -> Vec<NodeInfo> {
        match &self.mode {
            ClusterMode::Local(local) => local.get_node_list(),
            ClusterMode::Redis(redis) => redis.get_node_list().await,
        }
    }

    pub fn is_clustered(&self) -> bool {
        matches!(self.mode, ClusterMode::Redis(_))
    }

    pub fn redis_connected(&self) -> bool {
        match &self.mode {
            ClusterMode::Local(_) => false,
            ClusterMode::Redis(redis) => redis.redis_connected(),
        }
    }

    pub async fn check_global_rate_limit(&self, ip: IpAddr, limit: u32) -> bool {
        match &self.mode {
            ClusterMode::Local(_) => true,
            ClusterMode::Redis(redis) => redis.check_global_rate_limit(ip, limit).await,
        }
    }

    pub async fn publish_reputation_delta(&self, ip: IpAddr, delta: i32) {
        if let ClusterMode::Redis(redis) = &self.mode {
            redis.publish_reputation_delta(ip, delta).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;
    use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

    use super::ClusterHandle;
    use crate::config::ClusterConfig;
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn local_mode_returns_local_only_results() {
        let players = vec![RemotePlayerInfo {
            uuid: Uuid::new_v4(),
            username: "Player".to_string(),
            node_id: "node-1".to_string(),
            backend: "lobby".to_string(),
            connected_at: 1,
        }];
        let node = NodeInfo {
            node_id: "node-1".to_string(),
            bind_addr: "127.0.0.1:25577".to_string(),
            online_players: 1,
            started_at: 1,
            version: "0.3.0".to_string(),
        };
        let handle = ClusterHandle::new(
            &ClusterConfig::default(),
            Arc::new({
                let players = players.clone();
                move || players.clone()
            }),
            Arc::new(|| 1usize),
            Arc::new(|_| {}),
            Arc::new({
                let node = node.clone();
                move || node.clone()
            }),
            Arc::new(Metrics::new().expect("metrics")),
        )
        .await
        .expect("cluster handle");

        assert!(!handle.is_clustered());
        assert_eq!(handle.get_global_online_count().await, 1);
        assert_eq!(handle.get_global_players().await.len(), 1);
        assert_eq!(handle.get_node_list().await.len(), 1);
        assert!(
            handle
                .check_global_rate_limit(std::net::IpAddr::from([127, 0, 0, 1]), 20)
                .await
        );
    }

    #[test]
    fn node_info_roundtrip_json() {
        let node = NodeInfo {
            node_id: "node-1".to_string(),
            bind_addr: "127.0.0.1:25577".to_string(),
            online_players: 5,
            started_at: 100,
            version: "0.3.0".to_string(),
        };
        let json = serde_json::to_string(&node).expect("serialize");
        let parsed: NodeInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(node, parsed);
    }

    #[test]
    fn remote_player_info_roundtrip_json() {
        let player = RemotePlayerInfo {
            uuid: Uuid::new_v4(),
            username: "Player".to_string(),
            node_id: "node-2".to_string(),
            backend: "survival".to_string(),
            connected_at: 50,
        };
        let json = serde_json::to_string(&player).expect("serialize");
        let parsed: RemotePlayerInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(player, parsed);
    }
}
