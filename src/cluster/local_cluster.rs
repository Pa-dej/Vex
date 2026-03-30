use std::sync::Arc;

use tokio::sync::RwLock;
use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

use crate::cluster::pubsub::ClusterEvent;

type EventHandler = Arc<dyn Fn(ClusterEvent) + Send + Sync>;
type PlayersProvider = Arc<dyn Fn() -> Vec<RemotePlayerInfo> + Send + Sync>;
type OnlineProvider = Arc<dyn Fn() -> usize + Send + Sync>;
type BroadcastFn = Arc<dyn Fn(&str) + Send + Sync>;
type NodeProvider = Arc<dyn Fn() -> NodeInfo + Send + Sync>;

#[derive(Clone)]
pub struct LocalClusterHandle {
    players_provider: PlayersProvider,
    online_provider: OnlineProvider,
    broadcast_fn: BroadcastFn,
    node_provider: NodeProvider,
    handlers: Arc<RwLock<Vec<EventHandler>>>,
}

impl LocalClusterHandle {
    pub fn new(
        players_provider: PlayersProvider,
        online_provider: OnlineProvider,
        broadcast_fn: BroadcastFn,
        node_provider: NodeProvider,
    ) -> Self {
        Self {
            players_provider,
            online_provider,
            broadcast_fn,
            node_provider,
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn get_global_players(&self) -> Vec<RemotePlayerInfo> {
        (self.players_provider)()
    }

    pub fn get_global_online_count(&self) -> usize {
        (self.online_provider)()
    }

    pub fn broadcast_cluster(&self, message: &str) {
        (self.broadcast_fn)(message);
    }

    pub async fn publish_event(&self, event: ClusterEvent) {
        let handlers = self.handlers.read().await.clone();
        for handler in handlers {
            handler(event.clone());
        }
    }

    pub async fn subscribe(&self, handler: EventHandler) {
        self.handlers.write().await.push(handler);
    }

    pub fn get_node_list(&self) -> Vec<NodeInfo> {
        vec![(self.node_provider)()]
    }
}
