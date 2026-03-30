use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ClusterEvent {
    PlayerJoined {
        node_id: String,
        player: RemotePlayerInfo,
    },
    PlayerLeft {
        node_id: String,
        uuid: Uuid,
        username: String,
    },
    AttackModeOn {
        node_id: String,
        cps: f64,
    },
    AttackModeOff {
        node_id: String,
    },
    ReputationDelta {
        ip: IpAddr,
        delta: i32,
        source_node: String,
    },
    Broadcast {
        message: String,
        source_node: String,
    },
    NodeUp {
        node_info: NodeInfo,
    },
    NodeDown {
        node_id: String,
    },
    PluginMessage {
        channel: String,
        data: Vec<u8>,
        source_node: String,
    },
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::ClusterEvent;
    use uuid::Uuid;
    use vex_proxy_sdk::server::{NodeInfo, RemotePlayerInfo};

    fn roundtrip(event: ClusterEvent) {
        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: ClusterEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, event);
    }

    #[test]
    fn cluster_event_roundtrip_all_variants() {
        let sample_player = RemotePlayerInfo {
            uuid: Uuid::new_v4(),
            username: "Test".to_string(),
            node_id: "node-1".to_string(),
            backend: "lobby".to_string(),
            connected_at: 123,
        };
        let sample_node = NodeInfo {
            node_id: "node-1".to_string(),
            bind_addr: "0.0.0.0:25577".to_string(),
            online_players: 4,
            started_at: 123,
            version: "0.3.0".to_string(),
        };

        roundtrip(ClusterEvent::PlayerJoined {
            node_id: "node-1".to_string(),
            player: sample_player.clone(),
        });
        roundtrip(ClusterEvent::PlayerLeft {
            node_id: "node-1".to_string(),
            uuid: sample_player.uuid,
            username: sample_player.username.clone(),
        });
        roundtrip(ClusterEvent::AttackModeOn {
            node_id: "node-1".to_string(),
            cps: 144.0,
        });
        roundtrip(ClusterEvent::AttackModeOff {
            node_id: "node-1".to_string(),
        });
        roundtrip(ClusterEvent::ReputationDelta {
            ip: Ipv4Addr::new(1, 2, 3, 4).into(),
            delta: -25,
            source_node: "node-1".to_string(),
        });
        roundtrip(ClusterEvent::Broadcast {
            message: "hello".to_string(),
            source_node: "node-1".to_string(),
        });
        roundtrip(ClusterEvent::NodeUp {
            node_info: sample_node,
        });
        roundtrip(ClusterEvent::NodeDown {
            node_id: "node-2".to_string(),
        });
        roundtrip(ClusterEvent::PluginMessage {
            channel: "vex:test".to_string(),
            data: vec![1, 2, 3],
            source_node: "node-1".to_string(),
        });
    }
}
