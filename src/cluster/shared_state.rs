use std::collections::HashMap;
use std::net::IpAddr;

use vex_proxy_sdk::server::RemotePlayerInfo;

pub fn merge_players(
    local_players: Vec<RemotePlayerInfo>,
    mut remote_players: Vec<RemotePlayerInfo>,
) -> Vec<RemotePlayerInfo> {
    let mut merged = HashMap::with_capacity(local_players.len() + remote_players.len());
    for player in local_players {
        merged.insert(player.uuid, player);
    }
    for player in remote_players.drain(..) {
        merged.entry(player.uuid).or_insert(player);
    }
    merged.into_values().collect()
}

pub fn take_worst_score(local_score: i32, remote_score: i32) -> i32 {
    local_score.min(remote_score)
}

pub fn build_reputation_delta(
    ip: IpAddr,
    delta: i32,
    source_node: impl Into<String>,
) -> crate::cluster::pubsub::ClusterEvent {
    crate::cluster::pubsub::ClusterEvent::ReputationDelta {
        ip,
        delta,
        source_node: source_node.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use uuid::Uuid;
    use vex_proxy_sdk::server::RemotePlayerInfo;

    use super::{merge_players, take_worst_score};

    #[test]
    fn take_worst_score_prefers_lower_value() {
        assert_eq!(take_worst_score(50, 40), 40);
        assert_eq!(take_worst_score(20, 35), 20);
    }

    #[test]
    fn merge_players_deduplicates_by_uuid() {
        let uuid = Uuid::new_v4();
        let local = vec![RemotePlayerInfo {
            uuid,
            username: "Local".to_string(),
            node_id: "node-1".to_string(),
            backend: "lobby".to_string(),
            connected_at: 1,
        }];
        let remote = vec![RemotePlayerInfo {
            uuid,
            username: "Remote".to_string(),
            node_id: "node-2".to_string(),
            backend: "hub".to_string(),
            connected_at: 2,
        }];

        let merged = merge_players(local, remote);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].node_id, "node-1");
    }

    #[test]
    fn build_reputation_delta_wraps_cluster_event() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let event = super::build_reputation_delta(ip, -25, "node-1");
        if let crate::cluster::pubsub::ClusterEvent::ReputationDelta {
            ip: event_ip,
            delta,
            source_node,
        } = event
        {
            assert_eq!(event_ip, ip);
            assert_eq!(delta, -25);
            assert_eq!(source_node, "node-1");
        } else {
            panic!("expected reputation delta");
        }
    }
}
