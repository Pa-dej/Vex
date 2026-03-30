pub const NODE_TTL_SECS: u64 = 15;
pub const SESSION_TTL_SECS: u64 = 10;

pub fn node_key(prefix: &str, node_id: &str) -> String {
    format!("{prefix}nodes:{node_id}")
}

pub fn node_list_key(prefix: &str) -> String {
    format!("{prefix}nodes:list")
}

pub fn sessions_key(prefix: &str, node_id: &str) -> String {
    format!("{prefix}sessions:{node_id}")
}

pub fn ratelimit_key(prefix: &str, ip: &str, window_second: u64) -> String {
    format!("{prefix}ratelimit:{ip}:{window_second}")
}

pub fn reputation_key(prefix: &str, ip: &str) -> String {
    format!("{prefix}reputation:{ip}")
}

pub fn events_channel(prefix: &str) -> String {
    format!("{prefix}events")
}

pub fn reputation_channel(prefix: &str) -> String {
    format!("{prefix}reputation:channel")
}
