# Configuration Reference (English)

This page documents every field in `vex.toml`. Examples are valid TOML.

## [listener]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `bind` (string) | `"0.0.0.0:25577"` | Address to listen for client connections. | `bind = "0.0.0.0:25577"` |
| `max_packet_size` (int) | `2097152` | Hard limit for inbound packet/frame size (bytes). | `max_packet_size = 2097152` |
| `read_timeout_ms` (int) | `15000` | Read timeout for client sockets (ms). | `read_timeout_ms = 15000` |
| `write_timeout_ms` (int) | `15000` | Write timeout for client sockets (ms). | `write_timeout_ms = 15000` |

Example:

```toml
[listener]
bind = "0.0.0.0:25577"
max_packet_size = 2097152
read_timeout_ms = 15000
write_timeout_ms = 15000
```

## [auth]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `mode` (string) | `"auto"` | `offline`, `online`, or `auto`. | `mode = "online"` |
| `online_timeout_ms` (int) | `5000` | Timeout for session validation (ms). | `online_timeout_ms = 5000` |
| `session_server` (string) | `"https://sessionserver.mojang.com"` | Mojang session server URL override. | `session_server = "https://sessionserver.mojang.com"` |

Example:

```toml
[auth]
mode = "auto"
online_timeout_ms = 5000
session_server = "https://sessionserver.mojang.com"
```

## [forwarding.velocity]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `enabled` (bool) | `false` | Enable Velocity modern forwarding. | `enabled = true` |
| `secret` (string) | `"change-me"` | HMAC secret shared with backend. | `secret = "change-me-velocity"` |

Example:

```toml
[forwarding.velocity]
enabled = true
secret = "change-me-velocity"
```

## [routing]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `strategy` (string) | `"least_connections"` | Backend selection algorithm. | `strategy = "least_connections"` |
| `allow_degraded` (bool) | `true` | Continue operating when all backends are unhealthy. | `allow_degraded = true` |
| `health_check_enabled` (bool) | `true` | Enable active health checks. | `health_check_enabled = true` |
| `connect_timeout_ms` (int) | `3000` | Backend connect timeout (ms). | `connect_timeout_ms = 3000` |
| `retry_on_fail` (bool) | `true` | Retry a different backend on connect failure. | `retry_on_fail = true` |

### [[routing.backends]]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `name` (string) | _(required)_ | Backend identifier used in logs and plugins. | `name = "paper-1"` |
| `address` (string) | _(required)_ | `host:port` of backend server. | `address = "127.0.0.1:25565"` |
| `weight` (int) | `100` | Relative weight for load balancing. | `weight = 100` |
| `max_connections` (int) | `2000` | Per-backend connection cap. | `max_connections = 2000` |
| `force_online_mode` (bool) | `false` | Force online auth for this backend. | `force_online_mode = false` |

Example:

```toml
[routing]
strategy = "least_connections"
allow_degraded = true
health_check_enabled = true
connect_timeout_ms = 3000
retry_on_fail = true

[[routing.backends]]
name = "paper-1"
address = "127.0.0.1:25565"
weight = 100
max_connections = 2000
force_online_mode = false
```

## [limits]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `max_connections` (int) | `20000` | Global concurrent connection cap. | `max_connections = 20000` |
| `max_connections_per_ip` (int) | `50` | Per-IP concurrent cap. | `max_connections_per_ip = 50` |
| `handshake_timeout_ms` (int) | `3000` | Time allowed to finish handshake. | `handshake_timeout_ms = 3000` |
| `login_timeout_ms` (int) | `8000` | Time allowed to finish login. | `login_timeout_ms = 8000` |
| `idle_timeout_ms` (int) | `30000` | Disconnect idle connections. | `idle_timeout_ms = 30000` |

Example:

```toml
[limits]
max_connections = 20000
max_connections_per_ip = 50
handshake_timeout_ms = 3000
login_timeout_ms = 8000
idle_timeout_ms = 30000
```

## [anti_bot]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `enabled` (bool) | `true` | Master switch for anti-bot. | `enabled = true` |
| `global_conn_cap` (int) | `25000` | Global cap enforced before reputation logic. | `global_conn_cap = 25000` |
| `per_ip_rate_per_sec` (int) | `10` | Token bucket refill rate per IP. | `per_ip_rate_per_sec = 10` |
| `per_subnet_rate_per_sec` (int) | `200` | Token bucket refill rate per /24 subnet. | `per_subnet_rate_per_sec = 200` |
| `early_reject` (bool) | `true` | Reject malformed/oversized frames early. | `early_reject = true` |
| `attack_mode_enabled` (bool) | `true` | Enable automatic attack mode. | `attack_mode_enabled = true` |
| `attack_mode_threshold_rps` (int) | `3000` | RPS threshold to trigger attack mode. | `attack_mode_threshold_rps = 3000` |
| `attack_mode_cooldown_secs` (int) | `60` | Seconds of calm before disabling attack mode. | `attack_mode_cooldown_secs = 60` |

Example:

```toml
[anti_bot]
enabled = true
global_conn_cap = 25000
per_ip_rate_per_sec = 10
per_subnet_rate_per_sec = 200
early_reject = true
attack_mode_enabled = true
attack_mode_threshold_rps = 3000
attack_mode_cooldown_secs = 60
```

## [reputation]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `enabled` (bool) | `true` | Enable reputation scoring. | `enabled = true` |
| `neutral_score` (int) | `50` | Starting score for new IPs. | `neutral_score = 50` |
| `min_score` (int) | `0` | Lower bound for score. | `min_score = 0` |
| `max_score` (int) | `100` | Upper bound for score. | `max_score = 100` |
| `decay_interval_secs` (int) | `60` | Interval for decay toward neutral. | `decay_interval_secs = 60` |
| `decay_step` (int) | `1` | Step size toward neutral per interval. | `decay_step = 1` |
| `delay_score_25_49_ms` (int) | `200` | Delay for score 25–49. | `delay_score_25_49_ms = 200` |
| `delay_score_10_24_ms` (int) | `500` | Delay for score 10–24. | `delay_score_10_24_ms = 500` |
| `block_duration_1_secs` (int) | `30` | First block duration. | `block_duration_1_secs = 30` |
| `block_duration_2_secs` (int) | `120` | Second block duration. | `block_duration_2_secs = 120` |
| `block_duration_3_secs` (int) | `600` | Third block duration. | `block_duration_3_secs = 600` |

Example:

```toml
[reputation]
enabled = true
neutral_score = 50
min_score = 0
max_score = 100
decay_interval_secs = 60
decay_step = 1
delay_score_25_49_ms = 200
delay_score_10_24_ms = 500
block_duration_1_secs = 30
block_duration_2_secs = 120
block_duration_3_secs = 600
```

## [health]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `interval_ms` (int) | `1500` | Interval between checks. | `interval_ms = 1500` |
| `status_timeout_ms` (int) | `1000` | Timeout for status ping. | `status_timeout_ms = 1000` |
| `tcp_timeout_ms` (int) | `800` | Timeout for TCP connect fallback. | `tcp_timeout_ms = 800` |
| `unhealthy_threshold` (int) | `3` | Failures before marking unhealthy. | `unhealthy_threshold = 3` |
| `healthy_threshold` (int) | `2` | Successes before marking healthy. | `healthy_threshold = 2` |

Example:

```toml
[health]
interval_ms = 1500
status_timeout_ms = 1000
tcp_timeout_ms = 800
unhealthy_threshold = 3
healthy_threshold = 2
```

## [observability]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `log_level` (string) | `"info"` | Logging level (`trace`, `debug`, `info`, `warn`, `error`). | `log_level = "info"` |
| `log_format` (string) | `"pretty"` | `pretty` or `json`. | `log_format = "json"` |
| `metrics_enabled` (bool) | `true` | Expose Prometheus metrics. | `metrics_enabled = true` |
| `metrics_bind` (string) | `"0.0.0.0:9100"` | Bind address for metrics endpoint. | `metrics_bind = "0.0.0.0:9100"` |
| `metrics_path` (string) | `"/metrics"` | HTTP path for Prometheus. | `metrics_path = "/metrics"` |

Example:

```toml
[observability]
log_level = "info"
log_format = "json"
metrics_enabled = true
metrics_bind = "0.0.0.0:9100"
metrics_path = "/metrics"
```

## [admin]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `bind` (string) | `"127.0.0.1:8080"` | Admin API address. | `bind = "127.0.0.1:8080"` |
| `auth_token` (string) | `"change-me"` | Token for `x-admin-token` header. | `auth_token = "change-me"` |
| `allow_reload` (bool) | `true` | Allow POST `/reload`. | `allow_reload = true` |
| `allow_shutdown` (bool) | `true` | Allow POST `/shutdown`. | `allow_shutdown = true` |

Example:

```toml
[admin]
bind = "127.0.0.1:8080"
auth_token = "change-me"
allow_reload = true
allow_shutdown = true
```

## [shutdown]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `drain_seconds` (int) | `10` | Graceful drain time before force disconnect. | `drain_seconds = 10` |
| `disconnect_message` (string) | `"Proxy shutting down"` | Kick message during shutdown. | `disconnect_message = "Proxy restarting"` |

Example:

```toml
[shutdown]
drain_seconds = 10
disconnect_message = "Proxy shutting down"
```

## [protocol_map]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `path` (string) | `"config/protocol_map.toml"` | Protocol ID map file. | `path = "config/protocol_map.toml"` |

Example:

```toml
[protocol_map]
path = "config/protocol_map.toml"
```

## [plugins]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `enabled` (bool) | `true` | Master switch for plugin host. | `enabled = true` |
| `dir` (string) | `"plugins"` | Plugin directory. | `dir = "plugins"` |
| `event_handler_timeout_ms` (int) | `500` | Max time per handler. | `event_handler_timeout_ms = 500` |
| `intercept_plugin_messages` (bool) | `false` | Enable plugin message interception. | `intercept_plugin_messages = true` |
| `watch` (bool) | `true` | Watch plugin directory for changes. | `watch = true` |
| `watch_debounce_ms` (int) | `250` | Debounce for reload events. | `watch_debounce_ms = 250` |

Example:

```toml
[plugins]
enabled = true
dir = "plugins"
event_handler_timeout_ms = 500
intercept_plugin_messages = false
watch = true
watch_debounce_ms = 250
```

## [status]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `motd` (string) | `"Vex Proxy"` | Default MOTD. | `motd = "Vex Proxy"` |
| `max_players` (int) | `1000` | Shown in status ping. | `max_players = 1000` |
| `show_real_online` (bool) | `true` | Report real online instead of capped. | `show_real_online = true` |
| `sample_players` (array) | `[]` | Sample players shown in status ping. | `sample_players = ["Vex", "Proxy"]` |

Example:

```toml
[status]
motd = "Vex Proxy"
max_players = 1000
show_real_online = true
sample_players = ["Vex", "Proxy"]
```

## [cluster]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `enabled` (bool) | `false` | Enable clustering. | `enabled = true` |
| `node_id` (string) | `"node-1"` | Unique ID of this node. | `node_id = "edge-1"` |
| `heartbeat_interval_secs` (int) | `5` | Heartbeat interval. | `heartbeat_interval_secs = 5` |
| `heartbeat_ttl_secs` (int) | `15` | TTL for node registry. | `heartbeat_ttl_secs = 15` |
| `allow_degraded` (bool) | `true` | Continue when Redis unavailable. | `allow_degraded = true` |

Example:

```toml
[cluster]
enabled = true
node_id = "edge-1"
heartbeat_interval_secs = 5
heartbeat_ttl_secs = 15
allow_degraded = true
```

## [cluster.redis]

| Field (type) | Default | Description | Example |
|---|---|---|---|
| `url` (string) | `"redis://127.0.0.1:6379"` | Redis connection URL. | `url = "redis://127.0.0.1:6379"` |
| `connect_timeout_ms` (int) | `1000` | Timeout for initial connection. | `connect_timeout_ms = 1000` |
| `command_timeout_ms` (int) | `500` | Timeout for Redis commands. | `command_timeout_ms = 500` |
| `circuit_breaker_errors` (int) | `5` | Errors before breaker opens. | `circuit_breaker_errors = 5` |
| `circuit_breaker_reset_ms` (int) | `5000` | Reset interval for breaker. | `circuit_breaker_reset_ms = 5000` |
| `pubsub_channel` (string) | `"vex.cluster"` | Pub/sub channel name. | `pubsub_channel = "vex.cluster"` |

Example:

```toml
[cluster.redis]
url = "redis://127.0.0.1:6379"
connect_timeout_ms = 1000
command_timeout_ms = 500
circuit_breaker_errors = 5
circuit_breaker_reset_ms = 5000
pubsub_channel = "vex.cluster"
```

## See also
- [Getting Started](Getting-Started-en.md)
- [Clustering](Clustering-en.md)
- [Anti-Bot](Anti-Bot-en.md)
- [Home](Home-en.md)
