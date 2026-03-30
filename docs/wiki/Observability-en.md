# Observability (English)

Vex provides Prometheus metrics, structured logs, and a Grafana dashboard.

## Run the Grafana stack

```bash
docker compose -f docker-compose.observability.yml up -d
```

Grafana is typically exposed on `http://localhost:3000` with the pre-provisioned dashboard `vex-proxy-v1`.

## Enable JSON logs for production

```toml
[observability]
log_format = "json"
log_level = "info"
```

## trace_id correlation
Every connection gets a `trace_id` which appears in logs and spans:
- Use it to correlate handshake → login → backend routing.
- Plugin events also log with the same `trace_id` if they reference a player.

## Metrics (50+)

| Metric | Type | Description |
|---|---|---|
| `vex_connections_total` | counter | All TCP connections accepted. |
| `vex_connections_active` | gauge | Current active connections. |
| `vex_connections_rate` | gauge | Recent connections per second. |
| `vex_handshake_fail_total` | counter | Handshake failures. |
| `vex_login_success_total` | counter | Successful logins. |
| `vex_login_fail_total` | counter | Login failures. |
| `vex_auth_online_total` | counter | Online auth attempts. |
| `vex_auth_offline_total` | counter | Offline auth attempts. |
| `vex_status_ping_total` | counter | Status ping requests. |
| `vex_status_ping_fail_total` | counter | Status ping errors. |
| `vex_backend_connect_total` | counter | Backend connection attempts. |
| `vex_backend_connect_fail_total` | counter | Backend connection failures. |
| `vex_backend_latency_ms` | histogram | Backend login latency. |
| `vex_backend_active` | gauge | Active backend connections. |
| `vex_backend_healthy` | gauge | Healthy backends. |
| `vex_backend_unhealthy` | gauge | Unhealthy backends. |
| `vex_routing_selected_total` | counter | Backend selections. |
| `vex_routing_retry_total` | counter | Backend retry attempts. |
| `vex_routing_degraded_total` | counter | Degraded routing events. |
| `vex_player_online` | gauge | Online players (local). |
| `vex_player_login_duration_ms` | histogram | Login duration. |
| `vex_player_session_seconds` | histogram | Session length. |
| `vex_network_bytes_in_total` | counter | Bytes in from clients. |
| `vex_network_bytes_out_total` | counter | Bytes out to clients. |
| `vex_buffer_pool_bytes` | gauge | Total buffer pool size. |
| `vex_buffer_pool_in_use` | gauge | Buffers currently in use. |
| `vex_antibot_attack_mode` | gauge | Attack mode on/off (0/1). |
| `vex_antibot_attack_mode_seconds` | counter | Time spent in attack mode. |
| `vex_antibot_rate_limited_total` | counter | Rate-limited connections. |
| `vex_antibot_frame_reject_total` | counter | Malformed/oversize frame rejects. |
| `vex_antibot_conn_cap_reject_total` | counter | Global cap rejects. |
| `vex_antibot_ip_bucket_drops_total` | counter | Per-IP token drops. |
| `vex_antibot_subnet_bucket_drops_total` | counter | Per-/24 token drops. |
| `vex_reputation_score_avg` | gauge | Average reputation score. |
| `vex_reputation_blocks_total` | counter | Blocks triggered by reputation. |
| `vex_reputation_delay_total` | counter | Connections delayed by reputation. |
| `vex_plugin_events_total` | counter | Plugin events dispatched. |
| `vex_plugin_event_timeouts_total` | counter | Plugin handlers timed out. |
| `vex_plugin_panics_total` | counter | Plugin panics caught. |
| `vex_plugin_messages_total` | counter | Plugin messages seen. |
| `vex_plugin_message_drops_total` | counter | Plugin messages dropped. |
| `vex_scheduler_tasks_active` | gauge | Active scheduled tasks. |
| `vex_scheduler_tasks_total` | counter | Total scheduled tasks created. |
| `vex_cluster_nodes` | gauge | Nodes registered in cluster. |
| `vex_cluster_heartbeat_lag_ms` | histogram | Heartbeat lag from Redis. |
| `vex_cluster_redis_errors_total` | counter | Redis command errors. |
| `vex_cluster_pubsub_events_total` | counter | Cluster pub/sub events. |
| `vex_cluster_degraded` | gauge | Degraded mode on/off (0/1). |
| `vex_admin_requests_total` | counter | Admin API requests. |
| `vex_admin_auth_fail_total` | counter | Admin auth failures. |
| `vex_admin_reload_total` | counter | Reload calls. |
| `vex_admin_shutdown_total` | counter | Shutdown calls. |
| `vex_memory_bytes` | gauge | Resident memory bytes. |
| `vex_cpu_usage` | gauge | CPU usage percent. |
| `vex_trace_id_collisions_total` | counter | trace_id collisions (should be 0). |

## Custom plugin metrics
Plugins can register metrics with the Metrics API. Metric names are prefixed with `vex_plugin_<plugin>_...` and are removed when a plugin unloads.

## See also
- [Configuration Reference](Configuration-en)
- [Plugin Development](Plugin-Development-en)
- [Home](Home-en)
