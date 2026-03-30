# Changelog (English)

## v1.0 — Core proxy
- Initial proxy core
- Health checks + hot reload
- Graceful shutdown and drain

## v1.1 — Online auth + Velocity forwarding
- Online auth with Mojang validation
- Velocity modern forwarding (HMAC)
- AES/CFB8 encryption

## v1.2 — Basic anti-bot
- Global connection cap
- Per-IP and /24 token buckets
- Early frame rejection

## v1.3 — Observability
- Prometheus metrics
- JSON logging with trace_id
- Grafana dashboard provisioning

## v2.0 — Advanced anti-bot
- Reputation scoring (0–100)
- Adaptive delays by score
- Block escalation (30s → 2m → 10m)
- Attack mode auto-detection

## v3.0 — Plugin API + vex-proxy-sdk
- Native Rust plugins
- 17 event hooks
- Metrics API for plugins
- Plugin hot reload + file watcher

## v4.0 — Clustering
- Redis-backed node registry
- Shared reputation and rate limits
- Pub/sub events and global session registry
- Degraded mode and Redis circuit breaker

## See also
- [Home](Home-en.md)
- [Comparison](Comparison-en.md)
