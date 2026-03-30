# Vex Proxy (English)

High-performance Rust Minecraft Java proxy with built-in clustering, anti-bot, and native Rust plugins.

![crates.io](https://img.shields.io/crates/v/vex-proxy.svg) ![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg) ![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)

## Benchmark (10,000 concurrent connections)

| Proxy | Runtime | Peak RAM | KB/conn | Success | Timeouts |
|---|---|---:|---:|---:|---:|
| **Vex** | Rust | **258 MB** | **26 KB** | **100%** | **0** |
| Gate | Go | 968 MB | 97 KB | 100% | 0 |
| BungeeCord | JVM | 1526 MB | 153 KB | 100% | 428 |

After test (memory retained): Vex 14 MB, Gate 22 MB, BungeeCord 707 MB.

## Features

### Core proxy
- Minecraft Java 1.20–1.21.4 (protocol 763–774)
- Online + offline auth with Mojang session validation
- AES/CFB8 encryption
- Velocity modern forwarding with HMAC
- Weighted least-connections load balancing
- Active health checks (status ping + TCP fallback)
- Atomic hot reload via ArcSwap
- Graceful shutdown with connection drain
- Slowloris/idle timeout protection
- Per-connection buffer pools

### Anti-bot (v1.2 + v2)
- Global connection cap
- Per-IP and per-/24 subnet token buckets
- Early frame rejection (malformed/oversized)
- Reputation cache (0–100 per IP)
- Adaptive delays by score
- Escalating blocks (30s → 2m → 10m)
- Attack mode auto-detection and throttling
- Reputation decay toward neutral every 60s
- Cross-node sync via Redis (v4)

### Observability
- Prometheus metrics (50+)
- Structured JSON logging with per-connection trace_id
- Grafana dashboard (vex-proxy-v1, auto-provisioned)
- Docker Compose stack (Prometheus + Grafana + Redis)

### Plugin API (v3.0)
- Native Rust dynamic plugins (.dll/.so/.dylib)
- 17 core events (login, backend, status, reload, attack mode, etc.)
- transfer() to switch backends without disconnect
- Dynamic MOTD via status ping event
- Zero-copy plugin messaging (Bytes)
- Per-player metadata store (type-safe DashMap)
- Command registry with permission checks
- Scheduler API (run_later, run_timer, run_next_tick)
- Config API (YAML, save_default)
- Tab list, title, actionbar, chat message APIs
- Metrics API (custom Prometheus metrics)
- Plugin hot-reload with file watcher
- ABI version check (VEX_SDK_VERSION)
- 500ms handler timeout with panic isolation

### Clustering (v4)
- Redis backend and node registry (TTL 15s)
- Shared reputation across nodes
- Global rate limiting via Redis counters
- Pub/sub events (attack mode, reputation delta, broadcast)
- Global session registry (get_all_players)
- Degraded mode when Redis is unavailable
- Circuit breaker for Redis operations
- Admin API: /cluster/status, /cluster/nodes

### Admin API
- GET /healthz, GET /metrics
- POST /reload, /auth/mode, /shutdown
- POST /commands/{name}
- Auth via x-admin-token header

## Quick links
- [Getting Started](Getting-Started-en.md)
- [Configuration Reference](Configuration-en.md)
- [Plugin Development](Plugin-Development-en.md)
- [Plugin API Reference](Plugin-API-Reference-en.md)
- [Anti-Bot](Anti-Bot-en.md)
- [Clustering](Clustering-en.md)
- [Observability](Observability-en.md)
- [Comparison](Comparison-en.md)
- [Changelog](Changelog-en.md)

## See also
- [Home (RU)](Home-ru.md)
- [README](../../README.md)
