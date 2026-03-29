# Vex Proxy

Vex is a high-performance Rust Minecraft proxy focused on safe hot reloads, graceful operations, anti-bot protection, and production observability.

## Current Capability Matrix

### v1
- [x] Core proxy + hot reload + graceful shutdown
- [x] Health checks + Prometheus metrics
- [x] Protocol whitelist + reject
- [x] Slowloris / idle timeout
- [x] 26 unit/integration tests

### v1.1
- [x] Velocity Modern Forwarding + HMAC
- [x] Online auth + AES/CFB8 + circuit breaker
- [x] Real UUID + skin properties

### v1.2
- [x] Global cap + per-IP/subnet token buckets
- [x] Early frame rejection
- [x] Rejection metrics

### G (Observability)
- [x] Structured logging (`json`/`pretty`) + per-connection `trace_id`
- [x] Expanded Prometheus metrics
- [x] Grafana dashboard (`uid: vex-proxy-v1`)
- [x] Docker Compose observability stack

### v2
- [x] Reputation cache + decay + cleanup
- [x] Adaptive penalties (200ms / 500ms / block)
- [x] Block escalation (30s / 2min / 10min)
- [x] Attack analytics + attack mode
- [x] 26 tests green

## Project Layout

- `src/main.rs`: app bootstrap, runtime wiring, admin + proxy startup
- `src/server.rs`: listener, handshake/login pipeline, backend relay, anti-bot integration
- `src/admin.rs`: admin HTTP API (`/healthz`, `/metrics`, `/reload`, `/auth/mode`, `/shutdown`)
- `src/metrics.rs`: Prometheus registry and metric helpers
- `src/reputation.rs`: per-IP reputation, penalties, decay, cleanup
- `src/analytics.rs`: sliding-window attack analytics and attack-mode signal
- `src/limiter.rs`: global cap + per-IP/per-subnet token buckets
- `scripts/v1_smoke_checks.py`: end-to-end smoke checks

## Quick Start

## 1) Start a backend (local mock)

```bash
cargo run --bin mock_backend -- --bind 127.0.0.1:25565 --secret test-secret-123 --velocity true
```

## 2) Start Vex

```bash
cargo run --bin Vex
```

Vex reads config from `vex.toml`.

## 3) Run smoke checks

```bash
python scripts/v1_smoke_checks.py
```

## 4) Run tests

```bash
cargo test
```

## Admin API

Default bind: `127.0.0.1:8080`  
Auth header: `x-admin-token: <token from vex.toml>`

- `GET /healthz`
- `GET /metrics`
- `POST /reload`
- `POST /auth/mode`
- `POST /shutdown`

## Observability Stack (Prometheus + Grafana)

Run:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Endpoints:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Vex metrics source: `http://host.docker.internal:8080/metrics`

Dashboard:

- File: `grafana/vex-dashboard.json`
- UID: `vex-proxy-v1`

## Anti-Bot Runtime Behavior (v2)

- Reputation score per IP, range `0..100`, starts at `50`
- Automatic score decay toward neutral over time
- Delay tiers:
- `25..49`: 200ms before backend dial
- `10..24`: 500ms before backend dial (+warn log)
- `<10`: temporary block with escalation (`30s`, `2min`, `10min`)
- Attack mode uses sliding-window analytics and can reduce limiter capacity by 50% until traffic stabilizes

## Notes

- No per-packet play-state deep inspection is used for anti-bot.
- Existing auth, relay, ArcSwap reload, and observability behavior are preserved while anti-bot v2 is integrated.
