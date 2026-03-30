# Vex Proxy

High-performance Rust Minecraft Java proxy with hot reload, anti-bot, observability, and a dynamic plugin API.

## 1) Benchmark: Vex vs Gate vs BungeeCord

Internal benchmark scenario: 10,000 concurrent connections, same host class, measured resident memory per connection.

| Proxy | Runtime | Memory per connection | Relative to Vex |
|---|---|---:|---:|
| **Vex** | Rust + Tokio | **26 KB** | 1.0x |
| Gate | Go | 97 KB | 3.7x |
| BungeeCord | JVM | 153 KB | 5.9x |

Vex reached 100% successful connection handling in this benchmark profile.

## 2) Quick Start (3 commands)

### Command 1: Start a local backend

```bash
cargo run --bin mock_backend -- --bind 127.0.0.1:25565 --secret test-secret-123 --velocity true
```

### Command 2: Start Vex

```bash
cargo run --bin Vex
```

### Command 3: Run smoke checks

```bash
python scripts/v1_smoke_checks.py
```

Optional anti-bot suite:

```bash
python scripts/test_antibot.py
```

On Windows terminals that default to cp1251, run:

```cmd
set PYTHONIOENCODING=utf-8 && python scripts/test_antibot.py
```

## 3) Config Reference

Main config file: `vex.toml`

| Section | Key fields | Purpose |
|---|---|---|
| `[listener]` | `bind`, `max_packet_size` | Proxy listening address and frame limits |
| `[routing]` | `allow_degraded`, `[[routing.backends]]` | Backend pool and selection behavior |
| `[auth]` | `mode` (`offline`, `online`, `auto`) | Authentication mode |
| `[forwarding.velocity]` | `enabled`, `secret` | Velocity modern forwarding |
| `[limits]` | `max_connections*`, `handshake_timeout_ms`, `login_timeout_ms` | Capacity and protocol safety limits |
| `[anti_bot]` | `enabled`, `attack_*` thresholds | Attack mode trigger thresholds |
| `[reputation]` | `decay_interval_secs`, `block_duration_*` | Reputation decay and penalty tuning |
| `[health]` | `interval_ms`, `status_timeout_ms`, `tcp_timeout_ms` | Backend health probing and transitions |
| `[plugins]` | `enabled`, `dir`, `event_handler_timeout_ms`, `intercept_plugin_messages`, `watch`, `watch_debounce_ms` | Plugin host/runtime settings |
| `[status]` | `motd`, `max_players`, `show_real_online` | Status ping and MOTD behavior |
| `[admin]` | `bind`, `auth_token` | Admin API endpoint and auth |
| `[shutdown]` | `drain_seconds`, `disconnect_message` | Graceful drain behavior |
| `[protocol_map]` | `path` | Supported protocol ID table |

Admin API endpoints:

- `GET /healthz`
- `GET /metrics`
- `POST /reload`
- `POST /auth/mode`
- `POST /commands/{name}`
- `POST /shutdown`

All protected endpoints require `x-admin-token`.

## 4) Plugin API (v3.0-beta) - Hello World

Plugins are Rust dynamic libraries (`.dll`, `.so`, `.dylib`) that link against the standalone `vex-proxy-sdk` crate (local path `vex-sdk/` in this repo).

Minimal plugin skeleton:

```rust
use std::error::Error;
use std::sync::Arc;
use vex_proxy_sdk::VexPlugin;
use vex_proxy_sdk::api::PluginApi;
use vex_proxy_sdk::event::OnLoginSuccess;

struct HelloPlugin;

impl VexPlugin for HelloPlugin {
    fn name(&self) -> &'static str { "hello_plugin" }
    fn version(&self) -> &'static str { "3.0.0-beta" }

    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
        api.logger.info("Hello from hello_plugin!");
        let proxy = api.proxy.clone();
        api.events.on::<OnLoginSuccess, _, _>(move |event| {
            let proxy = proxy.clone();
            async move {
                proxy.broadcast(&format!("{} joined!", event.player.username));
            }
        });
        Ok(())
    }

    fn on_unload(&self) {}
}

#[no_mangle]
pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
    Box::new(HelloPlugin)
}
```

Working example plugin is included in `examples/hello_plugin`.

Build and load:

```bash
cargo build -p hello_plugin --release
```

Copy the generated library to the `plugins/` directory, then call:

```bash
curl -X POST http://127.0.0.1:8080/reload -H "x-admin-token: change-me"
```

What plugins get in v3.0-beta:

- Full proxy event surface (connect, handshake, pre-login, backend lifecycle, kick/switch, status ping, reload, attack mode, health transitions, permission checks)
- Hot reload by file change (`[plugins].watch = true`) with partial reload (changed plugins only)
- Plugin command registration
- Per-player typed metadata store
- Zero-copy plugin messaging via `Bytes`
- Metrics registration (`vex_plugin_<plugin>_<metric>`) with unload cleanup
- `transfer()` for backend switch without full reconnect

## 5) Architecture: Why Rust, Why Fast

Vex is designed for low overhead and operational safety:

- **Tokio async IO** for high connection density without thread explosion
- **ArcSwap runtime snapshots** for atomic config/protocol/backend reloads
- **Session registry + relay control channel** for safe disconnect/pause/switch commands
- **Plugin event bus** with per-handler timeout and panic isolation
- **Zero-copy byte paths** where possible (plugin messages via `Bytes`)
- **No extra hot-path overhead** when plugin-message interception is disabled
- **Prometheus-first observability** and structured logging for production diagnosis

Rust gives deterministic performance and memory behavior without JVM GC pauses, while keeping safety guarantees at compile time.

## 6) Roadmap (from PLAN.md)

| Milestone | Status | Scope |
|---|---|---|
| v1 | Done | Core proxy, health checks, hot reload, graceful shutdown |
| v1.1 | Done | Velocity forwarding, online auth, AES/CFB8, circuit breaker |
| v1.2 | Done | Connection caps, token buckets, frame hardening |
| v2 | Done | Reputation system, adaptive penalties, attack analytics |
| v3.0-alpha | Done | SDK surface, host scaffold, transfer/plugin messaging wiring |
| **v3.0-beta** | **Done** | Full event set, hot reload improvements, plugin metrics |
| v3.0 | Next | Release docs, SDK polish, examples, packaging |
| v3.1 | Planned | Plugin registry/marketplace |
| v4 | Planned | Clustering/synchronized distributed state |

## 7) License and Notes

- This repository currently ships both English (`README.md`) and Russian (`README_RU.md`) docs.
- Bench numbers above are project-reported values from the current development plan and benchmark setup.
