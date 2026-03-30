<div align="center">

<img src="assets/vex_banner.svg" width="280" />

<br/><br/>

[![language](https://img.shields.io/badge/language-Rust-D07030?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![rust version](https://img.shields.io/badge/rust-1.75+-D07030?style=flat-square)](https://blog.rust-lang.org)
[![version](https://img.shields.io/badge/version-0.1.0-D07030?style=flat-square)](https://github.com/Pa-dej/Vex/releases)
[![plugin sdk](https://img.shields.io/crates/v/vex-proxy-sdk?style=flat-square&label=plugin%20sdk&color=D07030)](https://crates.io/crates/vex-proxy-sdk)
![lines of rust](https://img.shields.io/endpoint?style=flat-square&label=lines%20of%20Rust&color=D07030&url=https%3A%2F%2Fghloc.vercel.app%2Fapi%2FPa-dej%2FVex%2Fbadge%3Ffilter%3D.rs%24)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-D07030?style=flat-square)](LICENSE)

</div>

---

## Documentation

- 🇬🇧 English — `docs/wiki/Home-en.md` (or [GitHub Wiki](https://github.com/Pa-dej/Vex/wiki))
- 🇷🇺 Русский — `docs/wiki/Home-ru.md`

---

## Benchmark (latest local)

> 10,000 concurrent connections · mock_backend · release build (2026-03-30)

| Metric | Result |
|---|---|
| Success rate | 100% |
| Peak concurrent logged_in | 10,000 |
| Vex peak RSS | 291 MB (~29.1 KB/conn) |
| mock_backend peak RSS | 39.9 MB |
| Timeouts / rejects | 0 / 0 |

Historical comparisons (Gate/BungeeCord) live in `PLAN.md` and should be revalidated for official claims.

---

## Quick Start

**1. Start a local backend**
```bash
cargo run --release --bin mock_backend -- --bind 127.0.0.1:25565 --secret test-secret-123 --velocity true
```

**2. Start Vex**
```bash
cargo run --release --bin Vex
```

**3. Run smoke checks**
```bash
python scripts/v1_smoke_checks.py
```

<details>
<summary>Anti-bot suite & Windows note</summary>

```bash
python scripts/test_antibot.py
```

On Windows terminals that default to cp1251:
```cmd
set PYTHONIOENCODING=utf-8 && python scripts/test_antibot.py
```

</details>

---

## Protocol support

Supported protocol IDs are listed in `config/protocol_ids.toml` (currently 1.20–1.21.11). The synthetic `bench` tool may lag the newest login packet changes; use real clients or `mock_backend` for load testing on brand-new versions.

---

## Config Reference

Main config file: `vex.toml`

| Section | Key fields | Purpose |
|---|---|---|
| `[listener]` | `bind`, `max_packet_size` | Proxy listening address and frame limits |
| `[routing]` | `allow_degraded`, `[[routing.backends]]` | Backend pool and selection behavior |
| `[auth]` | `mode` (`offline`, `online`, `auto`) | Authentication mode |
| `[forwarding.velocity]` | `enabled`, `secret` | Velocity modern forwarding |
| `[limits]` | `max_connections*`, `handshake_timeout_ms`, `login_timeout_ms` | Capacity, timeouts, memory caps |
| `[anti_bot]` | `enabled`, `attack_*` thresholds | Attack mode trigger thresholds |
| `[reputation]` | `decay_interval_secs`, `block_duration_*` | Reputation decay and penalty tuning |
| `[health]` | `interval_ms`, `status_timeout_ms`, `tcp_timeout_ms` | Backend health probing and transitions |
| `[plugins]` | `enabled`, `dir`, `event_handler_timeout_ms`, `watch`, `watch_debounce_ms` | Plugin host/runtime settings |
| `[status]` | `motd`, `max_players`, `show_real_online` | Status ping and MOTD behavior |
| `[admin]` | `bind`, `auth_token` | Admin API endpoint and auth |
| `[shutdown]` | `drain_seconds`, `disconnect_message` | Graceful drain behavior |
| `[protocol_map]` | `path` | Supported protocol ID table |
| `[observability]` | `log_level`, `log_format` | Logging + metrics output |
| `[cluster]` | `enabled`, `node_id` | Clustering (experimental) |
| `[cluster.redis]` | `url`, `prefix` | Redis transport for cluster |

<details>
<summary>Admin API endpoints</summary>

All protected endpoints require `x-admin-token` header.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `POST` | `/reload` | Hot reload config & plugins |
| `POST` | `/auth/mode` | Switch auth mode at runtime |
| `POST` | `/commands/{name}` | Dispatch plugin command |
| `POST` | `/shutdown` | Graceful shutdown |
| `GET` | `/cluster/status` | Cluster status |
| `GET` | `/cluster/nodes` | Cluster node list |

</details>

---

## Plugin API — SDK 0.3.x (alpha)

Plugins are Rust dynamic libraries (`.dll` / `.so` / `.dylib`) linked against `vex-proxy-sdk` (local path `vex-sdk/`). The SDK is evolving; breaking changes may still occur before 1.0.

<details>
<summary>Hello World plugin</summary>

```rust
use std::error::Error;
use std::sync::Arc;
use vex_proxy_sdk::VexPlugin;
use vex_proxy_sdk::api::PluginApi;
use vex_proxy_sdk::event::OnLoginSuccess;

struct HelloPlugin;

impl VexPlugin for HelloPlugin {
    fn name(&self) -> &'static str { "hello_plugin" }
    fn version(&self) -> &'static str { "0.3.0" }

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

</details>

**Build & load:**
```bash
cargo build -p hello_plugin --release
# copy .so / .dll to plugins/, then:
curl -X POST http://127.0.0.1:8080/reload -H "x-admin-token: change-me"
```

**What plugins get today:**
- 16 core events — TCP connect, handshake, pre-login, backend lifecycle, kick/switch, status ping, reload, attack mode, health transitions, permission checks
- Hot reload by file change (`[plugins].watch = true`) with partial reload (changed plugins only)
- Plugin command registration
- Per-player typed metadata store
- Zero-copy plugin messaging via `Bytes`
- Metrics registration (`vex_plugin_<plugin>_<metric>`) with unload cleanup
- `transfer()` for backend switch without full reconnect

---

## Architecture

> Why Rust, why fast

| Feature | Detail |
|---|---|
| **Tokio async IO** | High connection density without thread explosion |
| **ArcSwap runtime snapshots** | Atomic config / protocol / backend reloads |
| **Session registry** | Safe disconnect / pause / switch via relay control channel |
| **Plugin event bus** | Per-handler timeout and panic isolation |
| **Zero-copy byte paths** | Plugin messages via `Bytes` |
| **Prometheus-first** | Structured logging + metrics for production diagnosis |

Rust gives deterministic performance and memory behavior without JVM GC pauses, with compile-time safety guarantees.

---

## Status & roadmap

| Area | Status | Notes |
|---|---|---|
| Core proxy | ✅ done | Hot reload, health checks, graceful shutdown |
| Auth + forwarding | ✅ done | Online/offline + Velocity modern forwarding |
| Anti-bot v2 | ✅ done | Reputation + adaptive penalties |
| Observability | ✅ done | Prometheus + JSON logs + Grafana |
| Plugin SDK | 🧪 alpha | `vex-proxy-sdk` 0.3.x |
| Clustering | 🧪 experimental | Redis-backed state (opt-in) |
| Docs | 🚧 in progress | Wiki pages under `docs/wiki/` |

---

<div align="center">
<sub>This repository ships English (<code>README.md</code>) and Russian (<code>README_RU.md</code>) docs.<br/>Bench numbers above are from the latest local run; historical comparisons live in <code>PLAN.md</code>.</sub>
</div>
