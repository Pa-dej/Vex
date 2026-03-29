# Vex — Development Plan

High-performance Minecraft Java proxy written in Rust.
Benchmarked at 10,000 concurrent connections with 100% success rate,
26 KB RAM per connection vs 97 KB (Gate/Go) and 153 KB (BungeeCord/JVM).

---

## Current state (released)

| Version | Status | What it covers |
|---------|--------|----------------|
| v1      | ✓ done | Core proxy, offline auth, hot reload, health checks, metrics |
| v1.1    | ✓ done | Velocity Modern Forwarding, online auth, AES/CFB8, circuit breaker |
| v1.2    | ✓ done | Global cap, per-IP/subnet token buckets, early frame rejection |
| Г       | ✓ done | Structured logging, Grafana dashboard, Docker Compose stack |
| v2      | ✓ done | Reputation cache, adaptive penalties, attack analytics, attack mode |

---

## Protocol version support plan

Minecraft releases a major version roughly every 6–12 months.
Vex maintains a pinned protocol table in `config/protocol_ids.toml`.

### Supported range: 1.20 – current

| MC version | Protocol ID | Support status |
|------------|-------------|----------------|
| 1.20       | 763         | ✓ supported    |
| 1.20.2     | 764         | ✓ supported    |
| 1.20.3/4   | 765         | ✓ supported    |
| 1.21       | 766         | ✓ supported    |
| 1.21.1     | 767         | ✓ supported    |
| 1.21.2/3   | 768         | ✓ supported    |
| 1.21.4     | 769 → 774   | ✓ supported    |
| 1.21.5+    | TBD         | added on release |
| 1.22–26.x  | TBD         | added on release |

### Protocol update policy

1. When Mojang releases a new version — update `protocol_ids.toml` within 48h of stable release.
2. If login pipeline changes (new packet fields, encryption changes) — patch `mc.rs` and `server.rs`.
3. Snapshot/RC versions — listed in toml with `snapshot = true` flag, opt-in via config.
4. Versions older than 1.20 — not supported. Clear disconnect message: "This proxy requires 1.20 or newer."
5. Each protocol update gets a regression test added to the smoke suite.

### Configuration phase changes

Minecraft 1.20.2 introduced the Configuration state between Login and Play.
Already implemented. Future versions may add new configuration packets —
handle by read-and-discard for unknown packet IDs in configuration loop.

---

## v3 — Plugin API

### Goal

Allow operators to extend Vex behavior without forking the codebase.
Plugins run in-process as compiled Rust dynamic libraries (`.dll` / `.so` / `.dylib`).

### Why Rust for plugins

- Same performance as core — zero overhead FFI boundary via stable ABI
- Memory safety enforced by compiler — a plugin cannot corrupt proxy state
- Natural complexity filter: Rust requires understanding ownership and async,
  which correlates with the engineering quality needed to write correct proxy plugins
- No GC pauses introduced by plugin code — consistent latency guarantees

There is no artificial barrier. The barrier is Rust itself.
Good documentation and examples lower the learning curve without lowering the quality bar.

### Plugin API surface (planned)

```rust
// Plugin declares itself via this trait
pub trait VexPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn on_load(&self, api: &PluginApi);
    fn on_unload(&self);
}

// API available to plugins
pub struct PluginApi {
    // Event hooks
    pub events: EventBus,
    // Read-only access to runtime state
    pub backends: BackendView,
    // Metrics registration
    pub metrics: MetricsRegistry,
    // Logging
    pub logger: PluginLogger,
}
```

### Event hooks (planned)

| Event | When | Can cancel |
|-------|------|------------|
| `OnHandshake` | After handshake parsed | yes |
| `OnLoginStart` | After Login Start received | yes |
| `OnLoginSuccess` | After backend Login Success | no |
| `OnPlayerDisconnect` | On any disconnect | no |
| `OnBackendHealthChange` | Backend state transition | no |
| `OnReload` | After hot reload applied | no |
| `OnAttackModeChange` | Attack mode on/off | no |

### Plugin loading

```toml
# vex.toml
[plugins]
enabled = true
dir = "plugins/"
# plugins are .dll on Windows, .so on Linux, .dylib on macOS
```

Plugins are loaded at startup and on `POST /reload`.
A plugin that panics is unloaded and logged — it does not crash the proxy.

### Plugin isolation

- Plugins get read-only views of state — they cannot directly mutate routing table
- Plugins communicate changes via events and return values, not shared mutable state
- Each plugin runs in its own tokio task context
- Plugin API is versioned — breaking changes increment API major version

### Development timeline

| Milestone | Description |
|-----------|-------------|
| v3.0-alpha | Stable ABI definition, EventBus, OnHandshake + OnLoginStart hooks |
| v3.0-beta  | Full event set, metrics registration, plugin hot-reload |
| v3.0       | Plugin SDK crate published to crates.io, example plugins, docs |
| v3.1       | Plugin marketplace / registry (community) |

### Example plugin

```rust
// plugins/whitelist/src/lib.rs
use vex_sdk::{VexPlugin, PluginApi, Event, HandshakeEvent};

pub struct WhitelistPlugin {
    allowed: Vec<String>,
}

impl VexPlugin for WhitelistPlugin {
    fn name(&self) -> &str { "whitelist" }
    fn version(&self) -> &str { "1.0.0" }

    fn on_load(&self, api: &PluginApi) {
        api.events.on_handshake(|event: &mut HandshakeEvent| {
            if !self.allowed.contains(&event.username) {
                event.cancel("You are not whitelisted.");
            }
        });
    }

    fn on_unload(&self) {}
}
```

---

## v4 — Clustering (future)

Multiple Vex instances behind a shared state layer.
Reputation cache and rate limits synchronized across nodes via Redis or custom UDP gossip.
Not in scope until v3 is stable.

---

## Maintenance policy

- Security patches: released within 24h of discovery
- Protocol updates: within 48h of Minecraft stable release
- Breaking config changes: deprecated for one major version before removal
- Minimum supported Rust version: current stable - 2 releases

---

## What is explicitly out of scope

- Bedrock Edition support
- Built-in web panel (use Grafana dashboard)
- Per-player inventory or world management (that is the backend's job)
- Plugin scripting in languages other than Rust (v3 only, no Lua/JS/Python runtime)