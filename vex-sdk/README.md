# vex-proxy-sdk

Plugin SDK for [Vex](https://github.com/pa-dej/Vex) - high-performance Minecraft proxy.

## Quick start (full working example)

### Step 1: Create project

```bash
cargo new --lib my_plugin
cd my_plugin
```

### Step 2: Configure Cargo.toml

```toml
[package]
name = "my_plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
vex-proxy-sdk = "0.1"
```

### Step 3: Write plugin (`src/lib.rs`)

```rust
use std::error::Error;
use std::sync::Arc;
use vex_proxy_sdk::prelude::*;

struct MyPlugin;

impl VexPlugin for MyPlugin {
    fn name(&self) -> &'static str { "my_plugin" }
    fn version(&self) -> &'static str { "0.1.0" }

    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
        api.logger.info("my_plugin loaded");

        api.events.on::<OnLoginSuccess, _, _>(move |event| {
            let api = api.clone();
            async move {
                api.proxy
                    .broadcast(&format!("{} joined the network!", event.player.username));
            }
        });

        Ok(())
    }

    fn on_unload(&self) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
    Box::new(MyPlugin)
}

#[unsafe(no_mangle)]
pub static VEX_SDK_VERSION: u32 = vex_proxy_sdk::VEX_SDK_VERSION;
```

### Step 4: Build and install

```bash
cargo build --release
# Windows:
copy target\release\my_plugin.dll C:\path\to\vex\plugins\
# Linux:
cp target/release/libmy_plugin.so /path/to/vex/plugins/
```

## Available events

| Event | Cancellable | Description |
| --- | --- | --- |
| `OnTcpConnect` | Yes | Fires immediately after TCP accept, before reading bytes. |
| `OnHandshake` | Yes | Fires after handshake parse with host/protocol/next state. |
| `OnPreLogin` | Yes | Fires after Login Start, before auth starts. |
| `OnLoginSuccess` | No | Fires when player session is established. |
| `OnDisconnect` | No | Fires when an established player disconnects. |
| `OnBackendConnect` | Yes | Fires before backend login starts. |
| `OnBackendReady` | No | Fires after backend login success, before relay starts. |
| `OnBackendDisconnect` | No | Fires when backend TCP drops during relay. |
| `OnBackendKick` | Yes | Fires when backend disconnects player with a message. |
| `OnBackendSwitch` | No | Fires after successful transfer to another backend. |
| `OnStatusPing` | No | Fires for status ping and allows mutable response edits. |
| `OnReload` | No | Fires after plugin/config reload is applied. |
| `OnPluginMessage` | Yes | Fires when plugin channel packet interception is enabled. |
| `OnAttackModeChange` | No | Fires when anti-bot attack mode toggles. |
| `OnBackendHealthChange` | No | Fires on backend health state transitions. |
| `OnPermissionCheck` | No | Fires when the proxy checks a permission for a player. |

## ProxiedPlayer API

- `disconnect(reason)` - disconnects player from proxy session.
- `send_plugin_message(channel, data)` - sends a plugin channel payload.
- `transfer(backend)` - switch player backend without reconnect (best effort).
- `get_meta/set_meta/remove_meta/has_meta` - per-player typed metadata.
- `current_backend()` - current backend view from the proxy session.
- `latency_ms()` - current player latency as seen by the proxy.

## transfer() - switching players between servers

`transfer()` attempts a live backend switch with no client reconnect. Internally Vex pauses relay, connects and logs into target backend, then swaps relay streams and resumes traffic.

```rust
api.events.on::<OnBackendKick, _, _>(move |event| {
    let api = api.clone();
    async move {
        if let Some(target) = api.proxy.get_backends().into_iter().find(|b| b.is_healthy()) {
            let _ = event.player.transfer(target);
            event.cancel("redirecting");
        }
    }
});
```

## Plugin metrics

Enable `metrics` feature when registering Prometheus plugin metrics.

```toml
vex-proxy-sdk = { version = "0.1", features = ["metrics"] }
```

```rust
let counter = api.metrics.register_counter(
    "players_greeted_total",
    "Number of greeted players",
    &["source"],
)?;
counter.inc(&["login"]);
```

## Versioning and ABI

- `vex-proxy-sdk` exports `VEX_SDK_VERSION`.
- Vex proxy checks plugin ABI version during dynamic library load.
- On mismatch, plugin is rejected and proxy keeps running.
