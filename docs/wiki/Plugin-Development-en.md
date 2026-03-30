# Plugin Development (English)

This tutorial walks you through building a real plugin using `vex-proxy-sdk`.

## Step 1: Create a Rust project

```bash
cargo new whitelist_plugin --lib
cd whitelist_plugin
```

## Step 2: Configure `Cargo.toml` as a `cdylib`

```toml
[package]
name = "whitelist_plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
vex-proxy-sdk = "3.0"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
```

## Step 3: Implement `VexPlugin`

## Step 4: Register event handlers

## Step 5: Build the plugin

```bash
cargo build --release
```

The output library is in `target/release/`:
- Windows: `whitelist_plugin.dll`
- Linux: `libwhitelist_plugin.so`
- macOS: `libwhitelist_plugin.dylib`

## Step 6: Deploy

Copy the library to `plugins/` next to `vex.toml` and reload:

```bash
curl -X POST http://127.0.0.1:8080/reload -H "x-admin-token: change-me"
```

## Full working example

This plugin:
- Loads `config.yml` with the allowed usernames
- Cancels `OnPreLogin` for non-whitelisted users
- Sends a welcome message on login
- Broadcasts every 60 seconds
- Registers `/whitelist` command
- Exposes a Prometheus counter

### config.yml (placed in plugin data dir)

```yaml
allowed:
  - Alice
  - Bob
welcome: "Welcome to the server!"
broadcast: "Remember to be kind to each other!"
```

### src/lib.rs

```rust
use std::error::Error;
use std::sync::Arc;
use serde::Deserialize;
use vex_proxy_sdk::VexPlugin;
use vex_proxy_sdk::api::{PluginApi, CommandContext};
use vex_proxy_sdk::event::{OnPreLogin, OnLoginSuccess};
use vex_proxy_sdk::metrics::Counter;

#[derive(Clone, Debug, Deserialize)]
struct WhitelistConfig {
    allowed: Vec<String>,
    welcome: String,
    broadcast: String,
}

const DEFAULT_CONFIG: &str = r#"
allowed:
  - Alice
  - Bob
welcome: "Welcome to the server!"
broadcast: "Remember to be kind to each other!"
"#;

struct WhitelistPlugin;

impl VexPlugin for WhitelistPlugin {
    fn name(&self) -> &'static str { "whitelist_plugin" }
    fn version(&self) -> &'static str { "0.1.0" }

    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
        api.config.save_default("config.yml", DEFAULT_CONFIG)?;
        let cfg: WhitelistConfig = api.config.load_yaml("config.yml")?;
        let cfg = Arc::new(cfg);

        let denied: Counter = api.metrics.counter(
            "whitelist_denied_total",
            "Denied connections by whitelist plugin"
        )?;

        // Pre-login whitelist check
        let cfg_pre = cfg.clone();
        let denied_pre = denied.clone();
        api.events.on::<OnPreLogin, _, _>(move |event| {
            let cfg_pre = cfg_pre.clone();
            let denied_pre = denied_pre.clone();
            async move {
                if !cfg_pre.allowed.iter().any(|name| name.eq_ignore_ascii_case(&event.username)) {
                    denied_pre.inc();
                    event.deny("You are not whitelisted.");
                }
            }
        });

        // Welcome message after successful login
        let cfg_login = cfg.clone();
        api.events.on::<OnLoginSuccess, _, _>(move |event| {
            let cfg_login = cfg_login.clone();
            async move {
                event.player.send_message(&cfg_login.welcome);
            }
        });

        // Scheduled broadcast every 60s
        let proxy = api.proxy.clone();
        let cfg_broadcast = cfg.clone();
        api.scheduler.run_timer(60_000, move || {
            let proxy = proxy.clone();
            let msg = cfg_broadcast.broadcast.clone();
            async move {
                proxy.broadcast(&msg);
            }
        });

        // /whitelist command
        let cfg_cmd = cfg.clone();
        api.commands.register(
            "whitelist",
            "vex.whitelist",
            move |ctx: CommandContext| {
                let cfg_cmd = cfg_cmd.clone();
                async move {
                    let list = cfg_cmd.allowed.join(", ");
                    ctx.reply(&format!("Whitelisted: {}", list));
                }
            }
        );

        api.logger.info("whitelist_plugin loaded");
        Ok(())
    }

    fn on_unload(&self) {}
}

#[no_mangle]
pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
    Box::new(WhitelistPlugin)
}
```

## See also
- [Plugin API Reference](Plugin-API-Reference-en)
- [Configuration Reference](Configuration-en)
- [Getting Started](Getting-Started-en)
- [Home](Home-en)
