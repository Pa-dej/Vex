# Plugin API Reference (English)

This page documents the public surface of `vex-proxy-sdk` v3.

## Events (17)

| Event | When fired | Fields | Cancellable? | Example handler |
|---|---|---|---|---|
| `OnHandshake` | Client handshake packet received. | `protocol`, `server_address`, `intent` | Yes (deny) | `event.deny("Blocked");` |
| `OnPreLogin` | Before auth finishes. | `username`, `address` | Yes (deny) | `event.deny("Not whitelisted");` |
| `OnLoginSuccess` | After successful login. | `player` | No | `event.player.send_message("hi");` |
| `OnDisconnect` | Player disconnects. | `player`, `reason` | No | `api.logger.info(...);` |
| `OnBackendConnect` | Before connecting to backend. | `player`, `backend` | Yes (cancel/redirect) | `event.set_backend("hub");` |
| `OnBackendReady` | Backend login finished. | `player`, `backend` | No | `api.logger.info(...);` |
| `OnBackendDisconnect` | Backend connection lost. | `player`, `backend`, `reason` | No | `api.logger.warn(...);` |
| `OnBackendKick` | Backend sends kick. | `player`, `backend`, `message` | Yes (suppress/redirect) | `event.redirect("lobby");` |
| `OnBackendSwitch` | Player switches backend. | `player`, `from`, `to` | No | `api.logger.info(...);` |
| `OnStatusPing` | Status ping/MOTD request. | `address`, `response` | Yes (override response) | `event.response.motd = "...";` |
| `OnReload` | Proxy reload triggered. | `source` | No | `api.logger.info("reload");` |
| `OnPluginMessage` | Plugin message intercepted. | `player`, `channel`, `data` | Yes (drop) | `event.cancel();` |
| `OnAttackModeChange` | Attack mode toggled. | `enabled`, `rps` | No | `api.logger.warn(...);` |
| `OnBackendHealthChange` | Health status changes. | `backend`, `healthy` | No | `api.logger.info(...);` |
| `OnPermissionCheck` | Command permission check. | `player`, `permission`, `allowed` | Yes (override) | `event.allow();` |
| `OnTcpConnect` | TCP connect accepted. | `address`, `trace_id` | Yes (drop) | `event.deny("busy");` |

### Example: register an event handler

```rust
api.events.on::<OnPreLogin, _, _>(move |event| async move {
    if event.username == "NotAllowed" {
        event.deny("You are not allowed.");
    }
});
```

## ProxiedPlayer methods

| Method signature | Description | Example |
|---|---|---|
| `username(&self) -> &str` | Player name. | `player.username()` |
| `uuid(&self) -> Uuid` | Player UUID. | `player.uuid()` |
| `address(&self) -> SocketAddr` | Remote address. | `player.address()` |
| `send_message(&self, msg: &str)` | Send chat message. | `player.send_message("Hi");` |
| `send_title(&self, title: &str, subtitle: &str, fade_in: u32, stay: u32, fade_out: u32)` | Title + timings. | `player.send_title("Hi","",10,60,10);` |
| `send_actionbar(&self, msg: &str)` | Actionbar text. | `player.send_actionbar("Ready");` |
| `kick(&self, msg: &str)` | Disconnect player. | `player.kick("Bye");` |
| `transfer(&self, backend: &str)` | Switch backend without disconnect. | `player.transfer("hub");` |
| `set_tab_list(&self, header: &str, footer: &str)` | Set tab list header/footer. | `player.set_tab_list("H","F");` |
| `metadata(&self) -> PlayerMetadata` | Access per-player metadata. | `player.metadata().set("key", 1);` |

## ProxyHandle methods

| Method signature | Description | Example |
|---|---|---|
| `broadcast(&self, msg: &str)` | Broadcast to all players on this node. | `api.proxy.broadcast("hi");` |
| `get_player(&self, name: &str) -> Option<ProxiedPlayer>` | Find player by name. | `api.proxy.get_player("Alice");` |
| `online_count(&self) -> u32` | Online count (local). | `api.proxy.online_count()` |
| `get_all_players(&self) -> Vec<PlayerInfo>` | All players in cluster. | `api.proxy.get_all_players()` |
| `send_plugin_message(&self, channel: &str, data: Bytes)` | Send plugin message. | `api.proxy.send_plugin_message("BungeeCord", data);` |
| `reload(&self)` | Trigger reload. | `api.proxy.reload()` |
| `shutdown(&self)` | Trigger shutdown. | `api.proxy.shutdown()` |

## Scheduler API

| Method | Description | Example |
|---|---|---|
| `run_next_tick(f)` | Run once on next tick. | `api.scheduler.run_next_tick(|| async move { ... });` |
| `run_later(delay_ms, f)` | Run once after delay. | `api.scheduler.run_later(5000, || async move { ... });` |
| `run_timer(interval_ms, f)` | Run repeatedly. | `api.scheduler.run_timer(60000, || async move { ... });` |

## Config API

| Method | Description | Example |
|---|---|---|
| `save_default(path, contents)` | Create config file if missing. | `api.config.save_default("config.yml", DEFAULT);` |
| `load_yaml<T>(path)` | Load YAML into a struct. | `let cfg: Cfg = api.config.load_yaml("config.yml")?;` |
| `data_dir()` | Plugin data directory path. | `api.config.data_dir()` |

## Metrics API

| Method | Description | Example |
|---|---|---|
| `counter(name, help)` | Create a counter. | `api.metrics.counter("x_total", "help")?;` |
| `gauge(name, help)` | Create a gauge. | `api.metrics.gauge("x", "help")?;` |
| `histogram(name, help, buckets)` | Create histogram. | `api.metrics.histogram("x", "help", vec![...])?;` |

## Chat, title, actionbar, tab list

| Method | Description |
|---|---|
| `send_message` | Chat message to player. |
| `send_title` | Title and subtitle. |
| `send_actionbar` | Actionbar text. |
| `set_tab_list` | Tab header/footer. |

## See also
- [Plugin Development](Plugin-Development-en)
- [Configuration Reference](Configuration-en)
- [Home](Home-en)
