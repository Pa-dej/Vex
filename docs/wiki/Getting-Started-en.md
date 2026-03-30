# Getting Started (English)

This guide gets Vex running in ~5 minutes with a single backend.

## Prerequisites
- Rust (stable, 1.75+)
- Java 17+ server (Paper/Spigot/Vanilla) for backend
- Redis (optional, only for clustering / shared reputation)

## Build from source

```bash
git clone https://github.com/your-org/vex.git
cd vex
cargo build --release
```

The proxy binary will be in `target/release/Vex` (or `Vex.exe` on Windows).

## Minimal config (vex.toml)

```toml
[listener]
bind = "0.0.0.0:25577"
max_packet_size = 2097152
read_timeout_ms = 15000
write_timeout_ms = 15000

[auth]
mode = "offline"

[forwarding.velocity]
enabled = true
secret = "change-me-velocity"

[routing]
strategy = "least_connections"
allow_degraded = true
health_check_enabled = true

[[routing.backends]]
name = "paper-1"
address = "127.0.0.1:25565"
weight = 100
max_connections = 2000

[admin]
bind = "127.0.0.1:8080"
auth_token = "change-me"
```

## Start a Paper backend

Run a Paper server locally (example):

```bash
java -Xms1G -Xmx1G -jar paper.jar --nogui
```

Ensure it listens on `127.0.0.1:25565` to match the config above.

## Run Vex

```bash
./target/release/Vex
```

Connect with a Minecraft client to `localhost:25577`.

## Verify with health check

```bash
curl http://127.0.0.1:8080/healthz -H "x-admin-token: change-me"
```

Expected response:

```text
ok
```

## Common first-run issues
- **Backend not reachable**: check `routing.backends[].address`, firewall, and that the server is listening.
- **Velocity secret mismatch**: ensure backend uses the same `forwarding.velocity.secret`.
- **Online auth fails**: set `[auth].mode = "offline"` while testing locally.
- **Windows path issues**: place plugins in `plugins/` beside `vex.toml`.
- **Port already in use**: change `[listener].bind` or `[admin].bind`.

## See also
- [Configuration Reference](Configuration-en.md)
- [Anti-Bot](Anti-Bot-en.md)
- [Observability](Observability-en.md)
- [Home](Home-en.md)
