# Anti-Bot (English)

Vex ships a layered anti-bot system designed for high-load Minecraft proxies.

## 5-layer flow (ASCII)

```
Client TCP connect
      |
      v
[1] Global connection cap
      |
      v
[2] Per-IP /24 token buckets
      |
      v
[3] Early frame validation
      |
      v
[4] Reputation score (0-100)
      |
      v
[5] Adaptive delay / block
      |
      v
Login / backend routing
```

## Reputation score
- New IPs start at `neutral_score` (default 50).
- Score decreases for malformed frames, timeouts, or flooding.
- Score increases for clean logins and stable sessions.
- Decay moves scores toward neutral every 60s.
- Delays: 25–49 → 200ms, 10–24 → 500ms.
- Blocks escalate: 30s → 2m → 10m.

## Tuning guide

**For smaller communities (≤2k concurrent):**
- `per_ip_rate_per_sec = 5`
- `per_subnet_rate_per_sec = 100`
- `global_conn_cap = 8000`
- Keep default delays

**For medium servers (2k–10k):**
- `per_ip_rate_per_sec = 10`
- `per_subnet_rate_per_sec = 200`
- `global_conn_cap = 25000`

**For large networks (10k+):**
- `per_ip_rate_per_sec = 15`
- `per_subnet_rate_per_sec = 400`
- `global_conn_cap = 50000`
- Consider higher `attack_mode_threshold_rps`

## Attack mode
Attack mode activates when the connection rate crosses the configured threshold.

When active:
- Token bucket capacities are halved.
- Early frame rejection becomes more aggressive.
- Reputation penalties apply faster.

## Cross-node reputation sync
In v4 clustering mode:
- Reputation deltas are published over Redis.
- Nodes pull shared scores to reduce evasion between nodes.

## Recommended config snippet

```toml
[anti_bot]
enabled = true
global_conn_cap = 25000
per_ip_rate_per_sec = 10
per_subnet_rate_per_sec = 200
early_reject = true
attack_mode_enabled = true
attack_mode_threshold_rps = 3000
attack_mode_cooldown_secs = 60

[reputation]
neutral_score = 50
decay_interval_secs = 60
delay_score_25_49_ms = 200
delay_score_10_24_ms = 500
block_duration_1_secs = 30
block_duration_2_secs = 120
block_duration_3_secs = 600
```

## See also
- [Configuration Reference](Configuration-en.md)
- [Clustering](Clustering-en.md)
- [Observability](Observability-en.md)
- [Home](Home-en.md)
