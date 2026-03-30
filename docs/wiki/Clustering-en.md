# Clustering (English)

Clustering allows multiple Vex nodes to share reputation, rate limits, and player registry through Redis.

## Architecture (ASCII)

```
         +------------------+
         |     Clients      |
         +--------+---------+
                  |
        +---------+----------+
        |  Load Balancer     |
        +----+---------+-----+
             |         |
     +-------+--+   +--+-------+
     | Vex A   |   | Vex B     |
     | node_id |   | node_id   |
     +----+----+   +----+------+
          |             |
          +------+-+----+
                 | |
             +---+-v---+
             |  Redis  |
             +---+-----+
                 |
        +--------+--------+
        |   Backends      |
        +-----------------+
```

## When to use clustering
- You run multiple proxy nodes behind a load balancer.
- You want shared anti-bot reputation and global rate limiting.
- You need a global player list across nodes.

## Redis setup

Redis should be reachable by all nodes. Example:

```bash
docker run -d --name vex-redis -p 6379:6379 redis:7
```

## Node configuration

```toml
[cluster]
enabled = true
node_id = "edge-1"
heartbeat_interval_secs = 5
heartbeat_ttl_secs = 15
allow_degraded = true

[cluster.redis]
url = "redis://127.0.0.1:6379"
connect_timeout_ms = 1000
command_timeout_ms = 500
circuit_breaker_errors = 5
circuit_breaker_reset_ms = 5000
pubsub_channel = "vex.cluster"
```

## Shared reputation
- Each node writes IP scores to Redis.
- Reads merge local cache + Redis values.
- Decay and block escalation remain local but use shared score.

## Global rate limiting
- Token buckets are stored as Redis atomic counters.
- Bucket refill logic runs per node, but counters are global.
- Prevents a single IP from flooding all nodes.

## Pub/sub events
- Attack mode changes propagate to all nodes.
- Reputation deltas are broadcast to reduce stale scores.
- Broadcast messages can be pushed to all nodes.

## Degraded mode
When Redis is unavailable:
- Nodes continue to accept connections if `allow_degraded = true`.
- Local reputation cache keeps working without cross-node sync.
- Circuit breaker backs off Redis attempts until it recovers.

## Docker Compose example (2-node cluster)

```yaml
version: "3.9"
services:
  redis:
    image: redis:7
    ports:
      - "6379:6379"

  vex-a:
    image: vex:latest
    ports:
      - "25577:25577"
    volumes:
      - ./vex-a.toml:/app/vex.toml
    depends_on:
      - redis

  vex-b:
    image: vex:latest
    ports:
      - "25578:25577"
    volumes:
      - ./vex-b.toml:/app/vex.toml
    depends_on:
      - redis
```

## See also
- [Anti-Bot](Anti-Bot-en)
- [Configuration Reference](Configuration-en)
- [Observability](Observability-en)
- [Home](Home-en)
