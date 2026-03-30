# Comparison (English)

## Feature matrix

| Category | Vex | BungeeCord | Velocity | Gate |
|---|---|---|---|---|
| Language/runtime | Rust | Java (JVM) | Java (JVM) | Go |
| Performance (10k conns) | **26 KB/conn** | 153 KB/conn | ~70–120 KB/conn | 97 KB/conn |
| Protocol support | 1.20–1.21.4 | 1.8–1.21.x | 1.8–1.21.x | 1.20–1.21.x |
| Online auth | Yes | Yes | Yes | Yes |
| Velocity forwarding | Yes | Via plugins | Native | Native |
| Native plugins | Rust SDK | Java | Java | Go |
| Hot reload | Atomic | Partial | Partial | Limited |
| Clustering | Built-in (Redis) | External | External | External |
| Anti-bot | Built-in (v2) | Plugin ecosystem | Plugin ecosystem | Basic |
| Observability | Prometheus + JSON | JMX / plugins | JMX / plugins | Prometheus |
| Maintenance | Active | Mature / stable | Active | Active |

## When to choose alternatives

### BungeeCord
Choose BungeeCord if:
- You rely on a large, legacy Java plugin ecosystem.
- You need wide compatibility with older Minecraft versions.

### Velocity
Choose Velocity if:
- You want a modern Java proxy with a huge plugin ecosystem.
- Your team prefers JVM tooling and the Velocity API.

### Gate
Choose Gate if:
- You are already deep in Go infrastructure.
- You prefer a simple proxy with smaller plugin surface.

### Vex
Choose Vex if:
- You want lowest memory usage and predictable performance.
- You need built-in clustering and anti-bot without external plugins.
- You want native Rust plugin development and hot reload.

## See also
- [Home](Home-en)
- [Benchmark](Home-en#benchmark-10000-concurrent-connections)
- [Changelog](Changelog-en)
