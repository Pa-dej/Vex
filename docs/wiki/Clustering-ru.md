# Кластеризация (Русский)

Кластеризация позволяет нескольким нодам Vex делить репутацию, лимиты и реестр игроков через Redis.

## Архитектура (ASCII)

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

## Когда нужна кластеризация
- Несколько нод прокси за балансировщиком.
- Нужна общая антибот‑репутация и глобальные лимиты.
- Нужен глобальный список игроков по всем нодам.

## Настройка Redis

Redis должен быть доступен всем нодам:

```bash
docker run -d --name vex-redis -p 6379:6379 redis:7
```

## Конфигурация ноды

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

## Общая репутация
- Каждая нода пишет score IP в Redis.
- Чтение объединяет локальный кеш и Redis.
- Декей и блоки локальные, но score общий.

## Глобальный rate limiting
- Токен‑бакеты хранятся как Redis atomic counters.
- Рефилл выполняется на каждой ноде, но счётчики общие.
- Один IP не может загрузить все ноды сразу.

## Pub/sub события
- Attack mode синхронизируется между нодами.
- Дельты репутации пушатся для уменьшения устаревания.
- Возможен broadcast на все ноды.

## Degraded режим
Если Redis недоступен:
- Ноды продолжают принимать соединения при `allow_degraded = true`.
- Локальный кеш репутации работает без синхронизации.
- Circuit breaker снижает частоту попыток до восстановления.

## Docker Compose пример (2 ноды)

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
- [Антибот](Anti-Bot-ru.md)
- [Конфигурация](Configuration-ru.md)
- [Наблюдаемость](Observability-ru.md)
- [Home](Home-ru.md)
