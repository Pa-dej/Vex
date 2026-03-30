# Конфигурация (Русский)

Здесь перечислены все поля `vex.toml`. Примеры — валидный TOML.

## [listener]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `bind` (string) | `"0.0.0.0:25577"` | Адрес для входящих подключений. | `bind = "0.0.0.0:25577"` |
| `max_packet_size` (int) | `2097152` | Жёсткий лимит размера фрейма (байты). | `max_packet_size = 2097152` |
| `read_timeout_ms` (int) | `15000` | Таймаут чтения сокета (мс). | `read_timeout_ms = 15000` |
| `write_timeout_ms` (int) | `15000` | Таймаут записи сокета (мс). | `write_timeout_ms = 15000` |

Пример:

```toml
[listener]
bind = "0.0.0.0:25577"
max_packet_size = 2097152
read_timeout_ms = 15000
write_timeout_ms = 15000
```

## [auth]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `mode` (string) | `"auto"` | `offline`, `online` или `auto`. | `mode = "online"` |
| `online_timeout_ms` (int) | `5000` | Таймаут проверки сессии (мс). | `online_timeout_ms = 5000` |
| `session_server` (string) | `"https://sessionserver.mojang.com"` | URL сервера сессий Mojang. | `session_server = "https://sessionserver.mojang.com"` |

Пример:

```toml
[auth]
mode = "auto"
online_timeout_ms = 5000
session_server = "https://sessionserver.mojang.com"
```

## [forwarding.velocity]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `enabled` (bool) | `false` | Включить Velocity modern forwarding. | `enabled = true` |
| `secret` (string) | `"change-me"` | HMAC‑секрет, общий с бэкендом. | `secret = "change-me-velocity"` |

Пример:

```toml
[forwarding.velocity]
enabled = true
secret = "change-me-velocity"
```

## [routing]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `strategy` (string) | `"least_connections"` | Алгоритм выбора бэкенда. | `strategy = "least_connections"` |
| `allow_degraded` (bool) | `true` | Работать, даже если все бэкенды unhealthy. | `allow_degraded = true` |
| `health_check_enabled` (bool) | `true` | Включить активные проверки. | `health_check_enabled = true` |
| `connect_timeout_ms` (int) | `3000` | Таймаут подключения к бэкенду (мс). | `connect_timeout_ms = 3000` |
| `retry_on_fail` (bool) | `true` | Переходить на другой бэкенд при ошибке. | `retry_on_fail = true` |

### [[routing.backends]]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `name` (string) | _(обязательно)_ | Имя бэкенда в логах/плагинах. | `name = "paper-1"` |
| `address` (string) | _(обязательно)_ | `host:port` бэкенд‑сервера. | `address = "127.0.0.1:25565"` |
| `weight` (int) | `100` | Вес в балансировке. | `weight = 100` |
| `max_connections` (int) | `2000` | Лимит подключений на бэкенд. | `max_connections = 2000` |
| `force_online_mode` (bool) | `false` | Принудительный online‑auth для бэкенда. | `force_online_mode = false` |

Пример:

```toml
[routing]
strategy = "least_connections"
allow_degraded = true
health_check_enabled = true
connect_timeout_ms = 3000
retry_on_fail = true

[[routing.backends]]
name = "paper-1"
address = "127.0.0.1:25565"
weight = 100
max_connections = 2000
force_online_mode = false
```

## [limits]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `max_connections` (int) | `20000` | Глобальный лимит активных соединений. | `max_connections = 20000` |
| `max_connections_per_ip` (int) | `50` | Лимит активных соединений на IP. | `max_connections_per_ip = 50` |
| `handshake_timeout_ms` (int) | `3000` | Таймаут завершения handshake. | `handshake_timeout_ms = 3000` |
| `login_timeout_ms` (int) | `8000` | Таймаут завершения логина. | `login_timeout_ms = 8000` |
| `idle_timeout_ms` (int) | `30000` | Разрыв при простое. | `idle_timeout_ms = 30000` |

Пример:

```toml
[limits]
max_connections = 20000
max_connections_per_ip = 50
handshake_timeout_ms = 3000
login_timeout_ms = 8000
idle_timeout_ms = 30000
```

## [anti_bot]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `enabled` (bool) | `true` | Главный переключатель антибота. | `enabled = true` |
| `global_conn_cap` (int) | `25000` | Глобальный лимит до репутации. | `global_conn_cap = 25000` |
| `per_ip_rate_per_sec` (int) | `10` | Пополнение токенов на IP. | `per_ip_rate_per_sec = 10` |
| `per_subnet_rate_per_sec` (int) | `200` | Пополнение токенов на /24. | `per_subnet_rate_per_sec = 200` |
| `early_reject` (bool) | `true` | Ранний дроп кривых фреймов. | `early_reject = true` |
| `attack_mode_enabled` (bool) | `true` | Авто‑включение attack mode. | `attack_mode_enabled = true` |
| `attack_mode_threshold_rps` (int) | `3000` | Порог RPS для attack mode. | `attack_mode_threshold_rps = 3000` |
| `attack_mode_cooldown_secs` (int) | `60` | Время спокойствия до выключения. | `attack_mode_cooldown_secs = 60` |

Пример:

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
```

## [reputation]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `enabled` (bool) | `true` | Включить репутационный скоринг. | `enabled = true` |
| `neutral_score` (int) | `50` | Стартовый score для новых IP. | `neutral_score = 50` |
| `min_score` (int) | `0` | Нижняя граница score. | `min_score = 0` |
| `max_score` (int) | `100` | Верхняя граница score. | `max_score = 100` |
| `decay_interval_secs` (int) | `60` | Интервал затухания к нейтрали. | `decay_interval_secs = 60` |
| `decay_step` (int) | `1` | Шаг изменения к нейтрали. | `decay_step = 1` |
| `delay_score_25_49_ms` (int) | `200` | Задержка для score 25–49. | `delay_score_25_49_ms = 200` |
| `delay_score_10_24_ms` (int) | `500` | Задержка для score 10–24. | `delay_score_10_24_ms = 500` |
| `block_duration_1_secs` (int) | `30` | Длительность первого блока. | `block_duration_1_secs = 30` |
| `block_duration_2_secs` (int) | `120` | Длительность второго блока. | `block_duration_2_secs = 120` |
| `block_duration_3_secs` (int) | `600` | Длительность третьего блока. | `block_duration_3_secs = 600` |

Пример:

```toml
[reputation]
enabled = true
neutral_score = 50
min_score = 0
max_score = 100
decay_interval_secs = 60
decay_step = 1
delay_score_25_49_ms = 200
delay_score_10_24_ms = 500
block_duration_1_secs = 30
block_duration_2_secs = 120
block_duration_3_secs = 600
```

## [health]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `interval_ms` (int) | `1500` | Интервал между проверками. | `interval_ms = 1500` |
| `status_timeout_ms` (int) | `1000` | Таймаут status ping. | `status_timeout_ms = 1000` |
| `tcp_timeout_ms` (int) | `800` | Таймаут TCP fallback. | `tcp_timeout_ms = 800` |
| `unhealthy_threshold` (int) | `3` | Ошибок до unhealthy. | `unhealthy_threshold = 3` |
| `healthy_threshold` (int) | `2` | Успехов до healthy. | `healthy_threshold = 2` |

Пример:

```toml
[health]
interval_ms = 1500
status_timeout_ms = 1000
tcp_timeout_ms = 800
unhealthy_threshold = 3
healthy_threshold = 2
```

## [observability]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `log_level` (string) | `"info"` | Уровень логов. | `log_level = "info"` |
| `log_format` (string) | `"pretty"` | `pretty` или `json`. | `log_format = "json"` |
| `metrics_enabled` (bool) | `true` | Экспорт Prometheus‑метрик. | `metrics_enabled = true` |
| `metrics_bind` (string) | `"0.0.0.0:9100"` | Адрес HTTP для метрик. | `metrics_bind = "0.0.0.0:9100"` |
| `metrics_path` (string) | `"/metrics"` | Путь HTTP для метрик. | `metrics_path = "/metrics"` |

Пример:

```toml
[observability]
log_level = "info"
log_format = "json"
metrics_enabled = true
metrics_bind = "0.0.0.0:9100"
metrics_path = "/metrics"
```

## [admin]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `bind` (string) | `"127.0.0.1:8080"` | Адрес Admin API. | `bind = "127.0.0.1:8080"` |
| `auth_token` (string) | `"change-me"` | Токен для `x-admin-token`. | `auth_token = "change-me"` |
| `allow_reload` (bool) | `true` | Разрешить POST `/reload`. | `allow_reload = true` |
| `allow_shutdown` (bool) | `true` | Разрешить POST `/shutdown`. | `allow_shutdown = true` |

Пример:

```toml
[admin]
bind = "127.0.0.1:8080"
auth_token = "change-me"
allow_reload = true
allow_shutdown = true
```

## [shutdown]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `drain_seconds` (int) | `10` | Время drain до принудительного disconnect. | `drain_seconds = 10` |
| `disconnect_message` (string) | `"Proxy shutting down"` | Сообщение при остановке. | `disconnect_message = "Proxy restarting"` |

Пример:

```toml
[shutdown]
drain_seconds = 10
disconnect_message = "Proxy shutting down"
```

## [protocol_map]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `path` (string) | `"config/protocol_map.toml"` | Файл карты протоколов. | `path = "config/protocol_map.toml"` |

Пример:

```toml
[protocol_map]
path = "config/protocol_map.toml"
```

## [plugins]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `enabled` (bool) | `true` | Включить хост плагинов. | `enabled = true` |
| `dir` (string) | `"plugins"` | Директория плагинов. | `dir = "plugins"` |
| `event_handler_timeout_ms` (int) | `500` | Максимум времени обработчика. | `event_handler_timeout_ms = 500` |
| `intercept_plugin_messages` (bool) | `false` | Перехват plugin‑сообщений. | `intercept_plugin_messages = true` |
| `watch` (bool) | `true` | Watcher файлов плагинов. | `watch = true` |
| `watch_debounce_ms` (int) | `250` | Debounce для reload. | `watch_debounce_ms = 250` |

Пример:

```toml
[plugins]
enabled = true
dir = "plugins"
event_handler_timeout_ms = 500
intercept_plugin_messages = false
watch = true
watch_debounce_ms = 250
```

## [status]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `motd` (string) | `"Vex Proxy"` | MOTD по умолчанию. | `motd = "Vex Proxy"` |
| `max_players` (int) | `1000` | Отображаемый max игроков. | `max_players = 1000` |
| `show_real_online` (bool) | `true` | Показывать реальный online. | `show_real_online = true` |
| `sample_players` (array) | `[]` | Sample players в статусе. | `sample_players = ["Vex", "Proxy"]` |

Пример:

```toml
[status]
motd = "Vex Proxy"
max_players = 1000
show_real_online = true
sample_players = ["Vex", "Proxy"]
```

## [cluster]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `enabled` (bool) | `false` | Включить кластеризацию. | `enabled = true` |
| `node_id` (string) | `"node-1"` | Уникальный ID ноды. | `node_id = "edge-1"` |
| `heartbeat_interval_secs` (int) | `5` | Интервал heartbeat. | `heartbeat_interval_secs = 5` |
| `heartbeat_ttl_secs` (int) | `15` | TTL записи ноды. | `heartbeat_ttl_secs = 15` |
| `allow_degraded` (bool) | `true` | Работать без Redis. | `allow_degraded = true` |

Пример:

```toml
[cluster]
enabled = true
node_id = "edge-1"
heartbeat_interval_secs = 5
heartbeat_ttl_secs = 15
allow_degraded = true
```

## [cluster.redis]

| Поле (тип) | Default | Описание | Пример |
|---|---|---|---|
| `url` (string) | `"redis://127.0.0.1:6379"` | URL подключения к Redis. | `url = "redis://127.0.0.1:6379"` |
| `connect_timeout_ms` (int) | `1000` | Таймаут первичного подключения. | `connect_timeout_ms = 1000` |
| `command_timeout_ms` (int) | `500` | Таймаут команд Redis. | `command_timeout_ms = 500` |
| `circuit_breaker_errors` (int) | `5` | Ошибки до открытия breaker. | `circuit_breaker_errors = 5` |
| `circuit_breaker_reset_ms` (int) | `5000` | Пауза до сброса breaker. | `circuit_breaker_reset_ms = 5000` |
| `pubsub_channel` (string) | `"vex.cluster"` | Канал pub/sub. | `pubsub_channel = "vex.cluster"` |

Пример:

```toml
[cluster.redis]
url = "redis://127.0.0.1:6379"
connect_timeout_ms = 1000
command_timeout_ms = 500
circuit_breaker_errors = 5
circuit_breaker_reset_ms = 5000
pubsub_channel = "vex.cluster"
```

## See also
- [Быстрый старт](Getting-Started-ru.md)
- [Кластеризация](Clustering-ru.md)
- [Антибот](Anti-Bot-ru.md)
- [Home](Home-ru.md)
