# Наблюдаемость (Русский)

Vex предоставляет Prometheus‑метрики, структурные логи и Grafana‑дашборд.

## Запуск Grafana стека

```bash
docker compose -f docker-compose.observability.yml up -d
```

Grafana обычно доступна на `http://localhost:3000` с преднастроенным дашбордом `vex-proxy-v1`.

## JSON‑логи для продакшена

```toml
[observability]
log_format = "json"
log_level = "info"
```

## trace_id корреляция
Каждое соединение получает `trace_id`, который присутствует в логах и событиях:
- Используйте его для склейки handshake → login → backend routing.
- Плагин‑события используют тот же `trace_id`, если привязаны к игроку.

## Метрики (50+)

| Метрика | Тип | Описание |
|---|---|---|
| `vex_connections_total` | counter | Все принятые TCP соединения. |
| `vex_connections_active` | gauge | Текущие активные соединения. |
| `vex_connections_rate` | gauge | Соединений в секунду. |
| `vex_handshake_fail_total` | counter | Ошибки handshake. |
| `vex_login_success_total` | counter | Успешные логины. |
| `vex_login_fail_total` | counter | Ошибки логина. |
| `vex_auth_online_total` | counter | Попытки online auth. |
| `vex_auth_offline_total` | counter | Попытки offline auth. |
| `vex_status_ping_total` | counter | Запросы статуса. |
| `vex_status_ping_fail_total` | counter | Ошибки статуса. |
| `vex_backend_connect_total` | counter | Попытки подключиться к бэкенду. |
| `vex_backend_connect_fail_total` | counter | Ошибки подключения к бэкенду. |
| `vex_backend_latency_ms` | histogram | Латентность логина на бэкенд. |
| `vex_backend_active` | gauge | Активные backend‑соединения. |
| `vex_backend_healthy` | gauge | Healthy бэкенды. |
| `vex_backend_unhealthy` | gauge | Unhealthy бэкенды. |
| `vex_routing_selected_total` | counter | Выборы бэкенда. |
| `vex_routing_retry_total` | counter | Повторы выбора бэкенда. |
| `vex_routing_degraded_total` | counter | Срабатывания degraded режима. |
| `vex_player_online` | gauge | Онлайн игроков (локально). |
| `vex_player_login_duration_ms` | histogram | Длительность логина. |
| `vex_player_session_seconds` | histogram | Длина сессии. |
| `vex_network_bytes_in_total` | counter | Байты от клиентов. |
| `vex_network_bytes_out_total` | counter | Байты к клиентам. |
| `vex_buffer_pool_bytes` | gauge | Размер пула буферов. |
| `vex_buffer_pool_in_use` | gauge | Используемые буферы. |
| `vex_antibot_attack_mode` | gauge | Attack mode (0/1). |
| `vex_antibot_attack_mode_seconds` | counter | Время в attack mode. |
| `vex_antibot_rate_limited_total` | counter | Rate‑limit срабатывания. |
| `vex_antibot_frame_reject_total` | counter | Дроп кривых/слишком больших фреймов. |
| `vex_antibot_conn_cap_reject_total` | counter | Дроп по глобальному лимиту. |
| `vex_antibot_ip_bucket_drops_total` | counter | Дропы по IP токен‑бакету. |
| `vex_antibot_subnet_bucket_drops_total` | counter | Дропы по /24 токен‑бакету. |
| `vex_reputation_score_avg` | gauge | Средний репутационный score. |
| `vex_reputation_blocks_total` | counter | Блокировки по репутации. |
| `vex_reputation_delay_total` | counter | Задержанные подключения. |
| `vex_plugin_events_total` | counter | Доставленные события плагинов. |
| `vex_plugin_event_timeouts_total` | counter | Таймауты обработчиков. |
| `vex_plugin_panics_total` | counter | Пойманные panic в плагинах. |
| `vex_plugin_messages_total` | counter | Плагин‑сообщения. |
| `vex_plugin_message_drops_total` | counter | Дропнутые плагин‑сообщения. |
| `vex_scheduler_tasks_active` | gauge | Активные задачи планировщика. |
| `vex_scheduler_tasks_total` | counter | Всего созданных задач. |
| `vex_cluster_nodes` | gauge | Ноды в кластере. |
| `vex_cluster_heartbeat_lag_ms` | histogram | Лаг heartbeat в Redis. |
| `vex_cluster_redis_errors_total` | counter | Ошибки Redis команд. |
| `vex_cluster_pubsub_events_total` | counter | Pub/sub события. |
| `vex_cluster_degraded` | gauge | Degraded режим (0/1). |
| `vex_admin_requests_total` | counter | Запросы Admin API. |
| `vex_admin_auth_fail_total` | counter | Ошибки авторизации Admin API. |
| `vex_admin_reload_total` | counter | Вызовы reload. |
| `vex_admin_shutdown_total` | counter | Вызовы shutdown. |
| `vex_memory_bytes` | gauge | Память (RSS). |
| `vex_cpu_usage` | gauge | Использование CPU, %. |
| `vex_trace_id_collisions_total` | counter | Коллизии trace_id (должно быть 0). |

## Кастомные метрики плагинов
Плагины могут регистрировать метрики через Metrics API. Имена имеют префикс `vex_plugin_<plugin>_...` и удаляются при выгрузке плагина.

## See also
- [Конфигурация](Configuration-ru)
- [Разработка плагинов](Plugin-Development-ru)
- [Home](Home-ru)
