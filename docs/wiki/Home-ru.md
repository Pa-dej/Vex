# Vex Proxy (Русский)

Высокопроизводительный Rust‑прокси для Minecraft Java с кластеризацией, антиботом и нативными Rust‑плагинами.

![crates.io](https://img.shields.io/crates/v/vex-proxy.svg) ![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg) ![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)

## Бенчмарк (10 000 одновременных подключений)

| Прокси | Рантайм | Пиковая RAM | KB/conn | Успех | Таймауты |
|---|---|---:|---:|---:|---:|
| **Vex** | Rust | **258 MB** | **26 KB** | **100%** | **0** |
| Gate | Go | 968 MB | 97 KB | 100% | 0 |
| BungeeCord | JVM | 1526 MB | 153 KB | 100% | 428 |

После теста (удержание памяти): Vex 14 MB, Gate 22 MB, BungeeCord 707 MB.

## Возможности

### Ядро прокси
- Minecraft Java 1.20–1.21.4 (protocol 763–774)
- Онлайн + оффлайн авторизация с проверкой сессий Mojang
- Шифрование AES/CFB8
- Velocity modern forwarding с HMAC
- Балансировка weighted least-connections
- Активные health‑checks (status ping + TCP fallback)
- Атомарный hot reload через ArcSwap
- Корректное завершение с drain
- Защита от slowloris/idle таймаутов
- Пулы буферов на подключение

### Антибот (v1.2 + v2)
- Глобальный лимит подключений
- Токен‑бакеты на IP и /24 подсети
- Ранний дроп кривых/слишком больших фреймов
- Репутационный кеш (0–100 на IP)
- Адаптивные задержки по score
- Эскалация блокировок (30s → 2m → 10m)
- Attack mode с авто‑детектом флуда
- Затухание репутации к нейтрали раз в 60s
- Синхронизация репутации через Redis (v4)

### Наблюдаемость
- Prometheus‑метрики (50+)
- Структурные JSON‑логи с trace_id на соединение
- Grafana‑дашборд (vex-proxy-v1, авто‑провижининг)
- Docker Compose стек (Prometheus + Grafana + Redis)

### Plugin API (v3.0)
- Нативные Rust‑плагины (.dll/.so/.dylib)
- 17 событий (логин, бэкенд, статус, перезагрузка, attack mode, etc.)
- transfer() для переключения бэкенда без дисконнекта
- Динамический MOTD через статус‑пинг
- Zero‑copy plugin messaging (Bytes)
- Метаданные игрока (type‑safe DashMap)
- Реестр команд с permission‑checks
- Планировщик (run_later, run_timer, run_next_tick)
- Конфиг API (YAML, save_default)
- Tab list, title, actionbar, chat API
- Метрики плагинов (custom Prometheus)
- Hot‑reload плагинов через watcher
- Проверка ABI (VEX_SDK_VERSION)
- Таймаут обработчика 500ms с изоляцией panic

### Кластеризация (v4)
- Redis‑бэкенд и реестр нод (TTL 15s)
- Общая репутация между нодами
- Глобальный rate‑limit через Redis counters
- Pub/sub события (attack mode, репутация, broadcast)
- Глобальный реестр сессий (get_all_players)
- Degraded режим при недоступности Redis
- Circuit breaker для Redis операций
- Admin API: /cluster/status, /cluster/nodes

### Admin API
- GET /healthz, GET /metrics
- POST /reload, /auth/mode, /shutdown
- POST /commands/{name}
- Авторизация через x-admin-token

## Быстрые ссылки
- [Быстрый старт](Getting-Started-ru.md)
- [Конфигурация](Configuration-ru.md)
- [Разработка плагинов](Plugin-Development-ru.md)
- [Plugin API Reference](Plugin-API-Reference-ru.md)
- [Антибот](Anti-Bot-ru.md)
- [Кластеризация](Clustering-ru.md)
- [Наблюдаемость](Observability-ru.md)
- [Сравнение](Comparison-ru.md)
- [История версий](Changelog-ru.md)

## See also
- [Home (EN)](Home-en.md)
- [README](../../README.md)
