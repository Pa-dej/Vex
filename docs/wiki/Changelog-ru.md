# История версий (Русский)

## v1.0 — Ядро прокси
- Базовое ядро прокси
- Health‑checks + hot reload
- Корректный shutdown с drain

## v1.1 — Online auth + Velocity forwarding
- Online auth с проверкой Mojang
- Velocity modern forwarding (HMAC)
- Шифрование AES/CFB8

## v1.2 — Базовый антибот
- Глобальный лимит подключений
- Токен‑бакеты на IP и /24
- Ранний дроп фреймов

## v1.3 — Observability
- Prometheus‑метрики
- JSON‑логи с trace_id
- Grafana‑дашборд

## v2.0 — Расширенный антибот
- Репутационная система (0–100)
- Адаптивные задержки
- Эскалация блоков (30s → 2m → 10m)
- Авто‑детект attack mode

## v3.0 — Plugin API + vex-proxy-sdk
- Нативные Rust‑плагины
- 17 событий
- Метрики плагинов
- Hot reload + watcher

## v4.0 — Кластеризация
- Redis‑реестр нод
- Общая репутация и лимиты
- Pub/sub события и глобальный реестр сессий
- Degraded режим и circuit breaker

## See also
- [Home](Home-ru)
- [Сравнение](Comparison-ru)
