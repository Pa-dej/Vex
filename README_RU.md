# Vex Proxy

Vex — это высокопроизводительный Minecraft-прокси на Rust с упором на безопасный hot reload, аккуратное завершение, anti-bot защиту и production-observability.

## Текущая матрица возможностей

### v1
- [x] Базовый прокси + hot reload + graceful shutdown
- [x] Health checks + Prometheus metrics
- [x] Whitelist протоколов + reject неподдерживаемых
- [x] Slowloris / idle timeout
- [x] 26 unit/integration тестов

### v1.1
- [x] Velocity Modern Forwarding + HMAC
- [x] Online auth + AES/CFB8 + circuit breaker
- [x] Реальные UUID + skin properties

### v1.2
- [x] Global cap + per-IP/per-subnet token buckets
- [x] Early frame rejection
- [x] Метрики отклонений (rejection metrics)

### G (Observability)
- [x] Structured logging (`json`/`pretty`) + `trace_id` на соединение
- [x] Расширенные Prometheus-метрики
- [x] Grafana dashboard (`uid: vex-proxy-v1`)
- [x] Docker Compose стек observability

### v2
- [x] Reputation cache + decay + cleanup
- [x] Адаптивные штрафы (200ms / 500ms / block)
- [x] Эскалация блоков (30s / 2min / 10min)
- [x] Attack analytics + attack mode
- [x] 26 тестов зелёные

## Структура проекта

- `src/main.rs`: bootstrap приложения, wiring runtime, запуск admin + proxy
- `src/server.rs`: listener, handshake/login pipeline, relay к backend, интеграция anti-bot
- `src/admin.rs`: admin HTTP API (`/healthz`, `/metrics`, `/reload`, `/auth/mode`, `/shutdown`)
- `src/metrics.rs`: Prometheus registry и helpers для метрик
- `src/reputation.rs`: per-IP reputation, штрафы, decay, cleanup
- `src/analytics.rs`: attack-аналитика на скользящих окнах и сигнал attack-mode
- `src/limiter.rs`: global cap + per-IP/per-subnet token buckets
- `scripts/v1_smoke_checks.py`: end-to-end smoke checks

## Быстрый старт

## 1) Поднять backend (локальный mock)

```bash
cargo run --bin mock_backend -- --bind 127.0.0.1:25565 --secret test-secret-123 --velocity true
```

## 2) Запустить Vex

```bash
cargo run --bin Vex
```

Vex читает конфигурацию из `vex.toml`.

## 3) Запустить smoke-check

```bash
python scripts/v1_smoke_checks.py
```

## 4) Запустить тесты

```bash
cargo test
```

## Admin API

Bind по умолчанию: `127.0.0.1:8080`  
Заголовок авторизации: `x-admin-token: <token из vex.toml>`

- `GET /healthz`
- `GET /metrics`
- `POST /reload`
- `POST /auth/mode`
- `POST /shutdown`

## Observability-стек (Prometheus + Grafana)

Запуск:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Endpoint’ы:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Источник метрик Vex: `http://host.docker.internal:8080/metrics`

Dashboard:

- Файл: `grafana/vex-dashboard.json`
- UID: `vex-proxy-v1`

## Anti-Bot runtime поведение (v2)

- Reputation score на IP в диапазоне `0..100`, стартовое значение `50`
- Автоматический decay score обратно к нейтральному уровню
- Delay tiers:
- `25..49`: задержка 200ms перед backend dial
- `10..24`: задержка 500ms перед backend dial (+warn лог)
- `<10`: временный блок с эскалацией (`30s`, `2min`, `10min`)
- Attack mode использует скользящие окна аналитики и может снижать capacity лимитеров на 50% до стабилизации трафика

## Примечания

- Для anti-bot не используется глубокий per-packet анализ в play-state.
- Существующее поведение auth, relay, ArcSwap reload и observability сохранено при интеграции anti-bot v2.
