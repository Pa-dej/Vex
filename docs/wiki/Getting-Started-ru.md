# Быстрый старт (Русский)

Этот гайд запускает Vex примерно за 5 минут на одном бэкенде.

## Требования
- Rust (stable, 1.75+)
- Java 17+ сервер (Paper/Spigot/Vanilla) для бэкенда
- Redis (опционально, только для кластеризации/общей репутации)

## Сборка из исходников

```bash
git clone https://github.com/your-org/vex.git
cd vex
cargo build --release
```

Бинарник прокси будет в `target/release/Vex` (на Windows — `Vex.exe`).

## Минимальный конфиг (vex.toml)

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

## Запуск Paper бэкенда

Пример запуска Paper:

```bash
java -Xms1G -Xmx1G -jar paper.jar --nogui
```

Убедитесь, что он слушает `127.0.0.1:25565`, как в конфиге.

## Запуск Vex

```bash
./target/release/Vex
```

Подключайтесь клиентом к `localhost:25577`.

## Проверка через health check

```bash
curl http://127.0.0.1:8080/healthz -H "x-admin-token: change-me"
```

Ожидаемый ответ:

```text
ok
```

## Частые проблемы при первом запуске
- **Бэкенд недоступен**: проверьте `routing.backends[].address`, firewall и что сервер слушает порт.
- **Не совпадает Velocity secret**: проверьте `forwarding.velocity.secret`.
- **Проблемы с online auth**: для локальных тестов включите `[auth].mode = "offline"`.
- **Пути на Windows**: плагины кладите в `plugins/` рядом с `vex.toml`.
- **Порт занят**: измените `[listener].bind` или `[admin].bind`.

## See also
- [Конфигурация](Configuration-ru.md)
- [Антибот](Anti-Bot-ru.md)
- [Наблюдаемость](Observability-ru.md)
- [Home](Home-ru.md)
