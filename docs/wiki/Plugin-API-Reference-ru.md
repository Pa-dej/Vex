# Plugin API Reference (Русский)

Здесь описан публичный API `vex-proxy-sdk` v3.

## События (17)

| Событие | Когда вызывается | Поля | Отменяемо? | Пример |
|---|---|---|---|---|
| `OnHandshake` | При получении handshake. | `protocol`, `server_address`, `intent` | Да (deny) | `event.deny("Blocked");` |
| `OnPreLogin` | До завершения авторизации. | `username`, `address` | Да (deny) | `event.deny("Not whitelisted");` |
| `OnLoginSuccess` | После успешного логина. | `player` | Нет | `event.player.send_message("hi");` |
| `OnDisconnect` | При отключении игрока. | `player`, `reason` | Нет | `api.logger.info(...);` |
| `OnBackendConnect` | Перед подключением к бэкенду. | `player`, `backend` | Да (cancel/redirect) | `event.set_backend("hub");` |
| `OnBackendReady` | Когда бэкенд готов. | `player`, `backend` | Нет | `api.logger.info(...);` |
| `OnBackendDisconnect` | Разрыв соединения с бэкендом. | `player`, `backend`, `reason` | Нет | `api.logger.warn(...);` |
| `OnBackendKick` | Кик от бэкенда. | `player`, `backend`, `message` | Да (suppress/redirect) | `event.redirect("lobby");` |
| `OnBackendSwitch` | Переключение бэкенда. | `player`, `from`, `to` | Нет | `api.logger.info(...);` |
| `OnStatusPing` | Статус‑пинг/MOTD. | `address`, `response` | Да (override) | `event.response.motd = "...";` |
| `OnReload` | При перезагрузке прокси. | `source` | Нет | `api.logger.info("reload");` |
| `OnPluginMessage` | Перехват plugin‑message. | `player`, `channel`, `data` | Да (drop) | `event.cancel();` |
| `OnAttackModeChange` | Изменение attack mode. | `enabled`, `rps` | Нет | `api.logger.warn(...);` |
| `OnBackendHealthChange` | Изменение состояния бэкенда. | `backend`, `healthy` | Нет | `api.logger.info(...);` |
| `OnPermissionCheck` | Проверка прав команды. | `player`, `permission`, `allowed` | Да (override) | `event.allow();` |
| `OnTcpConnect` | Принятие TCP соединения. | `address`, `trace_id` | Да (drop) | `event.deny("busy");` |

### Пример регистрации

```rust
api.events.on::<OnPreLogin, _, _>(move |event| async move {
    if event.username == "NotAllowed" {
        event.deny("You are not allowed.");
    }
});
```

## ProxiedPlayer методы

| Сигнатура | Описание | Пример |
|---|---|---|
| `username(&self) -> &str` | Ник игрока. | `player.username()` |
| `uuid(&self) -> Uuid` | UUID игрока. | `player.uuid()` |
| `address(&self) -> SocketAddr` | Адрес игрока. | `player.address()` |
| `send_message(&self, msg: &str)` | Отправить чат. | `player.send_message("Hi");` |
| `send_title(&self, title: &str, subtitle: &str, fade_in: u32, stay: u32, fade_out: u32)` | Title + тайминги. | `player.send_title("Hi","",10,60,10);` |
| `send_actionbar(&self, msg: &str)` | Actionbar. | `player.send_actionbar("Ready");` |
| `kick(&self, msg: &str)` | Кикнуть игрока. | `player.kick("Bye");` |
| `transfer(&self, backend: &str)` | Перевести на другой бэкенд. | `player.transfer("hub");` |
| `set_tab_list(&self, header: &str, footer: &str)` | Заголовок/футер таба. | `player.set_tab_list("H","F");` |
| `metadata(&self) -> PlayerMetadata` | Метаданные игрока. | `player.metadata().set("key", 1);` |

## ProxyHandle методы

| Сигнатура | Описание | Пример |
|---|---|---|
| `broadcast(&self, msg: &str)` | Broadcast всем игрокам (локально). | `api.proxy.broadcast("hi");` |
| `get_player(&self, name: &str) -> Option<ProxiedPlayer>` | Найти игрока по имени. | `api.proxy.get_player("Alice");` |
| `online_count(&self) -> u32` | Онлайн (локальный). | `api.proxy.online_count()` |
| `get_all_players(&self) -> Vec<PlayerInfo>` | Онлайн по всему кластеру. | `api.proxy.get_all_players()` |
| `send_plugin_message(&self, channel: &str, data: Bytes)` | Отправить plugin‑message. | `api.proxy.send_plugin_message("BungeeCord", data);` |
| `reload(&self)` | Перезагрузка прокси. | `api.proxy.reload()` |
| `shutdown(&self)` | Остановка прокси. | `api.proxy.shutdown()` |

## Scheduler API

| Метод | Описание | Пример |
|---|---|---|
| `run_next_tick(f)` | Выполнить на следующем тике. | `api.scheduler.run_next_tick(|| async move { ... });` |
| `run_later(delay_ms, f)` | Выполнить через задержку. | `api.scheduler.run_later(5000, || async move { ... });` |
| `run_timer(interval_ms, f)` | Повторяющийся таймер. | `api.scheduler.run_timer(60000, || async move { ... });` |

## Config API

| Метод | Описание | Пример |
|---|---|---|
| `save_default(path, contents)` | Создать файл, если нет. | `api.config.save_default("config.yml", DEFAULT);` |
| `load_yaml<T>(path)` | Загрузить YAML в структуру. | `let cfg: Cfg = api.config.load_yaml("config.yml")?;` |
| `data_dir()` | Папка данных плагина. | `api.config.data_dir()` |

## Metrics API

| Метод | Описание | Пример |
|---|---|---|
| `counter(name, help)` | Создать counter. | `api.metrics.counter("x_total", "help")?;` |
| `gauge(name, help)` | Создать gauge. | `api.metrics.gauge("x", "help")?;` |
| `histogram(name, help, buckets)` | Создать histogram. | `api.metrics.histogram("x", "help", vec![...])?;` |

## Chat / Title / Actionbar / Tab list

| Метод | Описание |
|---|---|
| `send_message` | Чат‑сообщение игроку. |
| `send_title` | Title + subtitle. |
| `send_actionbar` | Actionbar. |
| `set_tab_list` | Заголовок/футер таба. |

## See also
- [Разработка плагинов](Plugin-Development-ru.md)
- [Конфигурация](Configuration-ru.md)
- [Home](Home-ru.md)
