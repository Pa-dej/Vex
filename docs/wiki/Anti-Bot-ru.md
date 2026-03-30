# Антибот (Русский)

Vex использует многослойную защиту от бот‑атак.

## 5‑слойный поток (ASCII)

```
TCP подключение клиента
      |
      v
[1] Глобальный лимит соединений
      |
      v
[2] Токен‑бакеты на IP и /24
      |
      v
[3] Раняя проверка фреймов
      |
      v
[4] Репутационный score (0-100)
      |
      v
[5] Адаптивная задержка / блок
      |
      v
Логин / маршрутизация
```

## Репутация
- Новые IP стартуют с `neutral_score` (по умолчанию 50).
- Score падает за плохие фреймы, таймауты и флуд.
- Score растёт за чистые логины и стабильные сессии.
- Затухание к нейтрали каждые 60s.
- Задержки: 25–49 → 200ms, 10–24 → 500ms.
- Блоки эскалируют: 30s → 2m → 10m.

## Как тюнить

**Небольшие сервера (≤2k concurrent):**
- `per_ip_rate_per_sec = 5`
- `per_subnet_rate_per_sec = 100`
- `global_conn_cap = 8000`

**Средние (2k–10k):**
- `per_ip_rate_per_sec = 10`
- `per_subnet_rate_per_sec = 200`
- `global_conn_cap = 25000`

**Крупные сети (10k+):**
- `per_ip_rate_per_sec = 15`
- `per_subnet_rate_per_sec = 400`
- `global_conn_cap = 50000`
- Повышайте `attack_mode_threshold_rps`

## Attack mode
Attack mode включается при превышении RPS порога.

При активации:
- Ёмкости токен‑бакетов режутся вдвое.
- Ранний дроп становится агрессивнее.
- Репутационные штрафы применяются быстрее.

## Синхронизация между нодами
В режиме кластера v4:
- Дельты репутации публикуются через Redis.
- Ноды подтягивают общий score, снижая обходы.

## Рекомендуемый фрагмент конфига

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

[reputation]
neutral_score = 50
decay_interval_secs = 60
delay_score_25_49_ms = 200
delay_score_10_24_ms = 500
block_duration_1_secs = 30
block_duration_2_secs = 120
block_duration_3_secs = 600
```

## See also
- [Конфигурация](Configuration-ru.md)
- [Кластеризация](Clustering-ru.md)
- [Наблюдаемость](Observability-ru.md)
- [Home](Home-ru.md)
