# API Reference - Rampart Manager

> REST API управления. Base URL: `http://MANAGER:8080`
> Авторизация: Bearer JWT (получить через `/api/v1/auth/login`).

Реализованные маршруты — см. `src/manager/api/guard/router.rs` (единственное место
сборки роутера, включая тесты). Это полный список: ничего сверх перечисленного
здесь API не предоставляет.

---

## Аутентификация

### `POST /api/v1/auth/login`

```json
// Request
{"password": "значение API_PASSWORD"}

// Response 200
{"token": "eyJhbGciOiJIUzI1NiIs..."}

// 401 → неверный пароль; 429 → больше 5 попыток за минуту с одного IP
```

Все защищённые запросы:

```
Authorization: Bearer <token>
```

Токен живёт `JWT_EXPIRATION_SECS` секунд (дефолт 86400).

---

## Health (публичный)

### `GET /api/v1/health`

```json
{"status": "healthy", "version": "0.3.0-dev"}
```

---

## Servers

### `GET /api/v1/servers` 🔒

Список серверов из Redis-реестра (`rampart:servers:*`).

```json
{
  "servers": [
    {"name": "app-01", "type": "tcp", "ip": "10.0.2.1", "port": 25566, "status": "online"}
  ]
}
```

Если Redis недоступен, API возвращает `503 Service Unavailable`.

---

## Blacklist

### `GET /api/v1/blacklist` 🔒

Query: `limit` (по умолчанию 100, максимум 1000) и `offset` (максимум 10000).

```json
{
  "items": [
    {"target": "1.2.3.4", "type": "ip", "reason": "manual_ban",
     "created_at": "2026-10-16T12:00:00+00:00", "expires_at": "2026-10-16T13:00:00+00:00"}
  ],
  "total": 42
}
```

Источник: Redis set `rampart:blacklist` и hash `rampart:blacklist:metadata`.
Записи читаются через `SSCAN` порциями, поэтому set никогда не выгружается целиком;
порядок страниц не определён (Redis set) и при параллельных изменениях страницы
могут пересекаться. `total` — размер set по `SCARD`, он может включать истёкшие
записи, которые API скрывает в `items`.

Метаданные содержат причину, время создания и абсолютный срок истечения; API
скрывает истёкшие записи. `GET` ничего не пишет в Redis: старые set-записи без
метаданных показываются с временной записью «пять минут» только для чтения, а
сама метаданные восстанавливаются одноразовым фоновым backfill при старте
manager (или при восстановлении снимка edge).

### `POST /api/v1/blacklist` 🔒

```json
// Request
{"target": "1.2.3.4", "type": "ip", "reason": "manual_ban", "duration_secs": 3600}

// Response 200 — запись и метаданные атомарно сохранены в Redis, а событие
// с duration_secs и expires_at_unix опубликовано в rampart:blacklist:events.
```

`target` — одиночный IPv4/IPv6-адрес (CIDR не поддерживается), `reason` — не
длиннее 256 байт; иначе `400 Bad Request`.

Edge подписывается на Pub/Sub перед загрузкой снимка из Redis. Поэтому события,
пришедшие во время загрузки, будут применены после снимка. При старте и после
переподключения активные Redis-баны восстанавливаются с оставшимся TTL; новые
события используют абсолютный срок и игнорируются, если он уже прошёл. Старый
формат события только с `duration_secs` продолжает поддерживаться.

### `DELETE /api/v1/blacklist` 🔒

```json
{"target": "1.2.3.4"}
```

Удаляет только Redis-бан и его метаданные, затем публикует событие unban.
Локальные баны детекторов хранятся отдельно и этим запросом не снимаются.

---

## Nodes

### `GET /api/v1/nodes` 🔒

Список зарегистрированных edge-нод из Redis (`rampart:nodes:*`, heartbeat).

Если Redis недоступен, API возвращает `503 Service Unavailable`; пустой массив
означает исправное, но пустое окружение.

```json
{
  "nodes": [
    {"id": "edge-eu-1", "role": "edge", "ip": "10.0.100.1",
     "status": "online", "last_heartbeat": "..."}
  ]
}
```

---

## Не реализовано

Честно, на текущий момент в API **нет**:

- drain нод через API (CLI-команда `rampart-cli drain <node>` существует, но
  завершается явной ошибкой «not implemented»);
- webhooks, metrics summary, challenge management;
- регистрации нод через `POST /api/v1/nodes`.

## Ограничения запросов

- Тело запроса — не больше 8 КиБ (`413`), любой запрос — не дольше 10 секунд.
- `/api/v1/auth/login` — 5 попыток в минуту с одного клиентского адреса (`429`).
- `POST`/`DELETE /api/v1/blacklist` (и любые будущие mutating-методы) — 30 запросов
  в минуту с одного клиентского адреса (`429`); успешный login сбрасывает счётчик.
- Клиентский адрес — TCP peer, если запрос не пришёл с сети из
  `MANAGER_TRUSTED_PROXIES`; только тогда используется `X-Forwarded-For`.

---

*Версия: 2.1 | Ноябрь 2026*
