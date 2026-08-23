# API Reference - Rampart Manager

> REST API управления. Base URL: `http://MANAGER:8080`
> Авторизация: Bearer JWT (получить через `/api/v1/auth/login`).

Реализованные маршруты — см. src/bin/rampart-manager.rs. Это полный список:
ничего сверх перечисленного здесь API не предоставляет.

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

Redis недоступен → пустой список.

---

## Blacklist

### `GET /api/v1/blacklist` 🔒

```json
{
  "items": [
    {"target": "1.2.3.4", "type": "ip", "reason": "manual_ban",
     "created_at": "...", "expires_at": null}
  ],
  "total": 42
}
```

Источник: Redis set `rampart:blacklist`. Пагинации и фильтров нет.

### `POST /api/v1/blacklist` 🔒

```json
// Request
{"target": "1.2.3.4", "type": "ip", "reason": "manual_ban", "duration_secs": 3600}

// Response 200/201 — запись добавлена в Redis set
```

Edge-ноды подхватывают ban при следующей синхронизации блэклиста.

---

## Nodes

### `GET /api/v1/nodes` 🔒

Список зарегистрированных edge-нод из Redis (`rampart:nodes:*`, heartbeat).

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

- удаления записей blacklist (только add/list);
- drain нод через API (есть только CLI `rampart-cli drain`);
- webhooks, metrics summary, challenge management;
- регистрации нод через `POST /api/v1/nodes`;
- rate limiting на сами запросы API (кроме login).

---

*Версия: 2.0 | Август 2026*
