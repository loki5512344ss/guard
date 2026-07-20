# API Reference - Rampart Manager

> REST API для управления Rampart.  
> Base URL: `https://manager.rampart.internal/api/v1`  
> Авторизация: Bearer JWT (получить через `/api/v1/auth/login`)

---

## Аутентификация

### `POST /api/v1/auth/login`

Получение JWT токена.

```json
// Request
{
  "password": "changeme"
}

// Response 200
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Все последующие запросы:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

---

## Nodes

### `GET /api/v1/nodes`

Список всех зарегистрированных нод.

```json
// Response 200
{
  "nodes": [
    {
      "id": "edge-eu-1",
      "role": "edge",
      "ip": "10.0.100.1",
      "public_ip": "45.200.10.1",
      "status": "online",
      "version": "0.4.0",
      "uptime_secs": 86400,
      "metrics": {
        "connections_per_sec": 1200,
        "active_connections": 45000,
        "cpu_percent": 45.2,
        "memory_mb": 512
      },
      "last_heartbeat": "2026-07-19T10:30:00Z"
    }
  ]
}
```

### `GET /api/v1/nodes/{id}`

Детальная информация о ноде.

### `POST /api/v1/nodes`

Регистрация новой ноды (или через авто-discovery).

```json
// Request
{
  "name": "edge-us-2",
  "role": "edge",
  "public_ip": "45.200.20.5",
  "wg_public_key": "<BASE64_KEY>"
}

// Response 201
{
  "id": "edge-us-2",
  "wg_config": "https://manager/api/v1/nodes/edge-us-2/wg-config",
  "tls_cert": "https://manager/api/v1/nodes/edge-us-2/cert"
}
```

### `POST /api/v1/nodes/{id}/drain`

Вывести ноду из ротации (graceful shutdown).

```json
// Response 200
{
  "status": "draining",
  "active_connections_before": 45000,
  "estimated_seconds": 30
}
```

---

## Blacklist

### `GET /api/v1/blacklist`

Список забаненных IP/ASN.

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `page` | int | 1 | Пагинация |
| `per_page` | int | 100 | Элементов на странице |
| `reason` | string | - | Фильтр по причине |
| `search` | string | - | Поиск по IP/ASN |

```json
// Response 200
{
  "items": [
    {
      "target": "1.2.3.4",
      "type": "ip",            // ip | asn | cidr
      "reason": "rate_limit",
      "created_by": "admin",
      "created_at": "2026-07-19T10:00:00Z",
      "expires_at": "2026-07-20T10:00:00Z",
      "hits": 1500
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 100
}
```

### `POST /api/v1/blacklist`

Добавить IP/ASN/CIDR в блэклист.

```json
// Request
{
  "target": "1.2.3.4",
  "type": "ip",              // ip | asn | cidr
  "reason": "manual_ban",
  "duration_secs": 3600      // null = навсегда
}

// Response 201
{
  "status": "added",
  "target": "1.2.3.4",
  "propagated_to_nodes": 2,
  "expires_at": "2026-07-19T11:00:00Z"
}
```

### `DELETE /api/v1/blacklist/{id}`

Удалить запись из блэклиста.

```json
// Response 200
{
  "status": "removed",
  "target": "1.2.3.4"
}
```

---

## Servers

### `GET /api/v1/servers`

Список зарегистрированных game серверов.

```json
// Response 200
{
  "servers": [
    {
      "name": "survival-01",
      "type": "survival",
      "ip": "10.0.2.1",
      "port": 25565,
      "status": "online",
      "proxy": "velocity-01",
      "online": 42,
      "max_players": 100,
      "tps": 19.8,
      "mspt": 25.3,
      "ram_used_mb": 2048,
      "ram_max_mb": 8192,
      "last_heartbeat": "2026-07-19T10:30:00Z"
    }
  ]
}
```

### `GET /api/v1/servers/{name}`

Детальная информация о сервере.

### `DELETE /api/v1/servers/{name}`

Принудительно удалить сервер из registry.

---

## Challenges (v0.5+)

### `GET /api/v1/challenges/status`

Статус challenge системы.

```json
// Response 200
{
  "enabled": true,
  "mode": "auto",
  "active_challenges": 15,
  "passed_last_hour": 1200,
  "failed_last_hour": 45,
  "current_type": "timing"
}
```

### `POST /api/v1/challenges/rotate`

Принудительно сменить тип challenge.

```json
// Request
{
  "type": "map_captcha"    // timing | map_captcha | behavioral | contextual
}

// Response 200
{
  "status": "rotated",
  "previous_type": "timing",
  "new_type": "map_captcha",
  "rotated_at": "2026-07-19T10:30:00Z"
}
```

---

## Metrics

### `GET /api/v1/metrics/summary`

Сводка метрик за период.

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `since` | ISO8601 | -24h | Начало периода |
| `until` | ISO8601 | now | Конец периода |

```json
// Response 200
{
  "total_connections": 5200000,
  "blocked": 45000,
  "allowed": 5155000,
  "active_connections": 85000,
  "top_attackers": [
    {"ip": "5.5.5.5", "hits": 12000, "country": "NL"},
    {"ip": "6.6.6.6", "hits": 8000, "country": "RU"}
  ],
  "top_countries": [
    {"country": "US", "connections": 2000000},
    {"country": "DE", "connections": 1000000}
  ]
}
```

---

## Health

### `GET /api/v1/health`

```json
// Response 200
{
  "status": "healthy",
  "version": "0.4.0",
  "uptime_secs": 604800,
  "components": {
    "redis": "healthy",
    "nats": "healthy",
    "clickhouse": "healthy",
    "edge_nodes": {"online": 2, "offline": 0},
    "velocity_nodes": {"online": 3, "offline": 1},
    "game_servers": {"online": 45, "offline": 2}
  }
}
```

---

## Webhooks

### `POST /api/v1/webhooks`

Настройка webhook для событий.

```json
// Request
{
  "url": "https://discord.com/api/webhooks/...",
  "events": ["blacklist.added", "node.down", "attack.detected"],
  "secret": "optional_hmac_secret"
}

// Response 201
{
  "id": "wh_abc123",
  "status": "active"
}
```

### Payload пример (blacklist.added)

```json
{
  "event": "blacklist.added",
  "timestamp": "2026-07-19T10:30:00Z",
  "data": {
    "target": "1.2.3.4",
    "reason": "rate_limit",
    "added_by": "auto"
  }
}
```

---

## OpenAPI Spec

Полная OpenAPI 3.0 спецификация: `docs/api/openapi.yaml`

```yaml
openapi: "3.0.3"
info:
  title: Rampart Manager API
  version: "0.4.0"
servers:
  - url: https://manager.rampart.internal/api/v1
paths:
  /nodes:
    get:
      summary: List all nodes
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Node list
  /blacklist:
    post:
      summary: Add to blacklist
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                target:
                  type: string
                type:
                  type: string
                  enum: [ip, asn, cidr]
                reason:
                  type: string
                duration_secs:
                  type: integer
      responses:
        '201':
          description: Added
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

---

## Rate Limiting

API имеет rate limiting: **60 запросов в минуту** на один JWT токен.

```json
// Response 429
{
  "error": "rate_limit_exceeded",
  "retry_after_secs": 30
}
```

Headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1626688800
```

---

*Версия: 1.0 | Июль 2026*
