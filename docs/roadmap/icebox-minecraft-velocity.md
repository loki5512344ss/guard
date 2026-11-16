# Icebox — Minecraft Velocity forwarding

| | |
|---|---|
| Milestone | icebox |
| Status | dropped |
| Priority | — |
| Depends on | решение о приоритете MC-сегмента |

## Цель

Поддержка Velocity modern forwarding в `protocol-minecraft`, чтобы edge мог
работать перед Velocity, а не только перед Paper.

## Почему отложено

v0.3 сознательно ушёл от Minecraft-специфичности к универсальной платформе.
Функция нужна только если MC-сегмент остаётся целевым; при этом современный
forwarding требует HMAC-секрета и меняет модель доверия между edge и прокси.

## Что нужно, если браться

- Разбор `login_start` с forwarding-полями и проверка HMAC.
- Конфиг с секретом (fail-fast, без дефолта) и ротацией.
- Игровые netns smoke-тесты и нагрузочная проверка (сейчас есть только
  TCP-handshake тесты).
- Документация: схема edge → Velocity → Paper, кто кому доверяет.

## Критерии возврата из icebox

Явный запрос пользователя + подтверждение, что MC-трафик — приоритетнее v0.5/v0.6
задач.
