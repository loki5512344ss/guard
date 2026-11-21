# Troubleshooting - FAQ и диагностика

---

## Edge нода

### "XDP не загружается"

При старте edge пишет одну строку `XDP environment: interface=… kernel=… virt=… btf=…
privileges=… driver=… expected_mode=…` — её же печатает `rampart-cli doctor`
(общий код `EnvironmentReport::summary_fields`). `expected_mode` — предсказание по
таблице драйверов; реальный режим логируется после attach (`native (drv)` или
`generic (skb)`). Ошибка attach содержит вердикт и `hint:` с рекомендацией
(контейнер lxc/openvz → нужна KVM-VDS; нет CAP_NET_ADMIN/CAP_BPF/CAP_PERFMON — даже у root в
контейнере, `privileges=missing-xdp-caps` → `docker run --cap-add …`; нет BTF → ядро с
`CONFIG_DEBUG_INFO_BTF=y`).

```bash
systemd-detect-virt   # openvz/lxc → XDP не работает, нужен KVM
uname -r              # нужно 5.10+
dpkg -l | grep libbpf # libbpf-dev нужен при сборке

journalctl -u rampart | grep -i "xdp\|ebpf\|bpf"

# Проверить компиляцию BPF-программы вручную:
clang -O2 -g -target bpf -I"/usr/include/$(gcc -print-multiarch)" \
  -c xdp/core/universal_filter.c -o /tmp/uf.o

# Не помогло — отключи XDP в config.toml ([xdp] enabled = false) и рестарт.
```

### "accept error: ... backing off" / "Too many open files"

```bash
# Кончились дескрипторы: демон сам делает backoff, но сервис уже деградирует
ulimit -n                       # для процесса
systemctl show rampart -p LimitNOFILE
journalctl -u rampart | grep -E "accept error|EMFILE|backing off"
ss -s | head -5
```

Поднять `LimitNOFILE` (например, 65535), перезапустить, проверить утечки
соединений (`ss -tan state established | wc -l`). Backoff в списке логов — это
симптом, а не причина.

### "XDP не снимается после остановки демона"

```bash
bpftool net show dev eth0
ip link show eth0 | grep -i xdp
```

Если программа осталась — загрузчик не снял её (регрессия), снять вручную
`ip link set dev eth0 xdp off` и завести баг с режимом attach из лога
(`native (drv)` / `generic (skb)`).

### "Rate limit блокирует реальных клиентов"

```bash
# Смотрим метрики
curl -s http://EDGE_IP:9090/metrics | grep rate_limit

# Клиенты за NAT (один IP — много людей) → увеличь лимиты в config.toml:
# [limits] max_connections_per_ip = 50
# Или добавь их адрес в whitelist (только IP), рестарт.
```

### "Высокое CPU на edge ноде"
```bash
top -p $(pgrep rampart)
perf top -p $(pgrep rampart)

# Частые причины:
# 1. Много мусорных коннектов в userspace → включи XDP ([xdp] enabled = true)
# 2. Заниженные rate limit → соединения постоянно рвутся и пересоздаются
# 3. Не хватает воркеров → [workers] count = числу vCPU
```

### "Edge не стартует: no protocol plugins compiled"

Реестр протоколов пуст: `rampart` требует хотя бы один ProtocolHandler.
Для Minecraft Java собери edge с `--features protocol-minecraft` и включи
`[protocol.minecraft]` в конфиге; для HTTP используй `--features protocol-http`.
Без зарегистрированного обработчика edge завершится с ошибкой при запуске.
Подробная инструкция: [Minecraft Java](minecraft-java.md).

---

## Manager

### "Manager не стартует: JWT_SECRET must be set"

```bash
export JWT_SECRET="$(openssl rand -hex 32)"   # минимум 32 байта
export API_PASSWORD="сильный_пароль"          # 'changeme' запрещён
export REDIS_URL="redis://127.0.0.1:6379/0"   # опционально
rampart-manager
```

### "Manager не стартует: API_PASSWORD must be ..."

`API_PASSWORD` должен быть непустым и не короче 16 символов, `JWT_SECRET` —
не короче 32 непробельных байт. Пустой пароль раньше принимался как валидный,
поэтому теперь это ошибка старта, а не тихий вход без пароля.

```bash
systemctl show rampart-manager -p Environment | tr ' ' '\n' | grep -E "API_PASSWORD|JWT_SECRET" | sed 's/=.*/=<redacted>/'
```

### "Manager отдаёт 401"

Токен истёк (`JWT_EXPIRATION_SECS`, дефолт 86400) — перелогинься:

```bash
curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"password":"..."}'
```

---

## Redis

### "Redis падает с OOM"

```bash
redis-cli INFO memory | grep used_memory_human
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### "Edge не синхронизирует блэклист через Redis"

```bash
# redis_url задан и не пустой? Сборка с feature store-redis (дефолт)?
grep redis_url /etc/rampart/config.toml
journalctl -u rampart | grep -i redis
```

Без Redis edge работает автономно на локальном кэше блэклиста.

---

## ClickHouse

### "ClickHouse не принимает данные"

```bash
systemctl status clickhouse-server
curl http://localhost:8123/ping
clickhouse-client --query "SHOW TABLES FROM rampart"
df -h /var/lib/clickhouse
```

Запись настраивается `store.clickhouse_url` в config.toml. Ошибки записи не
роняют edge: события складываются в bounded-буфер (10 000) и при переполнении
или таймауте учитываются в `rampart_clickhouse_dropped_total`.

```bash
curl -s http://EDGE_IP:9090/metrics | grep clickhouse_dropped
```

Растущий счётчик = ClickHouse не успевает; защита при этом работает, но
аналитика теряет события.

---

## Общая диагностика

```bash
rampart-cli doctor    # полная диагностика через Manager API
rampart-cli status    # краткий статус
```

> Честно: набор проверок `doctor` ограничен тем, что реализовано в CLI
> (см. src/cli/commands/doctor.rs) и доступно Manager API.

---

*Версия: 3.0 | Ноябрь 2026*
