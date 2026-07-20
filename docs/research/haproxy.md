# HAProxy и свой Rust Load Balancer

> HAProxy - хорошее начало для v0.1-v0.2.  
> Свой Rust LB - цель для v0.4 (убирает SPOF, добавляет MC-aware health check).

---

## Проблема с HAProxy

```
HAProxy как единственная точка входа = Single Point of Failure

Если HAProxy упал:
  Все 20 Velocity нод недоступны
  Все игроки дисконнектятся
  Нет автоматического failover

Решение:
  v0.1-v0.2: HAProxy + keepalived (VRRP failover)
  v0.4+:     Собственный Rust LB (несколько инстансов + SO_REUSEPORT)
```

---

## HAProxy конфиг (v0.1)

```
# /etc/haproxy/haproxy.cfg

global
    maxconn 100000
    log /dev/log local0
    stats socket /run/haproxy/admin.sock mode 660 level admin

defaults
    mode tcp
    timeout connect 3s
    timeout client  30s
    timeout server  30s
    option tcplog

# ── Входящие игроки (от edge нод) ──
frontend minecraft_in
    bind *:25565
    mode tcp

    # Принимаем только от наших edge нод
    acl is_edge_ip src 10.0.100.0/24
    tcp-request connection reject if !is_edge_ip

    default_backend velocity_pool

# ── Velocity кластер ──
backend velocity_pool
    mode tcp
    balance leastconn           # наименьшее число активных соединений
    option tcp-check            # проверяем что порт открыт

    # check inter 3s - проверяем каждые 3 сек
    # rise 2  - нужно 2 успеха чтобы считать живым
    # fall 3  - 3 неудачи → выводим из ротации
    server vel1  10.0.0.2:25565 check inter 3s rise 2 fall 3
    server vel2  10.0.0.3:25565 check inter 3s rise 2 fall 3
    server vel3  10.0.0.4:25565 check inter 3s rise 2 fall 3
    # ... до vel20

# ── Stats страница (для Prometheus) ──
frontend stats
    bind 10.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:${HAPROXY_STATS_PASS}
```

## HAProxy + keepalived (устраняет SPOF)

```
# Два HAProxy сервера, один активный (MASTER), второй резервный (BACKUP)
# Виртуальный IP переключается автоматически при падении MASTER

# /etc/keepalived/keepalived.conf (на MASTER)
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100                # MASTER имеет высший приоритет

    authentication {
        auth_type PASS
        auth_pass rampart
    }

    virtual_ipaddress {
        10.0.0.1/24             # виртуальный IP, на него смотрят edge ноды
    }

    notify_master "/etc/keepalived/notify.sh MASTER"
    notify_backup "/etc/keepalived/notify.sh BACKUP"
}

# На BACKUP: state BACKUP, priority 90
```

---

## Свой Rust Load Balancer (v0.4)

### Преимущества

```
✓ Нет SPOF - несколько инстансов на разных машинах
✓ SO_REUSEPORT - линейный scale по CPU
✓ MC-aware health check (не просто TCP, а настоящий MC ping)
✓ Hot reload без рестарта (добавить/убрать Velocity)
✓ Нативная интеграция с Redis/NATS
✓ Метрики в формате Prometheus из коробки
```

### MC-aware Health Check

```rust
// Не просто TCP connect, а настоящий MC Status ping
async fn check_velocity_health(addr: &SocketAddr) -> bool {
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(addr)
    ).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    // Шлём MC Handshake (next_state=1, status ping)
    let handshake = build_mc_handshake("health.check", addr.port(), 1);
    if stream.write_all(&handshake).await.is_err() { return false; }

    // Шлём Status Request (0x00)
    let status_req = vec![0x01, 0x00];
    if stream.write_all(&status_req).await.is_err() { return false; }

    // Ждём Status Response
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 5 => true,
        _ => false,
    }
}
```

### Hot Reload

```rust
pub struct RustLoadBalancer {
    backends: Arc<ArcSwap<Vec<Backend>>>,  // ArcSwap - lock-free swap
}

impl RustLoadBalancer {
    // Атомарная замена списка бэкендов - без блокировки
    pub async fn reload(&self, new_backends: Vec<Backend>) {
        self.backends.store(Arc::new(new_backends));
        // Текущие соединения не прерываются
        // Новые соединения идут по новому списку
    }
}

// ArcSwap из crates.io: arc-swap = "1"
```

### Несколько инстансов без SPOF

```
# На трёх разных машинах запускаем Rust LB
# Edge ноды видят все три через DNS round-robin или BGP anycast

DNS:
  lb.internal A → 10.0.0.10  (LB1)
  lb.internal A → 10.0.0.11  (LB2)
  lb.internal A → 10.0.0.12  (LB3)

Если LB1 упал:
  DNS TTL = 10 сек → edge ноды переключаются на LB2/LB3
  Без keepalived, без VRRP, без единой точки отказа
```
