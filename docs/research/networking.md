# Networking - WireGuard, BGP Anycast, QUIC, MTU

> Актуально: v0.1+ (WireGuard), v0.5+ (BGP), v0.4+ (QUIC)

---

## WireGuard - hub-and-spoke (v0.1-v0.3)

### Адресация

```
10.0.0.1      Manager + Redis + NATS (главный дедик)
10.0.0.2-21   Velocity 1-20
10.0.1.1-100  Hub 1-100
10.0.2.x      Survival серверы
10.0.3.x      Skyblock серверы
10.0.100.x    Edge ноды (EU, US, AS...)
```

### Конфиг Manager ноды (Hub)

```ini
# /etc/wireguard/wg0.conf

[Interface]
Address    = 10.0.0.1/16
PrivateKey = <MANAGER_PRIVATE_KEY>
ListenPort = 51820

# Edge нода EU
[Peer]
PublicKey  = <EDGE_EU_PUBLIC_KEY>
AllowedIPs = 10.0.100.1/32

# Edge нода US
[Peer]
PublicKey  = <EDGE_US_PUBLIC_KEY>
AllowedIPs = 10.0.100.2/32

# Velocity 1
[Peer]
PublicKey  = <VEL1_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32

# Hub 1
[Peer]
PublicKey  = <HUB1_PUBLIC_KEY>
AllowedIPs = 10.0.1.1/32

# ... и так для каждой ноды
```

### Конфиг Spoke ноды (edge, velocity, hub, game server)

```ini
# /etc/wireguard/wg0.conf на любой spoke ноде

[Interface]
Address    = 10.0.100.1/32      # свой адрес в mesh
PrivateKey = <THIS_NODE_PRIVATE_KEY>

# Только один пир - Manager (Hub)
[Peer]
PublicKey    = <MANAGER_PUBLIC_KEY>
Endpoint     = <MANAGER_PUBLIC_IP>:51820
AllowedIPs   = 10.0.0.0/16     # весь internal диапазон через hub
PersistentKeepalive = 25        # держим туннель через NAT
```

### Авто-генерация конфигов через CLI

```bash
# rampart CLI генерирует wg конфиги для всех нод

rampart wg init --network 10.0.0.0/16 --hub 185.200.100.1
rampart wg add-node --role edge --name edge-eu-1 --public-ip 45.200.10.1
rampart wg add-node --role velocity --name vel-1
rampart wg add-node --role hub --name hub-1

# Генерирует файлы:
# wg-configs/edge-eu-1/wg0.conf
# wg-configs/vel-1/wg0.conf
# ...

# Деплой на ноду
scp wg-configs/edge-eu-1/wg0.conf root@45.200.10.1:/etc/wireguard/
ssh root@45.200.10.1 'systemctl enable --now wg-quick@wg0'
```

---

## MTU - важный нюанс

```
Стандартный MTU Ethernet:  1500 байт
WireGuard overhead:         ~80 байт (заголовок + шифрование)
Effective MTU в WG туннеле: 1420 байт

Если Minecraft пакет > 1420 байт → фрагментация → производительность падает.

Minecraft пакеты:
  Handshake:     ~50-300 байт ✅ (безопасно)
  LoginStart:    ~30-50 байт ✅
  Chunk Data:    может быть > 1420 байт ⚠️

Для chunk data: MC клиент и сервер обрабатывают фрагментацию на уровне TCP.
Для нашего edge проксирования: мы просто туннелируем TCP стрим,
фрагментация прозрачна. Проблем нет.

Настройка MTU:
```

```ini
# /etc/wireguard/wg0.conf
[Interface]
MTU = 1420    # явно указываем чтобы не было auto-discovery проблем
```

---

## Firewall - полный набор правил

```bash
#!/bin/bash
# /etc/rampart/firewall.sh

# ── Edge нода ──
setup_edge_firewall() {
    iptables -F INPUT
    iptables -F FORWARD
    iptables -P INPUT DROP
    iptables -P FORWARD DROP

    # Localhost
    iptables -A INPUT -i lo -j ACCEPT

    # Established соединения
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # WireGuard
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT

    # Minecraft от всех (мы принимаем атаки здесь и фильтруем)
    iptables -A INPUT -p tcp --dport 25565 -j ACCEPT

    # SSH (только с нашего IP управления)
    iptables -A INPUT -p tcp --dport 22 -s ${MGMT_IP} -j ACCEPT

    # Prometheus от Manager
    iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.1 -j ACCEPT

    # HAProxy stats (для Prometheus)
    iptables -A INPUT -p tcp --dport 8404 -s 10.0.0.0/16 -j ACCEPT

    # Всё остальное - дроп
    iptables -A INPUT -j DROP
}

# ── Velocity / HAProxy нода ──
setup_backend_firewall() {
    iptables -F INPUT
    iptables -P INPUT DROP

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # WireGuard
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT

    # Minecraft только от edge нод через WireGuard
    iptables -A INPUT -i wg0 -p tcp --dport 25565 -s 10.0.100.0/24 -j ACCEPT

    # SSH
    iptables -A INPUT -p tcp --dport 22 -s ${MGMT_IP} -j ACCEPT

    # Prometheus сервисы (внутри WG)
    iptables -A INPUT -p tcp --dport 9091 -s 10.0.0.0/16 -j ACCEPT

    iptables -A INPUT -j DROP
}

# ── Game сервер ──
setup_game_firewall() {
    iptables -F INPUT
    iptables -P INPUT DROP

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # WireGuard
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT

    # Minecraft только от Velocity нод
    iptables -A INPUT -i wg0 -p tcp --dport 25565 -s 10.0.0.2/28 -j ACCEPT

    # SSH
    iptables -A INPUT -p tcp --dport 22 -s ${MGMT_IP} -j ACCEPT

    # Prometheus метрики Paper
    iptables -A INPUT -p tcp --dport 9092 -s 10.0.0.0/16 -j ACCEPT

    iptables -A INPUT -j DROP
}
```

```

---

## QUIC - канал Edge ↔ Manager (v0.4+)

### Зачем для управляющего канала

```
TCP проблема: Head-of-line blocking
  Большой blacklist update → блокирует heartbeat → edge думает что manager упал

QUIC решение: независимые streams
  Stream 0: heartbeat (5 сек)        - не блокируется
  Stream 1: blacklist updates (push)  - независимо
  Stream 2: metrics (1 сек)          - независимо
  Stream 3: команды (drain/reload)   - независимо

+ 0-RTT reconnect после разрыва (важно для мобильных VDS с нестабильным uplink)
+ Встроенный TLS 1.3 (не нужен отдельный слой)
```

### Реализация (quinn)

```toml
[dependencies]
quinn = "0.11"
```

```rust
// manager/src/quic.rs

pub async fn start_quic_server(config: Arc<Config>) -> Result<()> {
    let tls = build_quic_server_tls(&config.tls);
    let endpoint = quinn::Endpoint::server(tls, "0.0.0.0:7777".parse()?)?;

    while let Some(incoming) = endpoint.accept().await {
        let conn = incoming.await?;

        // Получаем identity подключившейся edge ноды из сертификата
        let node_id = extract_node_id(&conn);
        tokio::spawn(handle_edge(conn, node_id));
    }
    Ok(())
}

async fn handle_edge(conn: quinn::Connection, node_id: String) {
    // Открываем исходящие streams для push уведомлений
    let blacklist_tx = conn.open_uni().await.unwrap();

    // Слушаем входящие streams (heartbeat, metrics)
    loop {
        match conn.accept_bi().await {
            Ok((tx, rx)) => {
                tokio::spawn(handle_stream(tx, rx, node_id.clone()));
            }
            Err(_) => {
                tracing::warn!("Edge нода {} отключилась", node_id);
                break;
            }
        }
    }
}
```

---

## BGP Anycast (v0.6+)

> Только если проект вырастет до 10+ edge нод и нужен настоящий anycast.

### Что нужно

```
1. Свой AS номер - получить через RIPE NCC (Европа) или ARIN (США)
   Стоимость: ~500€/год членский взнос в RIPE
   Плюс: купить через LIR (Local Internet Registry) - дешевле

2. Своя /24 подсеть - 256 IP адресов
   Получить вместе с AS через RIPE
   Стоимость: включено в RIPE членство

3. VDS с поддержкой BGP сессий
   Vultr, Hetzner (не все локации), Leaseweb, OVH Premium
   Проверять явно: "BGP sessions supported"

4. FRRouting на каждой edge ноде
```

### FRRouting конфиг

```ini
# /etc/frr/frr.conf на edge ноде

router bgp 65001
  bgp router-id 185.200.100.1
  
  # BGP сессия с upstream провайдером
  neighbor 149.248.2.1 remote-as 20473
  neighbor 149.248.2.1 description "Vultr upstream"
  
  address-family ipv4 unicast
    # Анонсируем свою подсеть с этой edge ноды
    network 185.200.100.0/24
    
    # NO_EXPORT - не распространяем анонс дальше (только к upstream)
    neighbor 149.248.2.1 route-map SET_COMMUNITY out
  exit-address-family

route-map SET_COMMUNITY permit 10
  set community no-export

! Когда edge нода падает - FRRouting перестаёт анонсировать
! BGP withdraw → трафик автоматически идёт на другую ноду
! Время failover: ~30-60 сек (BGP convergence)
```

### Как это работает

```
play.server.com → 185.200.100.1  (один IP, твоя подсеть)

Игрок из Европы:
  BGP → ближайшая нода которая анонсирует 185.200.100.0/24 → edge-eu-1

Игрок из США:
  BGP → ближайшая нода → edge-us-1

edge-eu-1 упала → FRRouting делает withdraw →
  Европейский трафик → автоматически → edge-us-1 или edge-as-1
  Время: 30-60 сек
```
