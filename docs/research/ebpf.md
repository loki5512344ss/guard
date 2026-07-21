# eBPF / XDP — Rampart XDP слой

> Актуально: v0.4+
> Требует: Linux kernel 5.10+, KVM или Bare Metal (не OpenVZ/LXC)

---

## Почему XDP

```
Обычный путь пакета (без XDP):
  NIC → driver → kernel TCP stack → socket buffer → userspace → решение

XDP путь:
  NIC driver → XDP_DROP (ещё до kernel stack)
  Никаких аллокаций, никаких копий, никаких syscall
```

| Метод | Задержка дропа | CPU на 5M pps |
|-------|---------------|---------------|
| iptables | ~10 мкс | ~80% |
| nftables | ~8 мкс | ~70% |
| Rust userspace | ~5 мкс | ~50% |
| **XDP (generic)** | ~2 мкс | ~30% |
| **XDP (native)** | ~0.5 мкс | ~15% |
| **XDP (offload)** | ~0.1 мкс | ~0% |

---

## TCP State Machine

Rampart использует stateful подход из Minecraft-XDP-eBPF, с исправлениями:

```
                   ┌──────────┐
                   │  SYN     │
                   │ received │
                   └────┬─────┘
                        │
                   ┌────▼─────┐
         ┌────────►│AWAIT_ACK │◄─────────┐
         │         │ (SYN-ACK │          │
         │         │  sent)   │          │
         │         └────┬─────┘          │
         │              │ ACK received   │
         │         ┌────▼──────────┐     │
         │         │AWAIT_MC_      │     │ retransmit
         │         │HANDSHAKE      ├─────┘ (если pure ACK)
         │         └────┬──────────┘
         │              │ MC handshake
         │         ┌────▼──────────┐
         │         │AWAIT_LOGIN    │
         │         └────┬──────────┘
         │              │ LoginStart
         │         ┌────▼──────────┐     ┌──────────────┐
         │         │  VERIFIED     │────►│Idle bpf_timer│
         │         └────┬──────────┘     │ (60 sec)     │
         │              │                └──────┬───────┘
         │         ┌────▼──────────┐            │ timeout
         │         │  PING_SENT    │            │
         │         └────┬──────────┘     ┌──────▼───────┐
         │              │                │  ENTRY_DELETED│
         │         ┌────▼──────────┐     └──────────────┘
         │         │PING_COMPLETE  │
         │         └────┬──────────┘
         │              │
         │         ┌────▼──────────┐
         └─────────┤  CONN_DROP    │
                   │  (RST/FIN)    │
                   └───────────────┘
```

## Исправления относительно Minecraft-XDP-eBPF

### 1. Pure ACK deadlock (критический баг в MC-XDP-eBPF)

```
Оригинал (MC-XDP-eBPF):
  AWAIT_ACK → pure ACK → DROP + переход в AWAIT_MC_HANDSHAKE
  → сервер не видит ACK → retransmit SYN-ACK → ~1-7 сек лага

Наш фикс:
  AWAIT_ACK → pure ACK → PASS + переход в AWAIT_MC_HANDSHAKE
  → сервер видит ACK → TCP handshake завершён нормально
```

```c
// ОРИГИНАЛ (сломан):
if (state == AWAIT_ACK) {
    initial_state->state = state = AWAIT_MC_HANDSHAKE;
    if (tcp_payload >= tcp_payload_end) {
        goto drop;  // Pure ACK dropped → DEADLOCK
    }
}

// ИСПРАВЛЕНИЕ:
if (state == AWAIT_ACK) {
    initial_state->state = state = AWAIT_MC_HANDSHAKE;
    if (tcp_payload >= tcp_payload_end) {
        return XDP_PASS;  // Pure ACK passed → handshake ok
    }
}
```

### 2. Stale conntrack на RST/FIN

```c
// В AWAIT_MC_HANDSHAKE — RST/FIN должен чистить entry:
if ((tcp->fin || tcp->rst) && state != AWAIT_ACK) {
    bpf_map_delete_elem(&conntrack_map, &flow_key);
    return XDP_PASS;
}
```

### 3. Player map LRU

```c
// Оригинал: BPF_MAP_TYPE_HASH (plain) — при заполнении дропает новых игроков
// Исправление:
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct player_entry);
} player_connection_map SEC(".maps");
```

### 4. Idle timer на conntrack (не только на player)

```c
// Добавить bpf_timer в conntrack entry:
struct conntrack_entry {
    __u32 state;
    __u32 expected_seq;
    __u32 src_ip;
    __u16 src_port;
    __u8 fails;
    struct bpf_timer timer;  // 30 sec idle timeout
};
```

### 5. IPv6 support

```c
// Оригинал: return XDP_PASS for non-IP (IPv6 bypass)
// Исправление:
if (eth->h_proto != bpf_htons(ETH_P_IP)
    && eth->h_proto != bpf_htons(ETH_P_IPV6)) {
    return XDP_PASS;
}

// Отдельный flow key для IPv6:
struct flow_key_v6 {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
};
```

### 6. IP/CIDR whitelist (issue #42 из MC-XDP-eBPF)

```c
struct whitelist_key {
    __u32 prefixlen;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __type(key, struct whitelist_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_map SEC(".maps");
```

---

## BPF Maps

```c
// ── Blacklist (LPM_TRIE для CIDR) ──
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct lpm_key);
    __type(value, __u64);       // timestamp ban
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_map SEC(".maps");

// ── Whitelist (LPM_TRIE для CIDR) ──
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist_map SEC(".maps");

// ── Conntrack (unverified connections, LRU) ──
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct conntrack_entry);
} conntrack_map SEC(".maps");

// ── Verified players (LRU) ──
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct player_entry);
} player_connection_map SEC(".maps");

// ── SYN throttle per-IP ──
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);         // src IP
    __type(value, struct throttle_entry);
} connection_throttle SEC(".maps");

// ── Statistics (per-CPU, для Prometheus) ──
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");
```

---

## Граница XDP / Rust

```
XDP делает (L3/L4):                      Rust делает (L7):
  TCP state machine                       PoW Challenge (SHA256)
  SYN throttle per-IP                    MC handshake парсинг
  IP blacklist (LPM_TRIE)                HMAC sign/verify
  IP whitelist (CIDR)                    Rate limit per-IP
  Invalid TCP flags drop                 Death code auto-ban
  UDP drop                               GeoIP/ASN reputation
  Per-connection seq tracking            Blacklist (сложные правила)
  bpf_timer idle cleanup                 Reassembly буфер
```

XDP **не может** (даже в kernel 6.x):
- SHA256 (нет heap, нет looping на достаточное время)
- Floating point (ограничен)
- Сложные строковые операции
- TLS инспекция
- GeoIP / DNS resolve

---

## Загрузка (Rust + libbpf-rs)

```rust
use libbpf_rs::{MapFlags, ObjectBuilder};

pub struct RampartXdp {
    obj: Object,
    interface: String,
}

impl RampartXdp {
    pub fn load(interface: &str) -> Result<Self> {
        let obj = ObjectBuilder::default()
            .open_file("/etc/rampart/xdp_filter.o")?
            .load()?;

        let prog = obj.prog("rampart_xdp_filter").unwrap();
        prog.attach_xdp(if_nametoindex(interface)?)?;
        Ok(Self { obj, interface: interface.to_string() })
    }

    pub fn ban_ip(&self, ip: Ipv4Addr, duration: Duration) {
        let mut map = self.obj.map("blacklist_map").unwrap();
        let key = LpmKey::new(32, ip);
        let ts = now_nanos() + duration.as_nanos() as u64;
        map.update(&key.to_bytes(), &ts.to_le_bytes(), MapFlags::ANY).unwrap();
    }

    pub fn get_stats(&self) -> XdpStats {
        XdpStats {
            total:    self.read_percpu_sum("stats_map", 0),
            passed:   self.read_percpu_sum("stats_map", 1),
            blocked:  self.read_percpu_sum("stats_map", 2),
            ratelimit: self.read_percpu_sum("stats_map", 3),
        }
    }
}
```

---

## Требования

```bash
# Проверка XDP
ethtool -i eth0 | grep driver  # i40e, mlx5, virtio

# Тип виртуализации
systemd-detect-virt  # kvm/none = XDP, openvz/lxc = нет

# Версия ядра
uname -r  # >= 5.10

# Зависимости
apt-get install -y libbpf-dev clang llvm linux-headers-$(uname -r)
```

## ringbuf (вместо perfbuf)

| | perfbuf | ringbuf (kernel 5.8+) |
|---|---|---|
| Тип | Per-CPU | Один разделяемый |
| Копирование | Одно | Одно |
| Порядок | Не гарантирован | Гарантирован |
| Память | Per-CPU | Меньше |
| **Вывод** | Устаревший | **Используй ringbuf** |

## Лимиты BPF verifier

```
Максимум инструкций:    1M (kernel 5.2+)
Максимум стека:         512 байт
Максимум вложенности:   8
Циклы:                  разрешены с 5.3+
Dynamic alloc:          нет (только BPF maps)
```
