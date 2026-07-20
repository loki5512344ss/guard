# eBPF / XDP - Фильтрация уровня ядра

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

| Метод | Задержка дропа | CPU на 5M pps | Требует |
|---|---|---|---|
| iptables | ~10 мкс | ~80% | - |
| nftables | ~8 мкс | ~70% | - |
| Rust userspace | ~5 мкс | ~50% | - |
| **XDP (generic)** | ~2 мкс | ~30% | любой kernel |
| **XDP (native)** | ~0.5 мкс | ~15% | поддержка в драйвере NIC |
| **XDP (offload)** | ~0.1 мкс | ~0% | SmartNIC |

Для большинства VDS - native XDP (Intel i40e, Mellanox ConnectX).

---

## Граница ответственности (критично)

```
XDP МОЖЕТ:                          XDP НЕ МОЖЕТ:
  IP блэклист (LPM_TRIE)             HMAC-SHA256 (нет floating point < kernel 6.x)
  SYN flood rate limit               GeoIP lookup (нет heap allocation)
  Invalid TCP flags drop             DNS resolve
  UDP drop (MC = TCP only)           Сложные строковые операции
  Port whitelist                     Вызов userspace функций
  Per-IP packet rate                 Блокировать по hostname
  BPF map read/write                 TLS инспекция
```

Всё L7 (handshake парсинг, HMAC, hostname проверка) - **только в Rust userspace**.

---

## Структура BPF Maps

```c
// maps.h

// Блэклист IP (LPM - Longest Prefix Match, поддерживает CIDR)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct lpm_key);    // prefixlen + ip
    __type(value, __u64);           // timestamp бана
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist_map SEC(".maps");

// Rate limit per IP (LRU - автоматически вытесняет старые)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 500000);
    __type(key, __u32);             // src IP
    __type(value, struct rate_entry);
} rate_map SEC(".maps");

// Whitelist доверенных IP (edge нод например)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u8);            // просто флаг
} trusted_map SEC(".maps");

// Статистика (для Prometheus)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);             // индекс счётчика
    __type(value, __u64);
} stats_map SEC(".maps");

// Ringbuf для передачи событий в userspace (быстрее perfbuf)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");
```

---

## XDP программа (C)

```c
// xdp_filter.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

#define MC_PORT 25565
#define RATE_LIMIT_PPS 20       // пакетов/сек с одного IP
#define BAN_DURATION_NS 60000000000ULL  // 60 сек

// Статистические индексы
#define STAT_TOTAL    0
#define STAT_BLOCKED  1
#define STAT_RATELIM  2

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int minecraft_xdp_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    // ── Парсим Ethernet ──
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // ── Парсим IP ──
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS; // UDP → дроп неявный (MC=TCP)

    __u32 src_ip = ip->saddr;

    // ── Whitelist (наши edge ноды, manager) ──
    if (bpf_map_lookup_elem(&trusted_map, &src_ip)) return XDP_PASS;

    // ── Парсим TCP ──
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    if (tcp->dest != bpf_htons(MC_PORT)) return XDP_PASS;

    // ── Блэклист проверка ──
    struct lpm_key key = { .prefixlen = 32, .ip = src_ip };
    __u64 *ban_ts = bpf_map_lookup_elem(&blacklist_map, &key);
    if (ban_ts) {
        __u64 now = bpf_ktime_get_ns();
        if (now - *ban_ts < BAN_DURATION_NS) {
            inc_stat(STAT_BLOCKED);
            return XDP_DROP;
        }
        bpf_map_delete_elem(&blacklist_map, &key);
    }

    // ── Invalid TCP flags ──
    // Дропаем пакеты с мусорными флагами (не SYN, не ACK, не PSH+ACK)
    __u8 flags = ((__u8 *)tcp)[13];
    if ((flags & 0x3F) == 0) { // нет флагов вообще
        inc_stat(STAT_BLOCKED);
        return XDP_DROP;
    }

    // ── SYN rate limit ──
    if (tcp->syn && !tcp->ack) {
        struct rate_entry *entry = bpf_map_lookup_elem(&rate_map, &src_ip);
        __u64 now = bpf_ktime_get_ns();

        if (entry) {
            // Простой sliding window
            if (now - entry->window_start < 1000000000ULL) { // 1 сек
                if (entry->count >= RATE_LIMIT_PPS) {
                    // Баним
                    __u64 ban_ts = now;
                    bpf_map_update_elem(&blacklist_map, &key, &ban_ts, BPF_ANY);
                    inc_stat(STAT_RATELIM);
                    inc_stat(STAT_BLOCKED);
                    return XDP_DROP;
                }
                __sync_fetch_and_add(&entry->count, 1);
            } else {
                // Новое окно
                entry->window_start = now;
                entry->count = 1;
            }
        } else {
            struct rate_entry new_entry = { .window_start = now, .count = 1 };
            bpf_map_update_elem(&rate_map, &src_ip, &new_entry, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

## Rust loader (libbpf-rs)

```rust
// xdp/loader.rs

use libbpf_rs::{MapFlags, Object, ObjectBuilder};

pub struct XdpFilter {
    obj: Object,
    interface: String,
}

impl XdpFilter {
    pub fn load(interface: &str) -> Result<Self> {
        let obj = ObjectBuilder::default()
            .open_file("/etc/rampart/xdp_filter.o")?
            .load()?;

        // Аттачим XDP программу к интерфейсу
        let prog = obj.prog("minecraft_xdp_filter").unwrap();
        prog.attach_xdp(if_nametoindex(interface)?)?;

        Ok(Self { obj, interface: interface.to_string() })
    }

    // Добавляем IP в блэклист из Rust (обновляем BPF map)
    pub fn ban_ip(&self, ip: Ipv4Addr, duration: Duration) {
        let mut map = self.obj.map("blacklist_map").unwrap();
        let key = LpmKey::new(32, ip);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        map.update(&key.to_bytes(), &ts.to_le_bytes(), MapFlags::ANY).unwrap();
    }

    // Читаем статистику
    pub fn get_stats(&self) -> XdpStats {
        let map = self.obj.map("stats_map").unwrap();
        XdpStats {
            total:    read_percpu_sum(&map, 0),
            blocked:  read_percpu_sum(&map, 1),
            ratelim:  read_percpu_sum(&map, 2),
        }
    }

    // Читаем события из ringbuf (атаки, баны)
    pub async fn read_events(&self, tx: mpsc::Sender<XdpEvent>) {
        let mut ringbuf = RingBuffer::new();
        ringbuf.add(self.obj.map("events").unwrap(), move |data| {
            let event: XdpEvent = unsafe { *(data.as_ptr() as *const XdpEvent) };
            let _ = tx.try_send(event);
            0
        }).unwrap();

        loop {
            ringbuf.poll(Duration::from_millis(10)).unwrap();
        }
    }
}
```

---

## Cargo.toml для XDP компонента

```toml
[dependencies]
libbpf-rs = "0.23"
libbpf-sys = "1.4"

[build-dependencies]
libbpf-cargo = "0.23"   # автокомпиляция .c → .o в build.rs
```

```rust
// build.rs
use libbpf_cargo::SkeletonBuilder;

fn main() {
    SkeletonBuilder::new()
        .source("src/bpf/xdp_filter.c")
        .build_and_generate("src/bpf/xdp_filter.skel.rs")
        .unwrap();
}
```

---

## Требования к окружению

```bash
# Проверка что XDP поддерживается
ethtool -i eth0 | grep driver  # должен быть i40e, mlx5, или virtio

# Проверка типа виртуализации
systemd-detect-virt
# kvm → XDP работает (native или generic)
# none → bare metal → XDP native
# openvz / lxc → XDP НЕ работает

# Проверка версии ядра
uname -r
# >= 5.10 - достаточно для нашего XDP
# >= 6.0  - полный функционал (float в eBPF, CO-RE стабильный)

# Установка зависимостей (Ubuntu 22.04+)
apt-get install -y libbpf-dev clang llvm linux-headers-$(uname -r)
```

---

## ringbuf vs perfbuf

| | perfbuf | ringbuf (kernel 5.8+) |
|---|---|---|
| Тип | Per-CPU кольцевой буфер | Один разделяемый буфер |
| Копирование | Одно | Одно |
| Порядок событий | Не гарантирован | Гарантирован |
| Потребление памяти | Per-CPU | Меньше |
| **Вывод** | Устаревший | **Используй ringbuf** |

---

## Известные лимиты BPF verifier

```
Максимум инструкций:    1M (kernel 5.2+, раньше 4096)
Максимум стека:         512 байт
Максимум вложенности:   8 уровней (loops разрешены с 5.3+)
Циклы:                  разрешены, но верификатор считает итерации
Динамический allocation: нет (только BPF maps)
```

Если программа не проходит верификатор - упрости логику или разбей на несколько программ в цепочке (TC + XDP).
