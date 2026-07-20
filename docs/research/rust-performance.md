# Rust Performance - Zero-Copy, SO_REUSEPORT, NUMA

> Актуально: v0.3+

---

## Zero-Copy проксирование

```
Обычный proxy (2 копии):
  NIC → kernel buf → copy → userspace buf → copy → kernel buf → NIC

splice(2) zero-copy (0 копий в userspace):
  NIC → kernel pipe → NIC
  Данные никогда не покидают kernel
```

### Когда применять

```
Handshake фаза  → обычный read() (нужно видеть байты, парсить, ставить HMAC)
После handshake → zero-copy splice (просто проксируем стрим)
```

```rust
// src/proxy/tunnel.rs
use tokio_splice::zero_copy_bidirectional;

pub async fn tunnel(mut client: TcpStream, mut backend: TcpStream) {
    // После того как handshake прочитан и HMAC добавлен -
    // всё остальное идёт через splice(2) без копий в userspace
    let _ = zero_copy_bidirectional(&mut client, &mut backend).await;
}
```

---

## SO_REUSEPORT - линейный scale по CPU

```rust
// main.rs - N воркеров, каждый слушает тот же порт
// Ядро само балансирует входящие SYN между воркерами

use socket2::{Domain, Socket, Type};

fn build_listener(addr: SocketAddr) -> TcpListener {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    socket.set_reuse_port(true).unwrap();   // SO_REUSEPORT
    socket.set_reuse_address(true).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket.bind(&addr.into()).unwrap();
    socket.listen(65535).unwrap();
    TcpListener::from_std(socket.into()).unwrap()
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = "0.0.0.0:25565".parse().unwrap();
    let cpus = num_cpus::get();

    let handles: Vec<_> = (0..cpus)
        .map(|_| tokio::spawn(accept_loop(build_listener(addr))))
        .collect();

    futures::future::join_all(handles).await;
}
```

### Ожидаемый прирост

| Ядра | Без SO_REUSEPORT | С SO_REUSEPORT |
|---|---|---|
| 1 | 20k conn/s | 20k conn/s |
| 4 | 22k conn/s | 78k conn/s |
| 8 | 23k conn/s | 155k conn/s |

---

## Buffer Pool - без heap allocation на каждый пакет

```rust
// src/pool.rs - пул буферов, переиспользуем вместо Vec::new()
// ⚠ ВАЖНО: tokio::sync::Mutex блокирует async runtime в hot path.
// Используем crossbeam::ArrayQueue - lock-free, не блокирует.

use crossbeam::queue::ArrayQueue;
use std::sync::Arc;

pub struct BufferPool {
    pool: Arc<ArrayQueue<Vec<u8>>>,
    buf_size: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, buf_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            pool.push(vec![0u8; buf_size]).ok();
        }
        Self { pool: Arc::new(pool), buf_size }
    }

    // Не async! Не блокирует runtime.
    pub fn acquire(&self) -> Vec<u8> {
        self.pool.pop().unwrap_or_else(|| vec![0u8; self.buf_size])
    }

    // Не async! Не блокирует runtime.
    pub fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
        let _ = self.pool.push(buf); // игнорируем если полон
    }
}
```

---

## DashMap - lock-free concurrent HashMap

```rust
// Блэклист и rate limit - читаются на каждый пакет
// RwLock<HashMap> создаёт contention под нагрузкой
// DashMap решает это через шарды

use dashmap::DashMap;

pub struct Blacklist {
    // 64 шарда, каждый со своим RwLock
    // Разные IP попадают в разные шарды → нет contention
    ips: DashMap<Ipv4Addr, BanEntry>,
}

impl Blacklist {
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        if let Some(entry) = self.ips.get(&ip) {
            if entry.expires > Instant::now() {
                return true;
            }
            drop(entry);
            self.ips.remove(&ip); // expired
        }
        false
    }
}
```

---

## io_uring - async I/O нового поколения (v0.4+, future optimization)

> Текущий код на tokio (epoll). io_uring - future optimization для edge нод.

### epoll vs io_uring

```
epoll (tokio сейчас):
  read() → syscall → копирование в userspace buf → возврат
  На каждую операцию: минимум 1 syscall + 1 копия

io_uring:
  Кладём запросы в submission queue (shared memory)
  Ядро обрабатывает батчем, результаты в completion queue
  Нет syscall per operation (только sq_enter раз в батч)
  Нет копирования (registered buffers)
```

### Когда разница заметна

```
10k соединений:  epoll ≈ io_uring (разница < 5%)
100k соединений: io_uring +15-20%
1M соединений:   io_uring +35-40%
```

### Рантаймы сравнение

| Рантайм | Базируется на | Когда использовать |
|---|---|---|
| **tokio** (текущий) | epoll | v0.1-v0.3, универсально |
| **tokio-uring** | io_uring | v0.4+, Linux only |
| **glommio** | io_uring, thread-per-core | v0.5+, высокая изоляция |
| **monoio** | io_uring, Tencent | v0.6+, максимальная пропускная способность |

### Реализация через feature flag

```toml
# Cargo.toml
[features]
default = []
io-uring = ["dep:tokio-uring"]

[dependencies]
tokio        = { version = "1", features = ["full"] }
tokio-uring  = { version = "0.5", optional = true }
```

```rust
// src/runtime.rs
pub fn run(config: Config) {
    #[cfg(feature = "io-uring")]
    {
        tracing::info!("Запуск с io_uring runtime");
        tokio_uring::start(async { crate::edge::run(config).await });
    }

    #[cfg(not(feature = "io-uring"))]
    {
        tracing::info!("Запуск с epoll (tokio)");
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_cpus::get())
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::edge::run(config));
    }
}
```

```bash
# Обычная сборка (epoll, работает везде)
cargo build --release

# С io_uring (Linux 5.10+)
cargo build --release --features io-uring
```

### Registered Buffers

```rust
// Регистрируем буферы один раз в ядре
// Потом read/write используют эти буферы без копирования
use tokio_uring::buf::IoBuf;

let buffers: Vec<Vec<u8>> = (0..1024)
    .map(|_| vec![0u8; 4096])
    .collect();

// io_uring читает прямо в зарегистрированный буфер
// Нет copy_to_user, нет дополнительной аллокации
let (result, buf) = stream.read(buf).await;
```

### Ограничения io_uring

```
✗ Только Linux (macOS/Windows → epoll fallback)
✗ Требует kernel 5.10+ (stable features)
✗ Некоторые VDS провайдеры блокируют io_uring
  (проверь: cat /proc/sys/kernel/io_uring_disabled)
```

---

## NUMA-aware allocation (для 2-сокетных серверов)

> Актуально для bare metal с 2 физическими CPU (NUMA topology)

```rust
// Привязываем воркеры к NUMA нодам
// Память аллоцируется близко к CPU который её использует

use nix::sched::{sched_setaffinity, CpuSet};

fn pin_to_numa_node(worker_id: usize, numa_node: usize) {
    let mut cpuset = CpuSet::new();
    // NUMA node 0: CPU 0-7, NUMA node 1: CPU 8-15 (пример)
    let cpu_start = numa_node * 8;
    let cpu_for_worker = cpu_start + (worker_id % 8);
    cpuset.set(cpu_for_worker).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpuset).unwrap();
}
```

Для обычных VDS (1 NUMA нода) - не нужно.

---

## Profiling в production

```bash
# tokio-console - live view async tasks
# Запускаем edge с поддержкой tokio-console
TOKIO_CONSOLE_BIND=10.0.100.1:6669 ./rampart-edge

# На своей машине
tokio-console http://10.0.100.1:6669

# Parca - continuous profiling (CPU flame graphs)
docker run -p 7070:7070 ghcr.io/parca-dev/parca:latest
# Смотрим в браузере: http://localhost:7070

# perf (Linux)
perf record -g -p $(pgrep rampart-edge) -- sleep 30
perf report --stdio | head -50

# Flamegraph
cargo flamegraph --bin rampart-edge
```

---

## Сводная таблица оптимизаций

| Техника | Прирост | Версия | Сложность |
|---|---|---|---|
| SO_REUSEPORT | 4x на 4 ядрах | v0.1 | Низкая |
| DashMap вместо RwLock | 2x при contention | v0.1 | Низкая |
| Buffer pool | -30% alloc | v0.2 | Средняя |
| Zero-copy splice | -50% CPU на трафик | v0.2 | Средняя |
| io_uring | +30-40% conn/s | v0.4 | Высокая |
| XDP | 10x дроп rate | v0.4 | Высокая |
| NUMA pinning | +10-20% на 2P сервере | v0.6 | Высокая |
