# io_uring - Async I/O нового поколения

> Актуально: v0.4+  
> Требует: Linux 5.10+ (стабильный), 6.0+ (полный функционал)  
> Текущий код на tokio (epoll). io_uring - future optimization.

---

## epoll vs io_uring

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

Для edge ноды с 50-200k активных соединений - заметно.
```

---

## Рантаймы сравнение

| Рантайм | Базируется на | Когда использовать |
|---|---|---|
| **tokio** (текущий) | epoll | v0.1-v0.3, универсально, стабильно |
| **tokio-uring** | io_uring | v0.4+, Linux only, edge ноды |
| **glommio** | io_uring, thread-per-core | v0.5+, высокая изоляция |
| **monoio** | io_uring, Tencent | v0.6+, максимальная пропускная способность |

> **Monoio** показывает лучшие числа на синтетических echo-бенчмарках,  
> но для L7 (handshake парсинг, HMAC) разница с tokio-uring минимальна.  
> Начинай с tokio, переходи на tokio-uring если профайлер покажет I/O bottleneck.

---

## Реализация через feature flag

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
        println!("Запуск с io_uring runtime");
        tokio_uring::start(async { crate::edge::run(config).await });
    }

    #[cfg(not(feature = "io-uring"))]
    {
        println!("Запуск с epoll (tokio)");
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

# Проверить версию ядра перед включением
uname -r  # должно быть 5.10+
```

---

## Registered Buffers (продвинутый уровень)

```rust
// Регистрируем буферы один раз в ядре
// Потом read/write используют эти буферы без копирования

use tokio_uring::buf::IoBuf;

// При старте - регистрируем пул буферов
let buffers: Vec<Vec<u8>> = (0..1024)
    .map(|_| vec![0u8; 4096])
    .collect();

// io_uring читает прямо в зарегистрированный буфер
// Нет copy_to_user, нет дополнительной аллокации
let (result, buf) = stream.read(buf).await;
```

---

## Ограничения io_uring

```
✗ Только Linux (macOS/Windows → epoll fallback)
✗ Требует kernel 5.10+ (stable features)
✗ Некоторые VDS провайдеры блокируют io_uring
  (security concerns, проверь: ls /proc/sys/kernel/io_uring_*)
✗ Не все операции имеют io_uring версии
✗ Сложнее debug (нет привычного strace для каждой операции)
```

### Проверка доступности на VDS

```bash
# Проверяем что io_uring не заблокирован
cat /proc/sys/kernel/io_uring_disabled
# 0 = разрешён, 1 = только root, 2 = запрещён

# Пробуем запустить простой io_uring тест
cargo run --example io_uring_test --features io-uring
```
