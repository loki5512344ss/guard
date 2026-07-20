# Papers & References - Материалы для изучения

> Ссылки на статьи, RFC, проекты, инструменты которые легли в основу Rampart.

---

## Minecraft протокол

| Ресурс | Зачем |
|---|---|
| [wiki.vg/Protocol](https://wiki.vg/Protocol) | Официальная неофициальная документация MC протокола. Handshake, VarInt, все пакеты. |
| [wiki.vg/Handshaking_sequence](https://wiki.vg/Handshaking_sequence) | Полная последовательность handshake → login → play |
| [Velocity источник](https://github.com/PaperMC/Velocity) | Как PaperMC парсит MC протокол в Java - референс |
| [Pumpkin-MC](https://github.com/Snowiiii/Pumpkin) | MC сервер на Rust - референс для Rust парсинга протокола |

---

## eBPF / XDP

| Ресурс | Зачем |
|---|---|
| [Outfluencer/Minecraft-XDP-eBPF](https://github.com/Outfluencer/Minecraft-XDP-eBPF) | Референс: XDP фильтр специально для Minecraft (Rust + C, 190+ stars) |
| [xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) | Лучший туториал по XDP - от простого к сложному |
| [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) | Шаблоны eBPF программ с современным подходом (skeleton, CO-RE) |
| [aya-rs/aya](https://github.com/aya-rs/aya) | Альтернатива libbpf-rs - eBPF полностью на Rust (без C) |
| [BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html) | Книга Brendan Gregg - глубокий разбор BPF/eBPF |
| [Cloudflare: XDP введение](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/) | Как Cloudflare использует XDP для DDoS mitigation |
| [Facebook: XDP at scale](https://engineering.fb.com/2018/05/22/open-source/open-sourcing-katran-a-scalable-network-load-balancer/) | Katran - XDP load balancer от Facebook |

---

## Rust networking

| Ресурс | Зачем |
|---|---|
| [tokio-rs/tokio](https://github.com/tokio-rs/tokio) | Async runtime - основа edge ноды |
| [tokio-rs/tokio-uring](https://github.com/tokio-rs/tokio-uring) | io_uring runtime для tokio |
| [bytedance/monoio](https://github.com/bytedance/monoio) | Thread-per-core io_uring runtime от ByteDance |
| [glommio](https://github.com/DataDog/glommio) | io_uring runtime от DataDog |
| [rustls](https://github.com/rustls/rustls) | TLS на Rust - для mTLS |
| [quinn-rs/quinn](https://github.com/quinn-rs/quinn) | QUIC реализация на Rust |
| [zero-copy-paxos](https://www.usenix.org/conference/osdi14/technical-sessions/presentation/ports) | Статья о zero-copy в системных сервисах |
| [Uring и io_uring (LWN)](https://lwn.net/Articles/776703/) | Детальный разбор io_uring от автора |

---

## DDoS защита и сети

| Ресурс | Зачем |
|---|---|
| [Cloudflare Blog: DDoS](https://blog.cloudflare.com/tag/ddos/) | Статьи Cloudflare о реальных атаках и защите |
| [Path.net технический блог](https://path.net/blog/) | Как устроена игровая DDoS защита |
| [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | BGP - основа Anycast маршрутизации |
| [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) | QUIC протокол (официальный RFC) |
| [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf) | Технический документ WireGuard |
| [Hping3 man page](https://linux.die.net/man/8/hping3) | Инструмент для тестирования защиты |
| [tcpkali](https://github.com/satori-com/tcpkali) | Benchmark инструмент для TCP |

---

## Балансировка и прокси

| Ресурс | Зачем |
|---|---|
| [Envoy proxy docs](https://www.envoyproxy.io/docs/envoy/latest/) | EWMA, Circuit Breaker, xDS - референс архитектуры |
| [HAProxy конфигурация](https://www.haproxy.org/download/2.8/doc/configuration.txt) | Полная документация HAProxy |
| [Consistent Hashing paper](https://dl.acm.org/doi/10.1145/258533.258660) | Оригинальная статья Karger et al. 1997 |
| [EWMA в Envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers#weighted-least-request) | Как Envoy реализует EWMA балансировку |
| [Nginx SO_REUSEPORT](https://nginx.org/en/docs/http/ngx_http_upstream_module.html) | Как Nginx использует SO_REUSEPORT |

---

## Наблюдаемость

| Ресурс | Зачем |
|---|---|
| [OpenTelemetry](https://opentelemetry.io/docs/) | Официальная документация OTel |
| [ClickHouse docs](https://clickhouse.com/docs) | Документация ClickHouse - схемы, запросы |
| [VictoriaMetrics](https://github.com/VictoriaMetrics/VictoriaMetrics) | Prometheus-совместимое хранилище для долгосрочных метрик |
| [Grafana Tempo](https://grafana.com/oss/tempo/) | Хранилище distributed traces |
| [Parca](https://github.com/parca-dev/parca) | Continuous profiling для production |
| [tokio-console](https://github.com/tokio-rs/console) | Debug async tokio tasks |
| [Brendan Gregg: Flame Graphs](https://www.brendangregg.com/flamegraphs.html) | Методология профилирования через flame graphs |

---

## Безопасность

| Ресурс | Зачем |
|---|---|
| [STRIDE модель](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) | Методология threat modeling |
| [subtle crate](https://docs.rs/subtle/) | Constant-time операции в Rust |
| [HMAC RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | Оригинальный HMAC RFC |
| [cargo-audit](https://github.com/rustsec/rustsec) | CVE проверка Rust зависимостей |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | Политики лицензий и зависимостей |
| [SLSA framework](https://slsa.dev/) | Supply chain security уровни |
| [cosign](https://github.com/sigstore/cosign) | Подпись Docker образов |

---

## Смежные open-source проекты

| Проект | Язык | Что взять |
|---|---|---|
| [Velocity](https://github.com/PaperMC/Velocity) | Java | MC proxy - основа нашего плагина |
| [Gate (Minekube)](https://github.com/minekube/gate) | Go | Высокопроизводительный MC proxy - архитектурный референс |
| [Minecraft-XDP-eBPF](https://github.com/Outfluencer/Minecraft-XDP-eBPF) | Rust+C | XDP для Minecraft - брать за основу XDP компонента |
| [Sonar](https://github.com/jonesdevelopment/sonar) | Java | Antibot для Velocity - интегрируем как слой |
| [RedisBungee-Reloaded](https://github.com/ProxioDev/RedisBungee) | Java | Cross-proxy синхронизация - референс |
| [VeloFlame](https://github.com/) | Java | Velocity форк с встроенным антиботом (июль 2026) |
| [Pumpkin-MC](https://github.com/Snowiiii/Pumpkin) | Rust | MC сервер на Rust - референс протокола |
| [Katran](https://github.com/facebookincubator/katran) | C++ | XDP load balancer от Facebook - архитектурный референс |
| [NATS](https://github.com/nats-io/nats-server) | Go | Event bus - используем для критических событий |
| [FRRouting](https://github.com/FRRouting/frr) | C | BGP routing - для Anycast в v0.6+ |
| [headscale](https://github.com/juanfont/headscale) | Go | Self-hosted WireGuard координатор - для v0.6+ |

---

## Статьи и блоги по теме

| Статья | Почему стоит прочитать |
|---|---|
| [How TCPShield works](https://tcpshield.com/blog/) | Понять конкурента изнутри |
| [Cloudflare: Lessons from protecting 26M HTTP RPS](https://blog.cloudflare.com/ddos-threat-report-for-2024-q4/) | Реальная статистика DDoS атак |
| [Linux networking performance](https://talawah.io/blog/linux-kernel-vs-dpdk-http-performance-showdown/) | Kernel vs DPDK vs XDP сравнение |
| [Tokio internals](https://tokio.rs/blog/2019-10-scheduler) | Как работает tokio scheduler |
| [io_uring в production](https://developers.mattermost.com/blog/hands-on-iouring-go/) | Реальный опыт io_uring |
| [eBPF maps deep dive](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html) | BPF map типы, когда что использовать |

---

## RFC для изучения

| RFC | Тема |
|---|---|
| RFC 793 | TCP - основа всего |
| RFC 4271 | BGP-4 |
| RFC 4786 | Anycast через BGP |
| RFC 7413 | TCP Fast Open |
| RFC 9000 | QUIC Transport |
| RFC 9001 | QUIC + TLS 1.3 |
| RFC 8446 | TLS 1.3 |
| RFC 2104 | HMAC |
| RFC 5246 | TLS 1.2 (для совместимости) |

---

## Инструменты для разработки

```bash
# Анализ трафика
wireshark         # GUI пакетный анализатор
tshark            # CLI версия wireshark
tcpdump           # быстрый захват пакетов

# Benchmark
tcpkali           # TCP нагрузочное тестирование
iperf3            # bandwidth тест
hping3            # генерация специфических пакетов
wrk               # HTTP benchmark (для Manager API)

# eBPF отладка
bpftool           # управление BPF программами и картами
bpftrace          # скриптовый язык для eBPF
strace            # системные вызовы (для userspace)

# Rust
cargo-flamegraph  # flame graphs
cargo-criterion   # benchmark с HTML отчётами
cargo-audit       # CVE проверка
cargo-deny        # политики зависимостей
tokio-console     # async tasks debug

# Сеть
wireguard-tools   # wg, wg-quick
frr               # FRRouting (BGP)
iptables/nftables # firewall

# Мониторинг
prometheus        # метрики
grafana           # дашборды
clickhouse        # attack log аналитика
parca             # continuous profiling
```
