# Rampart Knowledge Base

> Теоретическая база и практика защиты от DDoS, на которой построена платформа.
> Статьи двуязычные: в каждой есть разделы `## English` и `## Русский`.

## English

### Attacks — how they work

- [SYN Flood](./attacks/syn-flood.md) — the classic TCP half-open exhaustion attack; backlog mechanics, why one packet costs the server memory.
- [HTTP Flood](./attacks/http-flood.md) — application-layer floods with syntactically perfect requests; why L3/L4 defense is powerless.
- [Slowloris & Slow Attacks](./attacks/slowloris.md) — exhausting connection slots with connections that never finish; no bandwidth needed.
- [UDP Amplification](./attacks/udp-amplification.md) — reflection and amplification factors; DNS/NTP/Memcached abuse.

### Defense fundamentals

- [Defense Levels](./defense-levels.md) — where to filter a packet: kernel (XDP) vs userspace trade-offs, full packet path through the Linux stack, and why Rampart uses hybrid kernel fast-path + userspace smart-path.

### Practice

- [Kernel Tuning](./practice/kernel-tuning.md) — sysctl parameters that matter under flood (`tcp_max_syn_backlog`, somaxconn, backlog queues), ready-to-adapt config.
- [NIC Tuning](./practice/nic-tuning.md) — ring buffers, IRQ affinity, offloads, RPS/XPS for high pps workloads.
- [Stress Testing](./practice/stress-testing.md) — methodology and tooling for load/attack simulation against your own infra.

---

## Русский

### Атаки — как они работают

- [SYN Flood](./attacks/syn-flood.md) — классическая атака на полуоткрытые соединения; механика backlog'а, почему один пакет стоит серверу памяти.
- [HTTP Flood](./attacks/http-flood.md) — L7-флуд синтаксически корректными запросами; почему защита уровня L3/L4 бессильна.
- [Slowloris и медленные атаки](./attacks/slowloris.md) — исчерпание слотов соединений соединениями, которые никогда не завершаются; полоса не нужна.
- [UDP-амплификация](./attacks/udp-amplification.md) — рефлексия и коэффициенты усиления; злоупотребление DNS/NTP/Memcached.

### Основы защиты

- [Уровни фильтрации](./defense-levels.md) — где дропать пакет: компромиссы ядра (XDP) и userspace, полный путь пакета через сетевой стек Linux и почему Rampart использует гибрид kernel fast-path + userspace smart-path.

### Практика

- [Тюнинг ядра](./practice/kernel-tuning.md) — значимые под флудом параметры sysctl (`tcp_max_syn_backlog`, somaxconn, очереди), готовый конфиг для адаптации.
- [Тюнинг NIC](./practice/nic-tuning.md) — ring buffers, привязка прерываний, offload'ы, RPS/XPS для высоких pps.
- [Стресс-тестирование](./practice/stress-testing.md) — методика и инструменты нагрузочной/атакующей симуляции на своей инфраструктуре.
