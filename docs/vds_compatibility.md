# VDS Compatibility - Rampart

> Совместимость VDS провайдеров с XDP/eBPF, io_uring и WireGuard.
> Обновляется: Июль 2026

---

## Почему это важно

Некоторые провайдеры используют виртуализацию, которая **не поддерживает XDP**:

| Тип виртуализации | XDP Native | XDP Generic | io_uring | Рекомендация |
|---|---|---|---|---|
| **KVM** | ✅ (зависит от драйвера) | ✅ | ✅ | Лучший выбор |
| **Bare Metal** | ✅ | ✅ | ✅ | Идеально для edge |
| **VMware** | ❌ | ✅ | ✅ | Приемлемо |
| **Hyper-V** | ❌ | ✅ | ✅ | Приемлемо |
| **OpenVZ / LXC** | ❌ | ❌ | ❌ | **НЕ ИСПОЛЬЗОВАТЬ** для edge |

> ⚠️ **OpenVZ/LXC контейнеры не поддерживают XDP и io_uring.**
> Если купите VDS за $3 у OVH - XDP не заведётся.

---

## Таблица провайдеров

### Edge нода (требует XDP)

| Провайдер | План | Виртуализация | XDP Native | XDP Generic | Цена/мес | Примечание |
|---|---|---|---|---|---|---|
| **Hetzner** | CX22 (2vCPU, 4GB) | KVM | ❌ (virtio) | ✅ | €4.5 | Отличный entry-level |
| **Hetzner** | CPX21 (3vCPU, 4GB) | KVM | ✅ (i40e) | ✅ | €6.9 | Рекомендуется |
| **Hetzner** | AX102 (8vCPU, 32GB) | Bare Metal | ✅ | ✅ | €35 | Для крупных нод |
| **Contabo** | Cloud VPS S (4vCPU, 8GB) | KVM | ❌ | ✅ | €5.0 | Бюджетно, но CPU слабее |
| **Vultr** | High Frequency (2vCPU, 4GB) | KVM | ✅ | ✅ | $12 | Хорошая сеть |
| **Vultr** | Regular (2vCPU, 4GB) | KVM | ❌ (virtio) | ✅ | $6 | Базовый вариант |
| **OVHcloud** | VPS Value (2vCPU, 4GB) | KVM | ❌ | ✅ | €3.5 | Бюджетно |
| **OVHcloud** | VPS Elite (4vCPU, 8GB) | KVM | ✅ | ✅ | €15 | Рекомендуется |
| **OVHcloud** | Bare Metal Game (4vCPU, 32GB) | Bare Metal | ✅ | ✅ | €30 | Для game серверов |
| **DigitalOcean** | Premium (2vCPU, 4GB) | KVM | ❌ | ✅ | $12 | Стабильно, но дороже |
| **Linode** | Dedicated CPU (4vCPU, 8GB) | KVM | ✅ | ✅ | $36 | Дороговато для edge |
| **Scaleway** | DEV1-L (4vCPU, 8GB) | KVM | ❌ (virtio) | ✅ | €11 | - |
| **AWS** | c6i.large (2vCPU, 4GB) | Nitro KVM | ✅ (ena) | ✅ | ~$24 | Дорого, сложный network |
| **Google Cloud** | e2-standard-2 (2vCPU, 4GB) | KVM | ❌ | ✅ | ~$17 | - |

> ✅ = Подтверждено работает
> ❌ = Не поддерживается драйвером

### Manager / Load Balancer (XDP не нужен)

Для Manager, HAProxy, Rust LB подойдёт **любой KVM VDS** с 2 vCPU. XDP не требуется.

| Провайдер | План | Цена/мес |
|---|---|---|
| Hetzner CX22 | 2vCPU, 4GB | €4.5 |
| Contabo VPS S | 4vCPU, 8GB | €5.0 |
| OVH VPS Value | 2vCPU, 4GB | €3.5 |

### Game серверы (Minecraft)

| Провайдер | План | RAM | Цена/мес | Примечание |
|---|---|---|---|---|
| Hetzner AX102 | Bare Metal, 8vCPU | 32GB | €35 | Лучшее соотношение |
| OVH Game | 4vCPU | 32GB | €30 | Оптимизирован для игр |
| Localhost | Dedicated | 64GB+ | - | Лучшая производительность |

---

## Как проверить совместимость

```bash
# 1. Тип виртуализации (должно быть kvm или none)
systemd-detect-virt

# 2. Драйвер сетевой карты
ethtool -i eth0 | grep driver
# i40e / mlx5 = XDP Native ✅
# virtio / vmxnet3 = XDP Generic только

# 3. Версия ядра (нужно 5.10+)
uname -r

# 4. XDP доступность
sudo ip link set dev eth0 xdp off 2>&1 || echo "XDP не поддерживается"

# 5. io_uring доступность
cat /proc/sys/kernel/io_uring_disabled
# 0 = OK, 1 = только root, 2 = заблокирован
```

---

## Рекомендуемые конфигурации

### Для старта (v0.1, до 500 игроков)

```
1 × Hetzner CX22 (€4.5)  - Manager + Redis + NATS
1 × Hetzner CX22 (€4.5)  - Edge нода (XDP Generic)
1 × Velocity на той же VDS что и Manager
N × Game серверы (ваши существующие)
Итого: ~€9/мес
```

### Medium (v0.4+, до 5000 игроков)

```
1 × Hetzner CPX31 (€12)  - Manager + Redis + NATS + ClickHouse
2 × Hetzner CPX21 (€6.9) - Edge ноды (XDP Native)
2 × Hetzner CX32 (€8)    - Velocity
5 × Hetzner AX102 (€35)  - Game серверы
Итого: ~€230/мес
```

### Large (v0.6+, до 50000 игроков)

```
1 × Hetzner AX102 (€35)  - Manager + NATS + ClickHouse
4 × Hetzner CPX31 (€12)  - Rust LB
6 × Hetzner CPX31 (€12)  - Edge ноды (XDP Native)
15 × Hetzner CX32 (€8)   - Velocity
20 × Hetzner AX102 (€35) - Game серверы
Итого: ~€1100/мес
```

---

## Лимиты провайдеров

### Hetzner
- **Traffic:** CX/CPX - 20TB включено, далее €1/TB
- **DDoS Protection:** Встроенная L3/L4 защита (10Gbps blackhole)
- **BGP:** Только на выделенных серверах (AX)

### Contabo
- **Traffic:** Неограничен (512Mbps)
- **DDoS Protection:** Есть, но слабая
- **CPU:** Старшие модели Intel Xeon, но shared

### OVHcloud
- **VPS:** OpenVZ на старых тарифах - **проверяйте перед покупкой**
- **Game серверы:** Встроенная DDoS защита (up to 1Tbps)
- **BGP:** На Bare Metal

---

*Версия: 1.0 | Июль 2026*
