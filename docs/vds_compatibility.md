# VDS Compatibility - Rampart

> Совместимость VDS провайдеров с XDP/eBPF.
> Обновляется: Ноябрь 2026

---

## Почему это важно

Некоторые провайдеры используют виртуализацию, которая **не поддерживает XDP**:

| Тип виртуализации | XDP Native | XDP Generic | Рекомендация |
|---|---|---|---|
| **KVM** | ✅ (зависит от драйвера) | ✅ | Лучший выбор |
| **Bare Metal** | ✅ | ✅ | Идеально для edge |
| **VMware / Hyper-V** | ❌ | ✅ | Приемлемо |
| **OpenVZ / LXC** | ❌ | ❌ | **НЕ ИСПОЛЬЗОВАТЬ** для edge |

> ⚠️ OpenVZ/LXC не поддерживают XDP. Дешёвая VDS за $3 — XDP не заведётся.

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

# 4. Диагностика окружения (XDP, BTF, драйвер, режим attach)
rampart-cli doctor
# Строка про XDP: native (drv) — лучший режим, generic (skb) — работает, но дороже.
# Если XDP недоступен совсем — используй userspace-фильтр (XDP опционален).
```

---

## Провайдеры

| Провайдер | План | Виртуализация | XDP Native | Цена/мес |
|---|---|---|---|---|
| Hetzner | CPX21 (3vCPU, 4GB) | KVM | ✅ (i40e на AX) | €6.9 |
| Hetzner | AX102 (bare metal) | — | ✅ | €35 |
| Vultr | High Frequency | KVM | ✅ | $12 |
| OVHcloud | VPS Elite | KVM | ✅ | €15 |
| Contabo | Cloud VPS S | KVM | ❌ (generic only) | €5.0 |
| DigitalOcean | Premium | KVM | ❌ (generic only) | $12 |

Для Manager подойдёт любой KVM VDS с 2 vCPU — XDP там не нужен.

> Таблица ориентировочная: перед покупкой проверь драйвер NIC и ядро командами выше.

---

## Лимиты провайдеров

### Hetzner
- Traffic: CX/CPX — 20TB включено, далее €1/TB
- DDoS Protection: встроенная L3/L4 защита (10Gbps blackhole)

### OVHcloud
- VPS: старые тарифы бывают на OpenVZ — **проверяй перед покупкой**
- Game-линейка: встроенная DDoS защита до 1Tbps

---

*Версия: 3.0 | Ноябрь 2026*
