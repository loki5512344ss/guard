#!/usr/bin/env python3
"""Много-IP Minecraft stress generator, маскирующийся под обычный трафик.

Отправляет валидные MC handshake с рандомными hostname из разных source IP
(--ips-start..--ips-end должны быть назначены на eth0 контейнера).

Modes:
  connect    - TCP connect + close (conn/s flood)
  handshake  - валидный MC handshake + ждём ответ backend (маскировка под клиента)
  status     - status-ping handshake (state 1)
  slowloris  - connect + 1 байт + hold
  keepalive  - connect + handshake + держим соединение
"""

import argparse
import random
import socket
import struct
import threading
import time
from datetime import datetime

HOSTS = [
    "play.example.com",
    "mc.example.com",
    "lobby.example.com",
    "hub.example.com",
    "survival.example.com",
    "skyblock.example.com",
    "bedwars.example.com",
    "minigames.example.com",
    "vip.example.com",
]
PROTOCOL = 767


def pack_varint(value):
    buf = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        buf.append(byte)
        if not value:
            break
    return bytes(buf)


def make_handshake(state=2, host=None):
    host = host or random.choice(HOSTS)
    pkt = bytearray()
    pkt.extend(pack_varint(0))  # packet ID 0x00
    pkt.extend(pack_varint(PROTOCOL))
    pkt.extend(pack_varint(len(host)))
    pkt.extend(host.encode())
    pkt.extend(struct.pack(">H", 25565))
    pkt.extend(pack_varint(state))
    return pack_varint(len(pkt)) + bytes(pkt)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="172.30.0.2")
    p.add_argument("--port", type=int, default=25565)
    p.add_argument(
        "--mode",
        choices=["connect", "handshake", "status", "slowloris", "keepalive"],
        default="handshake",
    )
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--threads", type=int, default=100)
    p.add_argument("--ips-start", type=int, default=101)
    p.add_argument("--ips-end", type=int, default=200)
    p.add_argument("--ips-base", default="172.30.0.")
    p.add_argument("--timeout", type=float, default=5.0)
    return p.parse_args()


def main():
    args = parse_args()
    src_ips = [f"{args.ips_base}{i}" for i in range(args.ips_start, args.ips_end + 1)]
    stop = threading.Event()
    stats = {"sent": 0, "lock": threading.Lock()}

    def worker():
        while not stop.is_set():
            src = random.choice(src_ips)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.bind((src, 0))
                s.settimeout(args.timeout)
                s.connect((args.target, args.port))
                if args.mode == "handshake":
                    s.sendall(make_handshake())
                    try:
                        s.recv(1)
                    except socket.timeout:
                        pass
                elif args.mode == "status":
                    s.sendall(make_handshake(state=1))
                    try:
                        s.recv(1)
                    except socket.timeout:
                        pass
                elif args.mode == "slowloris":
                    s.sendall(b"\x01")
                    time.sleep(30)
                elif args.mode == "keepalive":
                    s.sendall(make_handshake())
                    time.sleep(30)
                with stats["lock"]:
                    stats["sent"] += 1
                s.close()
            except OSError:
                pass
            except Exception:
                pass

    threads = [
        threading.Thread(target=worker, daemon=True) for _ in range(args.threads)
    ]
    for t in threads:
        t.start()

    t0 = time.time()
    try:
        while time.time() - t0 < args.duration:
            time.sleep(1)
            with stats["lock"]:
                cur = stats["sent"]
            print(
                f"  [{datetime.now():%H:%M:%S}] src_ips={len(src_ips)} sent={cur:8d} rate={cur / max(time.time() - t0, 1):9.1f}/s"
            )
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        time.sleep(0.5)

    elapsed = max(time.time() - t0, 0.001)
    with stats["lock"]:
        total = stats["sent"]
    print(
        f"DONE total={total} avg={total / elapsed:.1f}/s elapsed={elapsed:.1f}s src_ips={len(src_ips)}"
    )


if __name__ == "__main__":
    main()
