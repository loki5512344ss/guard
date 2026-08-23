#!/usr/bin/env python3
"""Много-IP TCP stress generator.

Открывает TCP-соединения с разных source IP (--ips-start..--ips-end должны
быть назначены на eth0 контейнера). Без маскировки под конкретный протокол:
флуд неотличим от обычных TCP-коннектов на уровне L3/L4, различие даёт
только per-IP rate limit и репутация на edge.

Modes:
  connect    - TCP connect + close (conn/s flood)
  slowloris  - connect + 1 байт + hold (медленные соединения)
  keepalive  - connect + держим соединение открытым
"""

import argparse
import random
import socket
import threading
import time
from datetime import datetime


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="172.30.0.2")
    p.add_argument("--port", type=int, default=25565)
    p.add_argument(
        "--mode",
        choices=["connect", "slowloris", "keepalive"],
        default="connect",
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
                if args.mode == "connect":
                    pass
                elif args.mode == "slowloris":
                    try:
                        s.sendall(b"\x01")
                        time.sleep(30)
                    except OSError:
                        pass
                elif args.mode == "keepalive":
                    try:
                        time.sleep(30)
                    except OSError:
                        pass
                with stats["lock"]:
                    stats["sent"] += 1
                if args.mode == "connect":
                    s.close()
            except OSError:
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
