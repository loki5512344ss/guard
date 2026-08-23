#!/usr/bin/env python3
"""Generic TCP-клиент: подключается ВО ВРЕМЯ DDoS и меряет RTT."""

import argparse
import socket
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--port", type=int, default=25565)
    p.add_argument("--count", type=int, default=6)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--name", default="legit")
    args = p.parse_args()

    for i in range(args.count):
        t0 = time.time()
        s = None
        try:
            s = socket.create_connection((args.target, args.port), timeout=args.timeout)
            s.settimeout(args.timeout)
            # Ждём первый байт от edge (PoW challenge / upstream-ответ).
            resp = s.recv(1)
            rtt = (time.time() - t0) * 1000
            ok = len(resp) > 0
            print(f"[{args.name}#{i}] {'OK' if ok else 'NO_RESP'} rtt={rtt:.1f}ms")
        except Exception as e:
            rtt = (time.time() - t0) * 1000
            print(f"[{args.name}#{i}] FAIL {type(e).__name__}: {e} rtt={rtt:.1f}ms")
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
