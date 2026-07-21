#!/usr/bin/env python3
"""DDoS simulation: 100 IPs from attacker container, 3 legit clients from host."""

import subprocess, time, re, sys

TARGET_IP = "172.18.0.6"
TARGET_PORT = 25565
METRICS_URL = "http://localhost:9090/metrics"
DURATION = 30
NUM_IPS = 100


def metrics():
    try:
        import urllib.request

        data = urllib.request.urlopen(METRICS_URL, timeout=5).read().decode()
        result = {}
        for line in data.splitlines():
            if line.startswith("rampart_"):
                parts = line.split()
                if len(parts) >= 2:
                    result[parts[0]] = parts[-1]
        return result
    except:
        return {}


def print_metrics(label, m):
    print(f"  [{label}]", end="")
    for k, v in sorted(m.items()):
        print(f" {k}={v}", end="")
    print()


ALLOWED = set("0123")


def solve_pow(challenge, difficulty):
    import hashlib

    t0 = time.time()
    for n in range(20_000_000):
        h = hashlib.sha256(f"{challenge}{n}".encode()).hexdigest()
        if all(c in ALLOWED for c in h[:difficulty]):
            return n, time.time() - t0
    return None, time.time() - t0


def legit_client(client_id, delay):
    import socket, hashlib, struct

    time.sleep(delay)
    m = metrics()
    diff = int(m.get("rampart_pow_current_difficulty", "4"))
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect(("localhost", TARGET_PORT))
        data = s.recv(4096).decode().strip()
        nonce, solve_t = solve_pow(data, diff)
        if nonce is None:
            print(f"  [legit#{client_id}] FAILED to solve PoW (diff={diff})")
            s.close()
            return
        s.sendall(f"{nonce}\n".encode())
        time.sleep(0.1)

        # MC handshake
        def wv(v):
            b = bytearray()
            while True:
                byte = v & 0x7F
                v >>= 7
                if v:
                    byte |= 0x80
                b.append(byte)
                if not v:
                    break
            return bytes(b)

        host = "localhost"
        hs = bytearray()
        hs.extend(wv(0))
        hs.extend(wv(767))
        hs.extend(wv(len(host)))
        hs.extend(host.encode())
        hs.extend(struct.pack(">H", 25565))
        hs.extend(wv(2))
        s.sendall(wv(len(hs)) + bytes(hs))
        time.sleep(0.1)
        name = f"test_{client_id}"
        login = bytearray()
        login.extend(wv(0))
        login.extend(wv(len(name)))
        login.extend(name.encode())
        s.sendall(wv(len(login)) + bytes(login))
        resp = s.recv(4096)
        status = "OK" if resp else "no_resp"
        print(
            f"  [legit#{client_id}] ✅ diff={diff} solve={solve_t:.3f}s status={status}"
        )
    except Exception as e:
        print(f"  [legit#{client_id}] ❌ diff={diff} error={e}")
    finally:
        try:
            s.close()
        except:
            pass


def run_flood_in_attacker():
    """Run the 100-IP flood inside the attacker container."""
    print("[setup] Launching flood inside attacker container...")
    import os, tempfile

    script = """
import socket, threading, time, struct

TARGET = ("172.18.0.6", 25565)
DURATION = 30
NUM_IPS = 100
sent = 0
lock = threading.Lock()

def wv(v):
    b = bytearray()
    while True:
        byte = v & 0x7F
        v >>= 7
        if v: byte |= 0x80
        b.append(byte)
        if not v: break
    return bytes(b)

host = "localhost"
handshake = wv(0) + wv(767) + wv(len(host)) + host.encode() + struct.pack(">H", 25565) + wv(2)
end = time.time() + DURATION

def flood():
    global sent
    while time.time() < end:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect(TARGET)
            s.sendall(wv(len(handshake)) + handshake)
            with lock: sent += 1
            s.close()
        except: pass

threads = [threading.Thread(target=flood) for _ in range(NUM_IPS)]
for t in threads: t.start()
for t in threads: t.join()
print(f"FLOOD_DONE:{sent}")
"""
    tmp = tempfile.mktemp(suffix=".py")
    with open(tmp, "w") as f:
        f.write(script)
    subprocess.run(f'docker cp "{tmp}" attacker:/tmp/flood.py', shell=True, check=True)
    os.unlink(tmp)
    result = subprocess.run(
        f"docker exec attacker python3 /tmp/flood.py",
        shell=True,
        capture_output=True,
        text=True,
        timeout=DURATION + 20,
    )
    for line in result.stdout.splitlines():
        if "FLOOD_DONE" in line:
            return int(line.split(":")[1])
    print("  [flood] stdout:", result.stdout[-300:])
    print("  [flood] stderr:", result.stderr[-300:])
    return 0


# ── Main ──
print("=" * 60)
print("Rampart DDoS Simulation — 100 IP Handshake Flood + Legit Clients")
print("=" * 60)

before = metrics()
print_metrics("BEFORE", before)

# Launch flood in attacker container
flood_total = run_flood_in_attacker()

# Launch legit clients during flood
import threading

legit3 = threading.Thread(target=legit_client, args=(3, 25))
legit2 = threading.Thread(target=legit_client, args=(2, 15))
legit1 = threading.Thread(target=legit_client, args=(1, 5))
legit1.start()
time.sleep(0.1)
legit2.start()
time.sleep(0.1)
legit3.start()

# Poll metrics during attack
for i in range(DURATION // 5):
    time.sleep(5)
    m = metrics()
    print_metrics(f"t={(i + 1) * 5}s", m)

legit1.join()
legit2.join()
legit3.join()
time.sleep(2)

after = metrics()
print_metrics("AFTER", after)

# Summary
print()
print("=" * 60)
print("SUMMARY")
print("=" * 60)
diff = lambda k: int(after.get(k, "0")) - int(before.get(k, "0"))
print(f"  Total handshakes sent:    {flood_total}")
print(f"  CPS:                      {flood_total // DURATION}")
print(
    f"  PoW challenges failed:    +{diff('rampart_pow_challenges_total{result="failed"}')}"
)
print(
    f"  PoW challenges passed:    +{diff('rampart_pow_challenges_total{result="passed"}')}"
)
print(
    f"  Connections allowed:      +{diff('rampart_connections_total{result="allowed"}')}"
)
print(
    f"  Connections blocked:      +{diff('rampart_connections_total{result="blocked"}')}"
)
print(
    f"  PoW difficulty (start):   {before.get('rampart_pow_current_difficulty', '?')}"
)
print(f"  PoW difficulty (end):     {after.get('rampart_pow_current_difficulty', '?')}")
