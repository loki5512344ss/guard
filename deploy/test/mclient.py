#!/usr/bin/env python3
"""Minecraft handshake client for testing Rampart."""

import argparse
import socket
import struct
import time


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


def make_handshake(host, port, protocol=767):
    packet = bytearray()
    packet.extend(pack_varint(protocol))
    packet.extend(pack_varint(len(host)))
    packet.extend(host.encode())
    packet.extend(struct.pack(">H", port))
    packet.extend(pack_varint(2))
    length = pack_varint(len(packet))
    return length + bytes(packet)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="localhost:25565")
    parser.add_argument("--username", default="test_bot")
    args = parser.parse_args()

    host, port_str = args.target.split(":")
    port = int(port_str)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(make_handshake(host, port))

    data = sock.recv(4096)
    if data:
        print(f"Got response: {data.hex()}")
        # If PoW challenge -> receive challenge, solve, send nonce
        if b"challenge" in data:
            print("PoW challenge received")
            challenge = data.decode().strip()
            for nonce in range(1000000):
                import hashlib

                h = hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest()
                if h.startswith("0000"):
                    sock.sendall(str(nonce).encode())
                    resp = sock.recv(4096)
                    print(f"PoW ok, handshake: {resp.hex()}")
                    break
        else:
            print(f"Handshake response: {data.hex()}")
    else:
        print("No response (blocked)")

    sock.close()


if __name__ == "__main__":
    main()
