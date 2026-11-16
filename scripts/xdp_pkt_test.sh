#!/usr/bin/env bash
# Packet-level smoke test for L2/L3 edge cases that ordinary sockets cannot
# produce: VLAN/QinQ tags, IPv4 fragments and Ethernet padding.
#
# What it verifies (each phase is a regression for a fix in universal_filter.c):
#   1. VLAN, QinQ and plain datagrams from a banned source are all dropped —
#      tags are peeled before L3 and the blacklist still runs;
#   2. first (MF) and non-first fragments from a banned source are dropped by
#      the source blacklist;
#   3. fragments from a clean source pass and bump STAT_FRAGMENT_BYPASS;
#   4. TCP payload length comes from ip->tot_len, not from the frame end: a
#      segment followed by 16 bytes of Ethernet padding advances expected_seq
#      by the 4 declared payload bytes only (read back from conntrack_map).
#
# Requires root/CAP_BPF+CAP_NET_ADMIN, bpftool, clang, python3.
# Run: sudo bash scripts/xdp_pkt_test.sh

set -u

NS=rampart_pkt_smoke
DEV0=rthp0
DEV1=rtapp0
HOST4=10.88.0.1
NS4=10.88.0.2
PORT=4444
OBJ=$(mktemp /tmp/rampart_pkt_smoke.XXXXXX.o)
PIN=/sys/fs/bpf/rampart_pkt_smoke
WORK=$(mktemp -d /tmp/rampart_pkt_work.XXXXXX)
PASS=1

fail() { echo "FAIL: $1"; PASS=0; }
ok() { echo "ok:   $1"; }

# Detach and remove every artefact, so a rerun starts from a clean state.
cleanup() {
	bpftool net detach xdp dev "$DEV0" 2>/dev/null
	rm -f "$PIN" "$OBJ"
	rm -rf "$WORK"
	ip link del "$DEV0" 2>/dev/null
	ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
cd "$(dirname "$0")/.." || exit 2

clang -O2 -g -target bpf -mcpu=v3 -c xdp/core/universal_filter.c -o "$OBJ" \
	-Ixdp -Ixdp/core -Ixdp/hooks -I/usr/include/x86_64-linux-gnu \
	|| { echo "clang: не собралось"; exit 1; }
ok "clang: universal_filter.c собран"

ip netns add "$NS" || { echo "не удалось создать netns"; exit 2; }
ip link add "$DEV0" type veth peer name "$DEV1" || exit 2
ip link set "$DEV1" netns "$NS"
ip addr add "$HOST4/24" dev "$DEV0"
ip link set "$DEV0" up
ip -n "$NS" addr add "$NS4/24" dev "$DEV1"
ip -n "$NS" link set "$DEV1" up
ip -n "$NS" link set lo up
ok "netns $NS + veth ($HOST4 <-> $NS4)"

# Loading through the verifier is itself a check.
bpftool prog load "$OBJ" "$PIN" type xdp || { echo "verifier отверг программу"; exit 1; }
bpftool net attach xdp pinned "$PIN" dev "$DEV0" || exit 1
ok "verifier принял программу, attach на $DEV0"

discover_maps() {
	IDS=$(bpftool prog show pinned "$PIN" | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2 | tr ',' ' ')
	B4=""
	CT=""
	ST=""
	for id in $IDS; do
		desc=$(bpftool map show id "$id" 2>/dev/null)
		case "$desc" in
			*"name blacklist_map"*) B4=$id ;;
			*"name conntrack_map"*) CT=$id ;;
			*"name stats_map"*) ST=$id ;;
		esac
	done
	[ -n "$B4" ] && [ -n "$CT" ] && [ -n "$ST" ]
}
discover_maps || { echo "карты не найдены"; exit 1; }
ok "blacklist_map id=$B4, conntrack_map id=$CT, stats_map id=$ST"

# Crafted-frame sender. argv: iface src dst kind args...
# The frames are emitted with AF_PACKET from inside the namespace, so they
# arrive on DEV0 exactly as a NIC would deliver them. Checksums of TCP/UDP are
# irrelevant: XDP runs before the stack and only the IP header is inspected.
cat > "$WORK/send.py" <<'PY'
import socket, struct, sys

iface, src, dst, kind = sys.argv[1:5]
SPORT = 40000

DST_MAC = bytes.fromhex("020000000001")
SRC_MAC = bytes.fromhex("020000000002")


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b"\0"
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(proto, payload, frag_off=0):
    total = 20 + len(payload)
    args = (0x45, 0, total, 0x1234, frag_off, 64, proto, 0,
            socket.inet_aton(src), socket.inet_aton(dst))
    hdr = struct.pack("!BBHHHBBH4s4s", *args)
    args = args[:7] + (ip_checksum(hdr),) + args[8:]
    return struct.pack("!BBHHHBBH4s4s", *args) + payload


def l2(eth_type, tags):
    hdr = DST_MAC + SRC_MAC
    if tags >= 1:
        hdr += struct.pack("!HH", 0x8100 if tags == 1 else 0x88A8, 100)
    if tags >= 2:
        hdr += struct.pack("!HH", 0x8100, 200)
    return hdr + struct.pack("!H", eth_type)


def emit(eth_type, l3, tags, pad):
    frame = l2(eth_type, tags) + l3
    if len(frame) < pad:
        frame += b"\0" * (pad - len(frame))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))
    sock.send(frame)


def udp(args):
    sport, dport, tags, pad = (int(a, 0) for a in args)
    data = b"x" * 8
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    emit(0x0800, ip4(17, hdr + data), tags, pad)


def frag(args):
    sport, dport, offset8, mf = (int(a, 0) for a in args)
    data = b"y" * 8
    hdr = struct.pack("!HHHH", sport, dport, 16, 0)
    frag_off = (offset8 & 0x1FFF) | (0x2000 if mf else 0)
    emit(0x0800, ip4(17, hdr + data, frag_off), 0, 0)


def tcp(args):
    sport, dport, seq, ack, flags, data_len, pad = (int(a, 0) for a in args)
    data = b"z" * data_len
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                      0xFFFF, 0, 0)
    emit(0x0800, ip4(6, hdr + data), 0, pad)


{"udp": udp, "frag": frag, "tcp": tcp}[kind](sys.argv[5:])
PY

send() { ip netns exec "$NS" python3 "$WORK/send.py" "$DEV1" "$NS4" "$HOST4" "$@"; }

# Sum the per-CPU counters and print only the non-zero ones.
stats() {
	bpftool -j map dump id "$ST" | python3 -c "
import json, sys
names = {0: 'total', 3: 'blacklist', 5: 'pass', 6: 'drop', 12: 'frag_bypass'}
out = {}
for e in json.load(sys.stdin):
    k = names.get(e['formatted']['key'])
    if k is not None:
        out[k] = sum(v['value'] for v in e['formatted']['values'])
print(' '.join(f'{k}={v}' for k, v in out.items() if v) or 'все нули')
"
}
metric() { stats | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }

# /32 LPM key for $NS4 and a ban that never expires in this run.
KEY4="20 00 00 00 0a 58 00 02"
BAN="ff ff ff ff ff ff ff ff"
bpftool map update id "$B4" key hex $KEY4 value hex $BAN || fail "ban $NS4"

# Phase 1: tagged traffic from a banned source (plain frame as control).
drop0=$(metric drop)
send udp 5000 $PORT 1 0
send udp 5000 $PORT 2 0
send udp 5000 $PORT 0 0
sleep 0.3
drop1=$(metric drop)
[ "${drop1:-0}" -ge $((${drop0:-0} + 3)) ] \
	&& ok "VLAN/QinQ/plain UDP от забаненного источника дропаются (drop $drop0 -> $drop1)" \
	|| fail "tagged traffic прошёл мимо бана (drop $drop0 -> $drop1, $(stats))"

# Phase 2: fragments from a banned source, first (MF) and later ones.
drop0=$(metric drop)
send frag 5001 $PORT 0 1
send frag 5002 $PORT 1 0
send frag 5003 $PORT 1 1
sleep 0.3
drop1=$(metric drop)
[ "${drop1:-0}" -ge $((${drop0:-0} + 3)) ] \
	&& ok "фрагменты (MF и offset>0) от забаненного источника дропаются (drop $drop0 -> $drop1)" \
	|| fail "фрагменты прошли мимо бана (drop $drop0 -> $drop1, $(stats))"

bpftool map delete id "$B4" key hex $KEY4 || fail "unban $NS4"

# Phase 3: fragments from a clean source pass and are counted separately.
pass0=$(metric pass)
frag0=$(metric frag_bypass)
send frag 5004 $PORT 0 1
send frag 5005 $PORT 1 0
send frag 5006 $PORT 2 0
sleep 0.3
pass1=$(metric pass)
frag1=$(metric frag_bypass)
[ "${pass1:-0}" -ge $((${pass0:-0} + 3)) ] && [ "${frag1:-0}" -ge $((${frag0:-0} + 3)) ] \
	&& ok "чистые фрагменты проходят и считаются (pass $pass0 -> $pass1, frag $frag0 -> $frag1)" \
	|| fail "чистые фрагменты не прошли/не посчитались (pass $pass0 -> $pass1, frag $frag0 -> $frag1, $(stats))"

# Phase 4: a padded frame must not inflate the TCP payload. ISN=1000, so after
# the handshake expected_seq is 1001; a 4-byte payload must leave 1005, not
# 1001 + 4 + 16 padding = 1021.
send tcp 40000 $PORT 1000 0 0x02 0 0         # SYN
send tcp 40000 $PORT 1001 2000 0x10 0 0      # ACK completes the handshake
send tcp 40000 $PORT 1001 2000 0x18 4 74     # 4 payload bytes, 16 pad bytes
sleep 0.3
got=$(bpftool -j map dump id "$CT" | python3 -c "
import json, sys
for e in json.load(sys.stdin):
    v = bytes(int(x, 0) for x in e['value'])
    print(int.from_bytes(v[4:8], 'little'))
    break
")
[ "${got:-0}" = "1005" ] \
	&& ok "expected_seq учёл 4 байта payload, а не 20 байт кадра (expected_seq=$got)" \
	|| fail "expected_seq=$got, ожидалось 1005 (паддинг попал в payload)"

[ "$PASS" = 1 ] && echo "PASS: VLAN/QinQ, фрагменты и паддинг обрабатываются корректно" || echo "FAIL"
[ "$PASS" = 1 ]
