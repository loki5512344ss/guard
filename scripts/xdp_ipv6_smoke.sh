#!/usr/bin/env bash
# Functional smoke test of XDP bans on a real kernel (netns + veth + verifier).
#
# What it verifies:
#   1. the verifier accepts universal_filter.o;
#   2. native IPv6 traffic passes without a ban and is dropped once a /128
#      entry exists in blacklist6_map;
#   3. a short UDP datagram (under 20 bytes of L4) is dropped as well; it used
#      to fall through to XDP_PASS past the blacklist because the length check
#      was sized for TCP;
#   4. the same holds for IPv4, through the shared L4 gate;
#   5. expiry: a ban with a monotonic TTL really expires in the kernel; it
#      used to live forever because userspace wrote epoch-ns while the C side
#      compared against bpf_ktime_get_ns().
#
# Requires root/CAP_BPF+CAP_NET_ADMIN, bpftool, clang, python3.
# Run: sudo bash scripts/xdp_ipv6_smoke.sh

set -u

NS=rampart_v6_smoke
DEV0=rth6
DEV1=rtap6
HOST6=fd00::1
NS6=fd00::2
HOST4=10.99.0.1
NS4=10.99.0.2
PORT=4444
OBJ=$(mktemp /tmp/rampart_v6_smoke.XXXXXX.o)
PIN=/sys/fs/bpf/rampart_v6_smoke
PASS=1

fail() { echo "FAIL: $1"; PASS=0; }
ok() { echo "ok:   $1"; }

# Detach and remove every artefact, so a rerun starts from a clean state.
cleanup() {
	bpftool net detach xdp dev "$DEV0" 2>/dev/null
	rm -f "$PIN" "$OBJ"
	ip link del "$DEV0" 2>/dev/null
	ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
cd "$(dirname "$0")/.." || exit 2

# Build the object once; the same binary is reused for every phase below.
clang -O2 -g -target bpf -mcpu=v3 -c xdp/core/universal_filter.c -o "$OBJ" \
	-Ixdp -Ixdp/core -Ixdp/hooks -I/usr/include/x86_64-linux-gnu \
	|| { echo "clang: не собралось"; exit 1; }
ok "clang: universal_filter.c собран"

# Isolated namespace with one veth pair: host side is DEV0, peer is DEV1.
ip netns add "$NS" || { echo "не удалось создать netns"; exit 2; }
ip link add "$DEV0" type veth peer name "$DEV1" || exit 2
ip link set "$DEV1" netns "$NS"
ip -6 addr add "$HOST6/64" dev "$DEV0"
ip addr add "$HOST4/24" dev "$DEV0"
ip link set "$DEV0" up
ip -n "$NS" -6 addr add "$NS6/64" dev "$DEV1"
ip -n "$NS" addr add "$NS4/24" dev "$DEV1"
ip -n "$NS" link set "$DEV1" up
ip -n "$NS" link set lo up
ok "netns $NS + veth ($HOST6/$HOST4 <-> $NS6/$NS4)"

# Loading through the verifier is itself a check: a rejected program exits here.
bpftool prog load "$OBJ" "$PIN" type xdp || { echo "verifier отверг программу"; exit 1; }
bpftool net attach xdp pinned "$PIN" dev "$DEV0" || exit 1
ok "verifier принял программу, attach на $DEV0"

# Resolve map ids from the pinned program; ids change on every load.
discover_maps() {
	IDS=$(bpftool prog show pinned "$PIN" | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2 | tr ',' ' ')
	B4=""
	B6=""
	ST=""
	for id in $IDS; do
		desc=$(bpftool map show id "$id" 2>/dev/null)
		case "$desc" in
			*"name blacklist6_map"*) B6=$id ;;
			*"name blacklist_map"*) B4=$id ;;
			*"name stats_map"*) ST=$id ;;
		esac
	done
	[ -n "$B4" ] && [ -n "$B6" ] && [ -n "$ST" ]
}
discover_maps || { echo "карты не найдены"; exit 1; }
ok "blacklist_map id=$B4, blacklist6_map id=$B6, stats_map id=$ST"

# LPM keys: prefixlen (u32 LE) followed by the address in network order.
KEY6="80 00 00 00 fd 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02"
KEY4="20 00 00 00 0a 63 00 02"

# Send one IPv6 UDP datagram of $1 payload bytes from inside the namespace.
send6() {
	ip netns exec "$NS" python3 -c "
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.sendto(b'x' * $1, ('$HOST6', $PORT))
"
}
# Same for IPv4.
send4() {
	ip netns exec "$NS" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'x' * $1, ('$HOST4', $PORT))
"
}

# Sum the per-CPU counters and print only the non-zero ones.
stats() {
	bpftool -j map dump id "$ST" | python3 -c "
import json, sys
names = {0: 'total', 1: 'tcp', 2: 'whitelist', 3: 'blacklist', 4: 'syn_thr',
         5: 'pass', 6: 'drop', 7: 'udp', 8: 'rate', 9: 'chal_sent'}
out = {}
for e in json.load(sys.stdin):
    k = names.get(e['formatted']['key'])
    if k is not None:
        out[k] = sum(v['value'] for v in e['formatted']['values'])
print(' '.join(f'{k}={v}' for k, v in out.items() if v) or 'все нули')
"
}
# Read a single counter value; empty output means the counter is zero.
metric() { stats | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }

# Monotonic now + $1 seconds as 8 little-endian bytes, the kernel's ban TTL format.
mono_ns_hex() {
	python3 -c "
import time
ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + $1 * 1_000_000_000
print(' '.join(f'{b:02x}' for b in ns.to_bytes(8, 'little')))
"
}

# Phase 1: IPv6 — traffic passes, a ban drops it, removing the ban restores it.
pass0=$(metric pass)
for _ in 1 2 3; do send6 100; done
sleep 0.5
pass1=$(metric pass)
[ "${pass1:-0}" -gt "${pass0:-0}" ] \
	&& ok "v6 без бана проходит (pass $pass0 -> $pass1)" \
	|| fail "v6 без бана не проходит ($(stats))"

drop0=$(metric drop)
bpftool map update id "$B6" key hex $KEY6 value hex ff ff ff ff ff ff ff ff || fail "v6 map update"
for _ in 1 2 3; do send6 100; done
for _ in 1 2 3; do send6 1; done # short datagram
sleep 0.5
drop1=$(metric drop)
[ "${drop1:-0}" -ge $((${drop0:-0} + 6)) ] \
	&& ok "v6 с баном дропает обычные и короткие (drop $drop0 -> $drop1)" \
	|| fail "v6 бан не дропает всё ($(stats))"

bpftool map delete id "$B6" key hex $KEY6 || fail "v6 map delete"
pass2=$(metric pass)
for _ in 1 2 3; do send6 100; done
sleep 0.5
pass3=$(metric pass)
[ "${pass3:-0}" -gt "${pass2:-0}" ] \
	&& ok "v6 после снятия бана проходит (pass $pass2 -> $pass3)" \
	|| fail "v6 после снятия бана не проходит ($(stats))"

# Phase 2: IPv4 through the shared L4 gate — only short datagrams, which is
# the min_l4 regression.
drop0=$(metric drop)
bpftool map update id "$B4" key hex $KEY4 value hex ff ff ff ff ff ff ff ff || fail "v4 map update"
for _ in 1 2 3; do send4 1; done # short datagrams only — the min_l4 regression
sleep 0.5
drop1=$(metric drop)
[ "${drop1:-0}" -ge $((${drop0:-0} + 3)) ] \
	&& ok "v4 короткие датаграммы дропаются баном (drop $drop0 -> $drop1)" \
	|| fail "v4 короткая датаграмма прошла мимо бана ($(stats))"
bpftool map delete id "$B4" key hex $KEY4 || fail "v4 map delete"

# Phase 3: ban expiry on the monotonic clock. A TTL written in epoch-ns would
# never expire against bpf_ktime_get_ns(), so this phase pins the clock choice.
TTL=2
bpftool map update id "$B6" key hex $KEY6 value hex $(mono_ns_hex $TTL) || fail "expiry update"
drop0=$(metric drop)
for _ in 1 2 3; do send6 100; done
sleep 0.5
drop1=$(metric drop)
[ "${drop1:-0}" -ge $((${drop0:-0} + 3)) ] \
	&& ok "бан с TTL=${TTL}s дропает сразу (drop $drop0 -> $drop1)" \
	|| fail "свежий бан не дропает ($(stats))"

sleep $((TTL + 2))
drop2=$(metric drop); pass2=$(metric pass)
for _ in 1 2 3; do send6 100; done
sleep 0.5
drop3=$(metric drop); pass3=$(metric pass)
[ "${drop3:-0}" -eq "${drop2:-0}" ] && [ "${pass3:-0}" -gt "${pass2:-0}" ] \
	&& ok "бан истёк по монотонным часам (pass $pass2 -> $pass3, drop $drop2 -> $drop3)" \
	|| fail "бан не истёк (pass $pass2 -> $pass3, drop $drop2 -> $drop3)"

# Phase 4: UDP rate-limit (policy=2) for native IPv6.
# Policy is a .rodata global and libbpf freezes .rodata after load, so the
# object section is patched before loading. The offsets are pinned by the
# _Static_asserts in xdp/core/config.h: udp_policy @49, udp_hit_count @52.
POBJ="$OBJ.rl"
cp "$OBJ" "$POBJ"
if llvm-objcopy --dump-section .rodata="$POBJ.rodata" "$POBJ" \
	&& python3 - "$POBJ.rodata" <<'PY' \
	&& llvm-objcopy --update-section .rodata="$POBJ.rodata" "$POBJ"
import sys
path = sys.argv[1]
img = bytearray(open(path, "rb").read())
assert len(img) >= 56, f"unexpected .rodata size {len(img)}"
img[49] = 2                             # G_UDP_POLICY = rate-limit
img[52:56] = (3).to_bytes(4, "little")  # G_UDP_HIT_COUNT = 3 (fast trigger)
open(path, "wb").write(img)
PY
then
	# Reload with the patched policy; map ids are invalidated by the reload.
	ip link set "$DEV0" xdp off 2>/dev/null
	rm -f "$PIN"
	if bpftool prog load "$POBJ" "$PIN" type xdp \
		&& bpftool net attach xdp pinned "$PIN" dev "$DEV0"; then
		if discover_maps; then
			rl0=$(metric rate); pass0=$(metric pass)
			for _ in 1 2 3 4 5 6; do send6 100; done
			sleep 0.3
			rl1=$(metric rate); pass1=$(metric pass)
			[ "${rl1:-0}" -gt "${rl0:-0}" ] && [ "${pass1:-0}" -gt "${pass0:-0}" ] \
				&& ok "v6 UDP rate-limit policy=2 (rate $rl0 -> $rl1, pass $pass0 -> $pass1)" \
				|| fail "v6 UDP rate-limit не срабатывает ($(stats))"
		else
			fail "карты не найдены после перезагрузки с policy=2"
		fi
	else
		fail "объект с policy=2 не загрузился"
	fi
	rm -f "$POBJ" "$POBJ.rodata"
else
	fail "не удалось пропатчить .rodata (policy=2)"
fi

[ "$PASS" = 1 ] && echo "PASS: XDP-баны и UDP rate-limit (v4/v6) работают на живом ядре" || echo "FAIL"
[ "$PASS" = 1 ]