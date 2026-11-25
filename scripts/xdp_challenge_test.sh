#!/usr/bin/env bash
# RST-challenge on a real kernel (netns + veth), client behind a stateful firewall.
#
# Checks:
#   1. a live client passes the challenge and gets HTTP 200 quickly, even with
#      "ct state INVALID drop" in its namespace (ufw, NAT routers): the bogus
#      ack must stay inside the client's conntrack window;
#   2. a verified client opens a second connection without a new challenge;
#   3. spoofed SYNs are answered but never verified;
#   4. a forged RST with a wrong seq fails the challenge;
#   5. the same for native IPv6 (live client, spoofed SYNs, forged RST), with
#      its own 128-bit tables.
#
# Both ends live in private namespaces, so the host firewall is never touched.
# veth delivers XDP_TX frames only when the peer runs a native XDP program, so
# a pass-through program is attached to the client side (a real NIC needs none).
#
# Run (root, kernel >= 5.15, iproute2, clang, hping3, python3, curl, iptables or nft):
#   BIN=./target/release/rampart bash scripts/xdp_challenge_test.sh

set -u

CNS=rampart_chal_cli
ENS=rampart_chal_edge
CLI_IP=10.244.252.1
EDGE_IP=10.244.252.2
SPOOF_IP=10.244.252.77
FORGE_IP=10.244.252.78
CLI_IP6=fd00:244:252::1
EDGE_IP6=fd00:244:252::2
SPOOF_IP6=fd00:244:252::77
FORGE_IP6=fd00:244:252::78
EDGE_PORT=9000
ORIGIN_PORT=9100
METRICS_PORT=9598
BIN=${BIN:-./target/release/rampart}
WORK=$(mktemp -d)
PIDS=()
PASS=1

fail() { echo "FAIL: $1"; PASS=0; }
ok()   { echo "ok:   $1"; }

cleanup() {
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null; done
    ip netns del "$CNS" 2>/dev/null
    ip netns del "$ENS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
[ -x "$BIN" ] || { echo "бинарь не найден: $BIN"; exit 2; }
for tool in clang hping3 curl python3; do
    command -v "$tool" >/dev/null || { echo "нужен $tool"; exit 2; }
done

ip netns del "$CNS" 2>/dev/null; ip netns del "$ENS" 2>/dev/null
ip netns add "$CNS" && ip netns add "$ENS" || { echo "не удалось создать netns"; exit 2; }
ip link add rchc0 netns "$CNS" type veth peer name rche0 netns "$ENS"
ip -n "$CNS" addr add "$CLI_IP/24" dev rchc0
ip -n "$ENS" addr add "$EDGE_IP/24" dev rche0
ip -n "$CNS" addr add "$CLI_IP6/64" dev rchc0 nodad
ip -n "$ENS" addr add "$EDGE_IP6/64" dev rche0 nodad
for ns in "$CNS" "$ENS"; do ip -n "$ns" link set lo up; done
ip -n "$CNS" link set rchc0 up
ip -n "$ENS" link set rche0 up

# Pass-through XDP on the client end; no headers needed (XDP_PASS == 2).
cat > "$WORK/xdp_pass.c" <<'C'
__attribute__((section("xdp"), used)) int xdp_pass(void *ctx) { return 2; }
char _license[] __attribute__((section("license"), used)) = "GPL";
C
clang -O2 -target bpf -c "$WORK/xdp_pass.c" -o "$WORK/xdp_pass.o" \
    || { echo "не удалось собрать xdp_pass.o"; exit 2; }
ip -n "$CNS" link set dev rchc0 xdp obj "$WORK/xdp_pass.o" sec xdp \
    || { echo "не удалось повесить XDP pass на клиентский veth"; exit 2; }

# Stateful firewall on the client: drop conntrack-INVALID input like ufw does.
if ip netns exec "$CNS" iptables -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null \
    && ip netns exec "$CNS" ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null; then
    ok "клиент за фаерволом: ip(6)tables ctstate INVALID DROP"
elif ip netns exec "$CNS" nft -f - 2>/dev/null <<'NFT'
table inet rampart_chal { chain input { type filter hook input priority 0; ct state invalid drop; } }
NFT
then
    ok "клиент за фаерволом: nft ct state invalid drop"
else
    fail "не удалось включить conntrack INVALID DROP (нет iptables/nft с conntrack)"
fi

cat > "$WORK/edge.toml" <<TOML
[bind]
address = "::"
port = $EDGE_PORT

[backend]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]

[xdp]
enabled = true
interface = "rche0"
protected_port_start = $EDGE_PORT
protected_port_end = $EDGE_PORT
events_enabled = false
throttle_enabled = false
auto_ban_enabled = false
syn_challenge_enabled = true
challenge_secret_hex = "$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

[metrics]
enabled = true
port = $METRICS_PORT

[pow]
enabled = false
TOML

echo "<html>rampart-challenge-origin</html>" > "$WORK/index.html"
ip netns exec "$ENS" python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 -d "$WORK" >/dev/null 2>&1 &
PIDS+=($!)
RAMPART_CONFIG="$WORK/edge.toml" ip netns exec "$ENS" "$BIN" > "$WORK/rampart.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 40); do
    grep -q "XDP filter attached" "$WORK/rampart.log" && break
    sleep 0.5
done
grep -q "XDP filter attached" "$WORK/rampart.log" \
    || { fail "XDP не аттачнулся"; tail -15 "$WORK/rampart.log"; exit 1; }
ok "XDP attached, syn_challenge_enabled = true"

# Spoofed IPv6 TCP segment over a raw socket (hping3 has no IPv6):
#   send6 <src> <dst> <sport> <dport> <S|R> <seq> [count]
cat > "$WORK/send6.py" <<'PY'
import socket, struct, sys, random
src, dst, sport, dport, flag, seq = sys.argv[1:7]
count = int(sys.argv[7]) if len(sys.argv) > 7 else 1
s6, d6 = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
flags = {"S": 0x02, "R": 0x04}[flag]
def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16: t = (t & 0xFFFF) + (t >> 16)
    return ~t & 0xFFFF
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
for i in range(count):
    sp = int(sport) + i if count > 1 else int(sport)
    sq = int(seq) if seq != "rand" else random.getrandbits(32)
    tcp = struct.pack("!HHIIBBHHH", sp, int(dport), sq, 0, 5 << 4, flags, 64240, 0, 0)
    c = csum(s6 + d6 + struct.pack("!IxxxB", len(tcp), 6) + tcp)
    tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
    ip6 = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + s6 + d6
    sock.sendto(ip6 + tcp, (dst, 0))
PY
send6() { ip netns exec "$CNS" python3 "$WORK/send6.py" "$@"; }

client_get() {
    ip netns exec "$CNS" curl -s -o /dev/null -w "%{http_code} %{time_total}" --max-time 5 \
        "http://$EDGE_IP:$EDGE_PORT/" 2>/dev/null
    true # curl prints the -w line even on failure
}
client_get6() {
    ip netns exec "$CNS" curl -s -o /dev/null -w "%{http_code} %{time_total}" --max-time 5 \
        "http://[$EDGE_IP6]:$EDGE_PORT/" 2>/dev/null
    true
}
# The poller refreshes the metrics every 5 s.
metrics() {
    sleep 6
    ip netns exec "$ENS" curl -s --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" > "$WORK/metrics"
}
metric() { awk -v m="$1" '$1==m{print int($2)}' "$WORK/metrics"; }

# 1. Live client behind conntrack passes on the first connect.
read -r CODE TIME < <(client_get)
if [ "$CODE" = 200 ] && awk -v t="$TIME" 'BEGIN{exit !(t < 3)}'; then
    ok "живой клиент прошёл challenge: HTTP $CODE за ${TIME}s"
else
    fail "живой клиент не прошёл challenge: HTTP $CODE за ${TIME}s"
fi
metrics
SENT1=$(metric rampart_xdp_challenge_sent); VER1=$(metric rampart_xdp_challenge_verified)
[ "${VER1:-0}" -ge 1 ] && ok "challenge_verified = $VER1" || fail "challenge_verified = ${VER1:-?}, ждали >= 1"

# 2. Verified source reconnects without a new challenge.
read -r CODE TIME < <(client_get)
[ "$CODE" = 200 ] && ok "повторное соединение: HTTP $CODE" || fail "повторное соединение: HTTP $CODE"

# 3. Spoofed sources get a challenge but never verify.
ip netns exec "$CNS" hping3 -q -S -p "$EDGE_PORT" -a "$SPOOF_IP" -c 3 -i u20000 "$EDGE_IP" >/dev/null 2>&1

# 4. A forged RST (wrong seq) after a spoofed SYN fails the challenge.
ip netns exec "$CNS" hping3 -q -S -p "$EDGE_PORT" -a "$FORGE_IP" -s 41000 -k -c 1 "$EDGE_IP" >/dev/null 2>&1
ip netns exec "$CNS" hping3 -q -R -p "$EDGE_PORT" -a "$FORGE_IP" -s 41000 -k -M 1 -c 1 "$EDGE_IP" >/dev/null 2>&1

metrics
SENT2=$(metric rampart_xdp_challenge_sent); VER2=$(metric rampart_xdp_challenge_verified)
FAILED2=$(metric rampart_xdp_challenge_failed)
NEW_SENT=$(( ${SENT2:-0} - ${SENT1:-0} ))
[ "$NEW_SENT" -ge 4 ] && ok "спуфленные SYN получили challenge ($NEW_SENT)" \
    || fail "ждали >= 4 новых challenge (3 спуфа + 1 forge), получили $NEW_SENT"
[ "${VER2:-0}" = "${VER1:-0}" ] && ok "спуф/forge не верифицированы (verified = $VER2)" \
    || fail "verified вырос с $VER1 до $VER2 без живого клиента"
[ "${FAILED2:-0}" -ge 1 ] && ok "поддельный RST провалил challenge (failed = $FAILED2)" \
    || fail "поддельный RST не засчитан как failed (failed = ${FAILED2:-?})"

# 5. Native IPv6: own tables, same contract.
read -r CODE TIME < <(client_get6)
if [ "$CODE" = 200 ] && awk -v t="$TIME" 'BEGIN{exit !(t < 3)}'; then
    ok "IPv6: живой клиент прошёл challenge: HTTP $CODE за ${TIME}s"
else
    fail "IPv6: живой клиент не прошёл challenge: HTTP $CODE за ${TIME}s"
fi
send6 "$SPOOF_IP6" "$EDGE_IP6" 42000 "$EDGE_PORT" S rand 3
send6 "$FORGE_IP6" "$EDGE_IP6" 43000 "$EDGE_PORT" S rand
send6 "$FORGE_IP6" "$EDGE_IP6" 43000 "$EDGE_PORT" R 1
metrics
SENT3=$(metric rampart_xdp_challenge_sent); VER3=$(metric rampart_xdp_challenge_verified)
FAILED3=$(metric rampart_xdp_challenge_failed)
[ $(( ${VER3:-0} - ${VER2:-0} )) = 1 ] && ok "IPv6: верифицирован ровно живой клиент (verified = $VER3)" \
    || fail "IPv6: verified $VER2 -> $VER3, ждали +1 (только живой клиент)"
[ $(( ${SENT3:-0} - ${SENT2:-0} )) -ge 5 ] && ok "IPv6: challenge выданы ($(( SENT3 - SENT2 )))" \
    || fail "IPv6: ждали >= 5 новых challenge (клиент + 3 спуфа + forge), получили $(( ${SENT3:-0} - ${SENT2:-0} ))"
[ $(( ${FAILED3:-0} - ${FAILED2:-0} )) -ge 1 ] && ok "IPv6: поддельный RST провалил challenge" \
    || fail "IPv6: поддельный RST не засчитан как failed"

[ "$PASS" = 1 ] && { echo "PASS — xdp challenge ($(uname -r))"; exit 0; }
echo "FAIL — xdp challenge"; tail -20 "$WORK/rampart.log"; exit 1
