#!/usr/bin/env bash
# SYN-flood stress test of the XDP path inside an isolated netns+veth pair.
#
# Measures, while a flood runs against the protected port:
#   * how many packets XDP processed and dropped (rampart_xdp_* metrics);
#   * whether a legitimate client from another address keeps getting answers;
#   * CPU busy share of the host during the flood.
#
# Everything lives in a private namespace, so production interfaces and the
# host firewall are never touched. Keep RATE modest on a shared host.
#
# Run (root, kernel >= 5.15, iproute2, hping3, python3, curl):
#   BIN=./target/release/rampart bash scripts/xdp_stress.sh
# Tunables (env): DURATION=20 (seconds), INTERVAL_US=100 (hping gap, lower = faster),
#                 SOURCES=single|random

set -u

NS=rampart_stress
HOST_IP=10.244.250.1
LEGIT_IP=10.244.250.3
EDGE_IP=10.244.250.2
EDGE_PORT=9000
ORIGIN_PORT=9100
METRICS_PORT=9596
BIN=${BIN:-./target/release/rampart}
DURATION=${DURATION:-20}
INTERVAL_US=${INTERVAL_US:-100}
SOURCES=${SOURCES:-single}
# Spoofed random sources defeat the per-source SYN throttle (each address sends one
# SYN), so that mode relies on the stateless RST challenge instead.
[ "$SOURCES" = random ] && CHALLENGE=true || CHALLENGE=false
WORK=$(mktemp -d)
PIDS=()
PASS=1

fail() { echo "FAIL: $1"; PASS=0; }
ok()   { echo "ok:   $1"; }

cleanup() {
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null; done
    ip netns del "$NS" 2>/dev/null
    ip link del rsh0 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
[ -x "$BIN" ] || { echo "бинарь не найден: $BIN"; exit 2; }
command -v hping3 >/dev/null || { echo "нужен hping3"; exit 2; }

ip netns del "$NS" 2>/dev/null
ip netns add "$NS" || { echo "не удалось создать netns"; exit 2; }
ip link add rsh0 type veth peer name rstap
ip link set rstap netns "$NS"
ip addr add "$HOST_IP/24" dev rsh0
ip addr add "$LEGIT_IP/24" dev rsh0
ip link set rsh0 up
# veth hands XDP_TX frames (the RST-challenge SYN-ACK) to the peer only when the
# peer runs a native XDP program; attach a pass-through one (a real NIC needs none).
printf '%s\n' '__attribute__((section("xdp"), used)) int xdp_pass(void *ctx) { return 2; }' \
    'char _license[] __attribute__((section("license"), used)) = "GPL";' > "$WORK/xdp_pass.c"
if clang -O2 -target bpf -c "$WORK/xdp_pass.c" -o "$WORK/xdp_pass.o" 2>/dev/null \
    && ip link set dev rsh0 xdp obj "$WORK/xdp_pass.o" sec xdp; then
    :
elif [ "$CHALLENGE" = true ]; then
    echo "нужен clang для XDP pass на rsh0 (иначе challenge SYN-ACK теряется в veth)"; exit 2
fi
ip -n "$NS" addr add "$EDGE_IP/24" dev rstap
ip -n "$NS" link set rstap up
ip -n "$NS" link set lo up

cat > "$WORK/edge.toml" <<TOML
[bind]
address = "$EDGE_IP"
port = $EDGE_PORT

[backend]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]

[xdp]
enabled = true
interface = "rstap"
protected_port_start = $EDGE_PORT
protected_port_end = $EDGE_PORT
events_enabled = false
throttle_enabled = true
auto_ban_enabled = false
syn_challenge_enabled = $CHALLENGE
challenge_secret_hex = "$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

[metrics]
enabled = true
port = $METRICS_PORT

[pow]
enabled = false
TOML

echo "<html>rampart-stress-origin</html>" > "$WORK/index.html"
ip netns exec "$NS" python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 -d "$WORK" >/dev/null 2>&1 &
PIDS+=($!)
RAMPART_CONFIG="$WORK/edge.toml" ip netns exec "$NS" "$BIN" > "$WORK/rampart.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 40); do
    grep -q "XDP filter attached" "$WORK/rampart.log" && break
    sleep 0.5
done
if grep -q "XDP filter attached" "$WORK/rampart.log"; then
    ok "XDP attached: $(grep -oE 'mode: [a-z ()]+' "$WORK/rampart.log" | tail -1)"
else
    fail "XDP не аттачнулся"; tail -15 "$WORK/rampart.log"; exit 1
fi

legit() {
    curl -s -o /dev/null -w "%{http_code} %{time_total}" --interface "$LEGIT_IP" --max-time 8 \
        --retry 5 --retry-connrefused --retry-all-errors --retry-delay 1 \
        "http://$EDGE_IP:$EDGE_PORT/" 2>/dev/null || echo "000 8.000"
}
metric() {
    ip netns exec "$NS" curl -s --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" \
        | awk -v m="$1" '$1==m{print int($2)}'
}
cpu_busy() { # prints "busy total" jiffies from /proc/stat
    awk '/^cpu /{idle=$5+$6; t=0; for(i=2;i<=NF;i++)t+=$i; print t-idle, t}' /proc/stat
}

echo "baseline legit: $(legit)"

# Metrics are refreshed by the poller every 5 s; wait for a fresh sample.
sleep 6
V0=$(metric rampart_xdp_challenge_verified); S0=$(metric rampart_xdp_challenge_sent); T0=$(metric rampart_xdp_total); D0=$(metric rampart_xdp_dropped); P0=$(metric rampart_xdp_passed)
read -r B0 C0 < <(cpu_busy)

HPING_ARGS=(-S -p "$EDGE_PORT" -i "u$INTERVAL_US")
[ "$SOURCES" = random ] && HPING_ARGS+=(--rand-source)
ip netns exec "$NS" true  # namespace sanity
timeout "$DURATION" hping3 "${HPING_ARGS[@]}" "$EDGE_IP" > "$WORK/hping.log" 2>&1 &
PIDS+=($!)

# Probe the legitimate client during the flood.
OK_CNT=0; ALL_CNT=0; WORST=0
END=$((SECONDS + DURATION - 2))
while [ "$SECONDS" -lt "$END" ]; do
    read -r CODE TIME < <(legit)
    ALL_CNT=$((ALL_CNT + 1))
    [ "$CODE" = 200 ] && OK_CNT=$((OK_CNT + 1))
    WORST=$(awk -v a="$WORST" -v b="$TIME" 'BEGIN{print (b>a)?b:a}')
    sleep 1
done
wait "${PIDS[-1]}" 2>/dev/null
sleep 6
read -r B1 C1 < <(cpu_busy)
V1=$(metric rampart_xdp_challenge_verified); S1=$(metric rampart_xdp_challenge_sent); T1=$(metric rampart_xdp_total); D1=$(metric rampart_xdp_dropped); P1=$(metric rampart_xdp_passed)

VERIFIED=$((V1 - V0)); CHALLENGES=$((S1 - S0)); TOTAL=$((T1 - T0)); DROPPED=$((D1 - D0)); PASSED=$((P1 - P0))
PPS=$((TOTAL / (DURATION > 0 ? DURATION : 1)))
CPU=$(awk -v b=$((B1 - B0)) -v t=$((C1 - C0)) 'BEGIN{printf "%.0f", t ? 100*b/t : 0}')
echo "---- результат (источники: $SOURCES, ${DURATION}s) ----"
echo "XDP обработал: $TOTAL пакетов (~$PPS pps), дропнул: $DROPPED, пропустил: $PASSED"
echo "RST-challenge отправлено: $CHALLENGES, подтверждено живых клиентов: $VERIFIED"
echo "CPU хоста занят: ${CPU}%"
echo "легитимный клиент: $OK_CNT/$ALL_CNT успешно, худшее время ${WORST}s"

[ "$TOTAL" -gt 0 ] && ok "XDP видел флуд" || fail "XDP не обработал ни одного пакета"
if [ "$SOURCES" = random ]; then
    [ "$CHALLENGES" -gt 0 ] && ok "флуд отвечается RST-challenge ($CHALLENGES)" || fail "challenge не сработал"
    # The baseline request already verified the client, before the V0 snapshot.
    [ "${V1:-0}" -ge 1 ] && ok "живой клиент верифицирован (всего $V1)" || fail "ни один живой клиент не прошёл challenge"
else
    [ "$DROPPED" -gt 0 ] && ok "флуд дропается в XDP" || fail "XDP ничего не дропнул"
fi
if [ "$ALL_CNT" -gt 0 ] && [ $((OK_CNT * 10)) -ge $((ALL_CNT * 8)) ]; then
    ok "легитимный клиент обслуживается под флудом (>=80%)"
else
    fail "легитимный клиент деградировал ($OK_CNT/$ALL_CNT)"
fi

kill -TERM "${PIDS[1]}" 2>/dev/null
wait "${PIDS[1]}" 2>/dev/null
sleep 1
ip -n "$NS" link show rstap | grep -q xdp && fail "XDP остался после выхода" || ok "XDP отвязан после SIGTERM"

[ "$PASS" = 1 ] && { echo "PASS — xdp stress ($(uname -r))"; exit 0; }
echo "FAIL — xdp stress"; tail -20 "$WORK/rampart.log"; exit 1
