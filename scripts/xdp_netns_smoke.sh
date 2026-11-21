#!/usr/bin/env bash
# netns + veth smoke test of the XDP path on a real kernel (finding #7 of the
# concurrency analysis).
#
# Covers what cannot be checked in a CI container without CAP_BPF:
#   1. the verifier accepts universal_filter.o (loaded through libbpf);
#   2. attach on a live interface inside a netns, native mode;
#   3. legitimate HTTP is proxied;
#   4. a SYN flood produces ringbuf events, so opt-in auto-ban works;
#   5. traffic recovers once the ban expires;
#   6. after SIGTERM the XDP program is really detached (regression on the
#      fd=-1 bug).
#
# Run: on a host with root/CAP_BPF (VDS or a VM CI runner), not in a container:
#   BIN=./target/release/rampart bash scripts/xdp_netns_smoke.sh
#
# Requires: iproute2, bpftool, hping3, python3 (http.server), curl.

set -u

NS=rampart_smoke
SUBNET=10.244.251
HOST_IP=$SUBNET.1
EDGE_IP=$SUBNET.2
EDGE_PORT=9000
ORIGIN_PORT=9100
METRICS_PORT=9595
BIN=${BIN:-./target/release/rampart}
WORK=$(mktemp -d)
RAMPID=""
SRVPID=""
PASS=1

fail() { echo "FAIL: $1"; PASS=0; }
ok()   { echo "ok:   $1"; }

# Kill both processes and drop the namespace, whatever the exit path was.
cleanup() {
    [ -n "$RAMPID" ] && kill -9 "$RAMPID" 2>/dev/null
    [ -n "$SRVPID" ] && kill -9 "$SRVPID" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
[ -x "$BIN" ] || { echo "бинарь не найден: $BIN"; exit 2; }

# Phase 1: netns plus veth, so the whole test is isolated and production
# traffic is never touched.
ip netns del "$NS" 2>/dev/null
ip netns add "$NS" || { echo "не удалось создать netns"; exit 2; }
ip link add rth0 type veth peer name rtap
ip link set rtap netns "$NS"
ip addr add "$HOST_IP/24" dev rth0; ip link set rth0 up
ip -n "$NS" addr add "$EDGE_IP/24" dev rtap
ip -n "$NS" link set rtap up
ip -n "$NS" link set lo up
ok "netns $NS + veth подняты"

# Phase 2: edge config. The protected range is a single port and auto-ban is
# on, otherwise there is nothing to observe.
cat > "$WORK/edge.toml" <<EOF
[bind]
address = "$EDGE_IP"
port = $EDGE_PORT

[backend]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]

[limits]
handshake_timeout_secs = 5

[xdp]
enabled = true
interface = "rtap"
protected_port_start = $EDGE_PORT
protected_port_end = $EDGE_PORT
events_enabled = true
throttle_enabled = true
auto_ban_enabled = true
auto_ban_duration_secs = 5
auto_ban_conn_drop_fails = 3

[store]
redis_url = ""
blacklist_cache_ttl_secs = 300
clickhouse_url = ""

[metrics]
enabled = true
port = $METRICS_PORT

[logging]
# debug: the script greps per-event "xdp event" lines
level = "debug"
format = "text"

[pow]
enabled = false
EOF

# Phase 3: origin server inside the namespace, on loopback: a host firewall with
# INPUT DROP (ufw) would otherwise cut the edge off from an origin on the host half.
echo "<html><body>rampart-smoke-origin</body></html>" > "$WORK/index.html"
ip netns exec "$NS" python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 -d "$WORK" >/dev/null 2>&1 &
SRVPID=$!
sleep 0.5

# Phase 4: start edge inside the namespace and wait for the attach log line.
RUST_LOG=rampart=debug RAMPART_CONFIG="$WORK/edge.toml" \
    ip netns exec "$NS" "$BIN" > "$WORK/rampart.log" 2>&1 &
RAMPID=$!
ATTACHED=no
for _ in $(seq 60); do
    grep -q "XDP filter attached" "$WORK/rampart.log" && { ATTACHED=yes; break; }
    kill -0 "$RAMPID" 2>/dev/null || break
    sleep 0.5
done
if [ "$ATTACHED" = yes ]; then
    ok "XDP attached (verifier принят ядром $(uname -r))"
else
    fail "XDP не аттачнулся; лог (начало и конец):"; sed -n '1,6p' "$WORK/rampart.log"; echo '...'; tail -20 "$WORK/rampart.log"; exit 1
fi

# Attach mode: native is expected on veth, but generic is a normal fallback in
# the load() ladder, so compare against the mode rampart actually reports.
if ip -n "$NS" link show rtap | grep -qE "xdp( |$)"; then
    ok "attach native (ip link: xdp)"
elif ip -n "$NS" link show rtap | grep -q "xdpgeneric"; then
    echo "warn: attach в generic (skb) — veth обычно тянет native, проверь лог"
else
    fail "на rtap нет XDP-программы после 'attached'"
fi
grep -oE "mode: [a-z ()]+" "$WORK/rampart.log" | tail -1

# Phase 5: a legitimate HTTP request must reach the origin through the proxy.
BODY=$(curl -s --max-time 5 "http://$EDGE_IP:$EDGE_PORT/" || true)
echo "$BODY" | grep -q "rampart-smoke-origin" \
    && ok "легитимный HTTP проксируется" \
    || fail "легитимный HTTP не дошёл до origin"

# Phase 6: SYN flood, then throttle, ringbuf events and auto-ban.
hping3 -S -p "$EDGE_PORT" -c 4000 -i u200 "$EDGE_IP" >/dev/null 2>&1 || true
sleep 3
grep -q "xdp event" "$WORK/rampart.log" \
    && ok "ringbuf-события долетают до userspace" \
    || fail "ни одного 'xdp event' в логе"
if grep -q "xdp auto-ban issued" "$WORK/rampart.log"; then
    ok "auto-ban выдан по событию"
else
    fail "auto-ban не сработал"
fi
BANS=$(ip netns exec "$NS" curl -s --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" \
    | awk '/^rampart_xdp_autobans_total /{print $2}')
[ "${BANS:-0}" != "0" ] && ok "метрика rampart_xdp_autobans_total=$BANS" \
    || fail "метрика autobans пуста"

# A banned source is refused while the ban is active.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://$EDGE_IP:$EDGE_PORT/" || true)
# curl prints 000 when the connection is refused or dropped.
[ "${HTTP_CODE:-000}" = "000" ] \
    && ok "забаненный клиент отклонён (http=$HTTP_CODE)" \
    || fail "забаненный клиент получил ответ ($HTTP_CODE)"

# Phase 7: expiry. The in-kernel SYN ban lasts syn_ban_duration_ns (60 s, a
# constant in XdpGlobals, not the userspace auto_ban_duration_secs), so poll
# until traffic returns on its own instead of sleeping a fixed time.
RECOVERED=no
for _ in $(seq 16); do
    sleep 5
    BODY=$(curl -s --max-time 3 "http://$EDGE_IP:$EDGE_PORT/" || true)
    echo "$BODY" | grep -q "rampart-smoke-origin" && { RECOVERED=yes; break; }
done
[ "$RECOVERED" = yes ] \
    && ok "бан истёк, легитимный трафик восстановлен" \
    || fail "после expiry трафик не восстановился"

# Phase 8: graceful stop must leave no program behind (regression on
# borrow_raw(-1) during detach).
kill -TERM "$RAMPID"
wait "$RAMPID"; RC=$?
RAMPID=""
[ "$RC" = 0 ] && ok "rampart завершился с кодом 0" || fail "код выхода rampart: $RC"
grep -q "XDP filter detached" "$WORK/rampart.log" \
    && ok "лог: detach выполнен" || fail "в логе нет строки detach"
sleep 1
if ip -n "$NS" link show rtap | grep -q "xdp"; then
    fail "XDP ПРОГРАММА ОСТАЛАСЬ НА ИНТЕРФЕЙСЕ ПОСЛЕ ВЫХОДА ПРОЦЕССА (detach сломан)"
else
    ok "XDP-программа реально отвязана после SIGTERM"
fi

# Phase 9: the runbook recovery procedure (docs/runbook.md, "Если нода
# заблокировала администратора"). A crashed edge leaves the program on the NIC;
# `ip link set dev <if> xdp off` must remove it without the daemon.
RAMPART_CONFIG="$WORK/edge.toml" ip netns exec "$NS" "$BIN" > "$WORK/rampart2.log" 2>&1 &
RAMPID=$!
for _ in $(seq 40); do
    grep -q "XDP filter attached" "$WORK/rampart2.log" && break
    sleep 0.5
done
kill -9 "$RAMPID" 2>/dev/null; wait "$RAMPID" 2>/dev/null; RAMPID=""
if ip -n "$NS" link show rtap | grep -q "xdp"; then
    ok "после kill -9 программа осталась на интерфейсе (ожидаемо)"
    ip -n "$NS" link set dev rtap xdp off
    ip -n "$NS" link show rtap | grep -q "xdp" \
        && fail "recovery: 'ip link set dev rtap xdp off' не снял программу" \
        || ok "recovery: 'ip link set dev <if> xdp off' снимает программу без демона"
else
    fail "после kill -9 программы нет на интерфейсе: нечего восстанавливать (проверка бессмысленна)"
fi

# Summary: exit code drives CI, the log excerpt makes a failure diagnosable.
echo
if [ "$PASS" = 1 ]; then
    echo "PASS — xdp netns smoke ($(uname -r))"
    exit 0
else
    echo "FAIL — см. вывод выше; полный лог edge:"
    tail -40 "$WORK/rampart.log"
    exit 1
fi
