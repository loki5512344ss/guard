#!/usr/bin/env bash
# netns+veth smoke-тест XDP-пути на РЕАЛЬНОМ ядре (вывод №7 конкурентного анализа).
#
# Проверяет то, что невозможно проверить в контейнере CI без CAP_BPF:
#   1. verifier принимает universal_filter.o (загрузка через libbpf);
#   2. attach на живом интерфейсе в netns, native-режим;
#   3. легитимный HTTP проксируется;
#   4. SYN-флуд порождает ringbuf-события -> opt-in auto-ban работает;
#   5. по завершении бана трафик восстанавливается (expiry);
#   6. после SIGTERM XDP-ПРОГРАММА РЕАЛЬНО ОТВЯЗАНА (регрессия на bug fd=-1).
#
# Запуск: на хосте с root/CAP_BPF (VDS или VM-раннер CI), не в контейнере:
#   BIN=./target/release/rampart bash scripts/xdp_netns_smoke.sh
#
# Требования: iproute2, bpftool, hping3, python3 (http.server), curl.

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

cleanup() {
    [ -n "$RAMPID" ] && kill -9 "$RAMPID" 2>/dev/null
    [ -n "$SRVPID" ] && kill -9 "$SRVPID" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (CAP_BPF+CAP_NET_ADMIN)"; exit 2; }
[ -x "$BIN" ] || { echo "бинарь не найден: $BIN"; exit 2; }

# --- 1. netns + veth: весь тест изолирован, прод-трафик не затрагивается ---
ip netns del "$NS" 2>/dev/null
ip netns add "$NS" || { echo "не удалось создать netns"; exit 2; }
ip link add rth0 type veth peer name rtap
ip link set rtap netns "$NS"
ip addr add "$HOST_IP/24" dev rth0; ip link set rth0 up
ip -n "$NS" addr add "$EDGE_IP/24" dev rtap
ip -n "$NS" link set rtap up
ip -n "$NS" link set lo up
ok "netns $NS + veth подняты"

# --- 2. конфиг edge: узкий защищённый диапазон, автобан включён (иначе нечего тестить) ---
cat > "$WORK/edge.toml" <<EOF
[bind]
address = "$EDGE_IP"
port = $EDGE_PORT

[backend]
upstreams = ["$HOST_IP:$ORIGIN_PORT"]

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
level = "info"
format = "text"

[pow]
enabled = false
EOF

# --- 3. origin на host-половине veth ---
echo "<html><body>rampart-smoke-origin</body></html>" > "$WORK/index.html"
python3 -m http.server "$ORIGIN_PORT" --bind "$HOST_IP" -d "$WORK" >/dev/null 2>&1 &
SRVPID=$!
sleep 0.5

# --- 4. старт edge внутри netns, ожидание attach ---
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
    fail "XDP не аттачнулся; лог:"; sed -n '1,30p' "$WORK/rampart.log"; exit 1
fi

# Режим attach: native ожидаем на veth, но fallback на generic — штатный
# путь лестницы в load(); сверяем с честным логом режима от rampart.
if ip -n "$NS" link show rtap | grep -qE "xdp( |$)"; then
    ok "attach native (ip link: xdp)"
elif ip -n "$NS" link show rtap | grep -q "xdpgeneric"; then
    echo "warn: attach в generic (skb) — veth обычно тянет native, проверь лог"
else
    fail "на rtap нет XDP-программы после 'attached'"
fi
grep -oE "mode: [a-z ()]+" "$WORK/rampart.log" | tail -1

# --- 5. легитимный HTTP проходит прокси ---
BODY=$(curl -s --max-time 5 "http://$EDGE_IP:$EDGE_PORT/" || true)
echo "$BODY" | grep -q "rampart-smoke-origin" \
    && ok "легитимный HTTP проксируется" \
    || fail "легитимный HTTP не дошёл до origin"

# --- 6. SYN-флуд -> throttle -> ringbuf events -> auto-ban ---
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

# забаненный источник отклоняется до истечения 5с
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://$EDGE_IP:$EDGE_PORT/" || echo "err")
[ "$HTTP_CODE" = "err" ] || [ "$HTTP_CODE" = "000" ] \
    && ok "забаненный клиент отклонён (http=$HTTP_CODE)" \
    || fail "забаненный клиент получил ответ ($HTTP_CODE)"

# --- 7. expiry: через 7с (> ban 5s) трафик возвращается ---
sleep 7
BODY=$(curl -s --max-time 5 "http://$EDGE_IP:$EDGE_PORT/" || true)
echo "$BODY" | grep -q "rampart-smoke-origin" \
    && ok "бан истёк, легитимный трафик восстановлен" \
    || fail "после expiry трафик не восстановился"

# --- 8. ГРЕЙСФУЛ СТОП -> ПРОГРАММА ОТВЯЗАНА (регрессия на borrow_raw(-1)) ---
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

# --- итог ---
echo
if [ "$PASS" = 1 ]; then
    echo "PASS — xdp netns smoke ($(uname -r))"
    exit 0
else
    echo "FAIL — см. вывод выше; полный лог edge:"
    tail -40 "$WORK/rampart.log"
    exit 1
fi
