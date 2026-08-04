#!/usr/bin/env bash
set -euo pipefail

NET="rampart-stress-net"
SUB="172.30.0.0/24"
EDGE_IP="172.30.0.2"
ATT_IP="172.30.0.3"
DIR="${DIR:-$(cd "$(dirname "$0")" && pwd)}"
IPS_START=101
IPS_END=200

edge_metrics() {
  curl -s --max-time 5 http://127.0.0.1:9090/metrics 2>/dev/null | grep -E '^rampart_' || true
}
mget() {
  local label="$1"
  local val
  val=$(edge_metrics | grep -F "$label" | awk '{print $NF}' | head -1)
  echo "${val:-0}"
}
edge_cpu() {
  docker stats --no-stream --format '{{.CPUPerc}}' rampart-edge 2>/dev/null || echo "?"
}

start_edge() {
  local cfg="$1"
  docker rm -f rampart-edge 2>/dev/null || true
  docker run -d --name rampart-edge --network "$NET" --ip "$EDGE_IP" \
    -p 127.0.0.1:25565:25565 -p 127.0.0.1:9090:9090 \
    -v "$DIR/configs/$cfg:/etc/rampart/config.toml:ro" \
    rampart-edge >/dev/null
  for _ in $(seq 1 30); do
    if edge_metrics | grep -q rampart_; then return 0; fi
    sleep 2
  done
  echo "ERROR: edge не поднялся" >&2
  return 1
}

run_flood_phase() {
  local phase="$1" cfg="$2" duration="$3" mode="$4" threads="$5" ips="$6" name="$7"
  echo ""
  echo "=============================================================="
  echo "ФАЗА $phase: $name (cfg=$cfg, duration=${duration}s, mode=$mode, ips=$ips, threads=$threads)"
  echo "=============================================================="
  start_edge "$cfg"

  local ba bb bp
  ba=$(mget 'rampart_connections_total{result="allowed"}')
  bb=$(mget 'rampart_connections_total{result="blocked"}')
  bp=$(mget 'rampart_pow_challenges_total{result="failed"}')
  echo "baseline: allowed=$ba blocked=$bb pow_fail=$bp"

  docker exec rampart-attacker python3 /flood.py \
    --target "$EDGE_IP" --port 25565 --mode "$mode" \
    --duration "$duration" --threads "$threads" \
    --ips-start "$IPS_START" --ips-end "$ips" \
    > /tmp/flood_$phase.log 2>&1 &
  local flood_pid=$!

  python3 "$DIR/legit.py" --target 127.0.0.1 --port 25565 \
    --count 5 --interval $((duration / 5)) --name "phase$phase" \
    > /tmp/legit_$phase.log 2>&1 &
  local legit_pid=$!

  for i in $(seq 1 $((duration / 5))); do
    sleep 5
    local a bl p s cpu
    a=$(mget 'rampart_connections_total{result="allowed"}')
    bl=$(mget 'rampart_connections_total{result="blocked"}')
    p=$(mget 'rampart_pow_challenges_total{result="failed"}')
    s=$(mget 'rampart_attack_status ')
    cpu=$(edge_cpu)
    echo "  [t=${i}x5s] status=$s cpu=$cpu allowed=+$((a - ba)) blocked=+$((bl - bb)) pow_fail=+$((p - bp))"
  done

  wait "$flood_pid" || true
  wait "$legit_pid" || true

  local ea eb ep es ec
  ea=$(mget 'rampart_connections_total{result="allowed"}')
  eb=$(mget 'rampart_connections_total{result="blocked"}')
  ep=$(mget 'rampart_pow_challenges_total{result="failed"}')
  es=$(mget 'rampart_attack_status ')
  ec=$(edge_cpu)
  echo "--- итог фазы $phase ---"
  echo "  attack_status=$es cpu=$ec"
  echo "  allowed:  $((ea - ba))  (+$(( (ea - ba) / duration ))/s)"
  echo "  blocked:  $((eb - bb))  (+$(( (eb - bb) / duration ))/s)"
  echo "  pow_fail: $((ep - bp))"
  echo "--- легитимные клиенты во время фазы ---"
  grep -E '^\[phase' /tmp/legit_$phase.log || true
  echo ""
}

echo "=== [setup] сеть + образы ==="
docker rm -f rampart-edge rampart-attacker 2>/dev/null || true
docker network rm -f "$NET" 2>/dev/null || true
docker network create --subnet "$SUB" "$NET" >/dev/null

# Подготовка контекстов: бинарь ищем в target/release репозитория
mkdir -p "$DIR/edge-ctx" "$DIR/attacker-ctx"
cp "$DIR/flood.py" "$DIR/attacker-ctx/flood.py" 2>/dev/null || true
if [ ! -f "$DIR/edge-ctx/rampart-core" ]; then
  for p in "$DIR/rampart-core" "$DIR/repo/target/release/rampart-core" "$DIR/../target/release/rampart-core"; do
    if [ -f "$p" ]; then cp "$p" "$DIR/edge-ctx/rampart-core"; break; fi
  done
fi
[ -f "$DIR/edge-ctx/rampart-core" ] || { echo "ERROR: rampart-core не найден. Собери: cargo build --release --bin rampart-core" >&2; exit 1; }

docker build -q -f "$DIR/edge.Dockerfile" -t rampart-edge "$DIR/edge-ctx"
docker build -q -f "$DIR/attacker.Dockerfile" -t rampart-attacker "$DIR/attacker-ctx"

echo "=== [setup] attacker + 100 source IP ==="
docker rm -f rampart-attacker 2>/dev/null || true
docker run -d --name rampart-attacker --network "$NET" --ip "$ATT_IP" \
  --cap-add=NET_RAW --cap-add=NET_ADMIN rampart-attacker >/dev/null
docker exec rampart-attacker sh -c '
  for i in $(seq 101 200); do
    ip addr add 172.30.0.$i/24 dev eth0 2>/dev/null || true
  done
  echo "source IPs on eth0: $(ip addr show eth0 | grep -c "inet ")"
'

echo ""
echo "############### PHASE A: СЫРАЯ ПРОПУСКНАЯ СПОСОБНОСТЬ ###############"
echo "############### (лимиты сняты: 100k pps, 100 src IP, валидные handshake) ###############"
run_flood_phase A edge-high.toml 30 handshake 100 "$IPS_END" "raw throughput, 100 IP flood, valid handshake"

echo ""
echo "############### PHASE B: ЗАЩИТА (дефолтные лимиты 5 pps/IP) ###############"
echo "############### (та же атака, но теперь edge режет по IP; легитимные клиенты заходят) ###############"
run_flood_phase B edge-defense.toml 30 handshake 100 "$IPS_END" "defense, rate limit 5pps/IP + reputation bans"

echo ""
echo "############### PHASE C: SYN flood ###############"
echo "=============================================================="
echo "ФАЗА C: SYN flood hping3 (rand-source, 20s)"
echo "=============================================================="
ba=$(mget 'rampart_connections_total{result="allowed"}')
bb=$(mget 'rampart_connections_total{result="blocked"}')
timeout 20 docker exec rampart-attacker hping3 -S --flood --rand-source -p 25565 "$EDGE_IP" || true
sleep 2
ea=$(mget 'rampart_connections_total{result="allowed"}')
eb=$(mget 'rampart_connections_total{result="blocked"}')
es=$(mget 'rampart_attack_status ')
echo "  attack_status=$es cpu=$(edge_cpu) allowed=+$((ea - ba)) blocked=+$((eb - bb))"
echo "  (SYN flood обрабатывается kernel'ом/XDP, L7 edge почти не задет)"
echo ""

echo ""
echo "############### PHASE D: активные соединения (keepalive) ###############"
echo "=============================================================="
echo "ФАЗА D: 300 keepalive коннектов (валидный handshake, держим открытым)"
echo "=============================================================="
start_edge edge-high.toml
ba=$(mget 'rampart_connections_total{result="allowed"}')
docker exec rampart-attacker python3 /flood.py \
  --target "$EDGE_IP" --port 25565 --mode keepalive \
  --duration 20 --threads 300 --ips-start "$IPS_START" --ips-end "$IPS_END" || true
sleep 2
ea=$(mget 'rampart_connections_total{result="allowed"}')
echo "  allowed=+$((ea - ba)) cpu=$(edge_cpu)"

echo ""
echo "=============================================================="
echo "ИТОГОВЫЙ СВОД"
echo "=============================================================="
edge_metrics | grep -E 'connections_total|pow_challenges|attack_status'
echo ""
echo "CPU/память контейнеров:"
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' rampart-edge rampart-attacker
