#!/usr/bin/env bash
set -euo pipefail

NET="rampart-test"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Сборка rampart ==="
cargo build --release --bin rampart

echo "=== Создание сети ==="
docker network create "$NET" 2>/dev/null || true

echo "=== Backend stub (TCP echo) ==="
docker rm -f backend 2>/dev/null || true
docker run -d --name backend --network "$NET" \
  alpine sh -c "apk add socat && socat TCP-LISTEN:25566,fork EXEC:'cat'"

echo "=== Rampart Edge ==="
docker rm -f rampart 2>/dev/null || true
TMPDIR=$(mktemp -d)
cp "$DIR/../../target/release/rampart" "$TMPDIR/"
cp "$DIR/../docker/Dockerfile.test" "$TMPDIR/Dockerfile"
docker build -t rampart "$TMPDIR"
rm -rf "$TMPDIR"
docker run -d --name rampart --network "$NET" \
  -p 25565:25565 -p 9090:9090 \
  -e RAMPART_CONFIG=/etc/rampart/config.toml \
  -v "$DIR/config.test.toml:/etc/rampart/config.toml" \
  rampart

echo "=== Attacker ==="
docker rm -f attacker 2>/dev/null || true
docker run -d --name attacker --network "$NET" \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$DIR/stress/flood.py:/flood.py:ro" \
  debian:bookworm-slim bash -c "
    apt-get update -qq && apt-get install -y -qq python3 iproute2 >/dev/null && \
    while true; do sleep 10; done
  "

echo ""
echo "=== Готово ==="
echo "Rampart edge: localhost:25565"
echo "Metrics:       http://localhost:9090/metrics"
echo ""
echo "Пример атаки:"
echo "  docker exec attacker python3 /flood.py --target rampart --port 25566 --mode connect --duration 30 --threads 50"
echo "Легитимный клиент:"
echo "  python3 $DIR/stress/legit.py --target localhost --port 25565"
echo ""
echo "Для остановки: docker rm -f rampart backend attacker"
