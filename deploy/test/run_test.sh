#!/usr/bin/env bash
set -euo pipefail

NET="rampart-test"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Создание сети ==="
docker network create "$NET" 2>/dev/null || true

echo "=== ClickHouse ==="
docker rm -f clickhouse 2>/dev/null || true
docker run -d --name clickhouse --network "$NET" \
  -v "$DIR/../clickhouse/schema.sql:/docker-entrypoint-initdb.d/schema.sql" \
  -p 8123:8123 \
  clickhouse/clickhouse-server:latest

echo "=== Grafana ==="
docker rm -f grafana 2>/dev/null || true
docker run -d --name grafana --network "$NET" \
  -p 3000:3000 \
  -e GF_INSTALL_PLUGINS=grafana-clickhouse-datasource \
  grafana/grafana:latest

echo "=== Backend (Minecraft stub) ==="
docker rm -f backend 2>/dev/null || true
# simple TCP echo server as placeholder
docker run -d --name backend --network "$NET" \
  alpine sh -c "apk add socat && socat TCP-LISTEN:25565,fork EXEC:'cat'"

echo "=== Rampart Edge ==="
docker rm -f rampart 2>/dev/null || true
TMPDIR=$(mktemp -d)
cp "$DIR/../../target/release/rampart-core" "$TMPDIR/"
cp "$DIR/../docker/Dockerfile.test" "$TMPDIR/Dockerfile"
docker build -t rampart-core "$TMPDIR"
rm -rf "$TMPDIR"
docker run -d --name rampart --network "$NET" \
  --cap-add=NET_ADMIN \
  -p 25565:25565 -p 9090:9090 \
  -e RAMPART_CONFIG=/etc/rampart/config.toml \
  -v "$DIR/config.test.toml:/etc/rampart/config.toml" \
  rampart-core

echo "=== Attacker (MHDDoS) ==="
docker rm -f attacker 2>/dev/null || true
docker run -d --name attacker --network "$NET" \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$DIR/../../ref/MHDDoS:/ref/MHDDoS" \
  python:3.11 bash -c "
    cd /ref/MHDDoS && pip install -r requirements.txt -q && \
    while true; do sleep 10; done
  "

echo ""
echo "=== Готово ==="
echo "Rampart edge: localhost:25565"
echo "Metrics:       http://localhost:9090/metrics"
echo "Grafana:       http://localhost:3000 (admin/admin)"
echo "ClickHouse:    http://localhost:8123"
echo ""
echo "Пример атаки:"
echo "  docker exec attacker python3 /ref/MHDDoS/start.py TCP rampart:25565 60 100"
echo ""
echo "Для остановки: docker rm -f rampart backend attacker clickhouse grafana"
