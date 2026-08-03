#!/usr/bin/env bash
set -euo pipefail

PAPER_VERSION="${PAPER_VERSION:-1.21}"
PAPER_BUILD="${PAPER_BUILD:-latest}"
OUT="${PAPER_OUT:-deploy/docker/downloads/paper.jar}"
UA="rampart/1.0.0 (https://github.com/loki5512344/rampart)"

mkdir -p "$(dirname "${OUT}")"

if [ "${PAPER_BUILD}" = "latest" ]; then
  PAPER_BUILD="$(curl -fsSL -H "User-Agent: ${UA}" \
    "https://fill.papermc.io/v3/projects/paper/versions/${PAPER_VERSION}/builds" \
    | jq -r 'first(.[] | select(.channel == "STABLE") | .id) // empty')"
fi

URL="$(curl -fsSL -H "User-Agent: ${UA}" \
  "https://fill.papermc.io/v3/projects/paper/versions/${PAPER_VERSION}/builds" \
  | jq -r --arg b "${PAPER_BUILD}" 'first(.[] | select(.id == ($b | tonumber)) | .downloads."server:default".url) // empty')"

if [ -z "${URL}" ]; then
  echo "error: no Paper download URL found for version ${PAPER_VERSION} build ${PAPER_BUILD}" >&2
  exit 1
fi

echo "Downloading Paper ${PAPER_VERSION} build ${PAPER_BUILD}"
case "${URL}" in
  http*) JAR_URL="${URL}" ;;
  *) JAR_URL="https://fill.papermc.io${URL}" ;;
esac
curl -fsSLo "${OUT}" -H "User-Agent: ${UA}" "${JAR_URL}"
echo "Saved ${OUT}"
