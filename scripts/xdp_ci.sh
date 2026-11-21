#!/usr/bin/env bash
# Single entry point for the XDP checks on a real kernel (netns + veth).
#
#   sudo bash scripts/xdp_ci.sh            # local run
#   bash scripts/xdp_ci.sh --require       # a SKIP becomes a failure (exit 3)
#   BIN=./target/release/rampart bash scripts/xdp_ci.sh   # skip the build
#
# Phases (each prints one machine-readable line `RESULT <name> PASS|FAIL|SKIP`):
#   pkt    scripts/xdp_pkt_test.sh      VLAN/QinQ, fragments, Ethernet padding
#   smoke  scripts/xdp_netns_smoke.sh   verifier, attach, proxy, ban, expiry, detach
#   ipv6   scripts/xdp_ipv6_smoke.sh    opt-in via --with-ipv6 (known gaps, see docs/testing.md)
#
# Exit codes: 0 all passed (or honestly skipped), 1 a phase failed,
#             2 usage, 3 skipped while --require was given.
# Without privileges or tools the run prints `SKIP: <reason>` and never reports
# a green result for something that did not execute.

set -u

REQUIRE=0
WITH_IPV6=0
for arg in "$@"; do
    case "$arg" in
        --require) REQUIRE=1 ;;
        --with-ipv6) WITH_IPV6=1 ;;
        --ci) ;; # accepted for CI call sites: output is always CI-friendly
        *) echo "usage: $0 [--require] [--with-ipv6] [--ci]"; exit 2 ;;
    esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 2

skip() {
    echo "SKIP: $1"
    echo "RESULT xdp_ci SKIP"
    [ "$REQUIRE" = 1 ] && exit 3
    exit 0
}

# --- privileges: root, or passwordless sudo (re-exec keeping the environment).
if [ "$(id -u)" != 0 ]; then
    if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
        exec sudo -n -E bash "$0" "$@"
    fi
    skip "нужен root (CAP_BPF + CAP_NET_ADMIN): запустите через sudo"
fi

# --- kernel >= 5.10.
KERNEL=$(uname -r)
if [ "$(printf '%s\n%s\n' 5.10 "${KERNEL%%-*}" | sort -V | head -1)" != 5.10 ]; then
    skip "ядро $KERNEL старше 5.10"
fi

# --- tools. Ubuntu ships `bpftool` as a wrapper that fails when linux-tools for the
# running kernel is missing, so look for a real binary before giving up.
for tool in ip clang python3 curl hping3; do
    command -v "$tool" >/dev/null || skip "не найден '$tool'"
done
if ! bpftool version >/dev/null 2>&1; then
    REAL=$(ls /usr/lib/linux-tools*/bpftool /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
    [ -n "$REAL" ] || skip "нет рабочего bpftool (установите linux-tools для ядра $KERNEL)"
    SHIM=$(mktemp -d)
    ln -s "$REAL" "$SHIM/bpftool"
    export PATH="$SHIM:$PATH"
    trap 'rm -rf "$SHIM"' EXIT
fi
ip netns add rampart_ci_probe 2>/dev/null && ip netns del rampart_ci_probe \
    || skip "не удалось создать netns (контейнер без CAP_NET_ADMIN?)"

# --- binary.
if [ -z "${BIN:-}" ]; then
    echo "== build: cargo build --release --features xdp,protocol-http --bin rampart"
    cargo build --release --features xdp,protocol-http --bin rampart || { echo "RESULT build FAIL"; exit 1; }
    BIN=$ROOT/target/release/rampart
fi
export BIN
[ -x "$BIN" ] || { echo "бинарь не найден: $BIN"; echo "RESULT build FAIL"; exit 1; }

FAILED=0
run_phase() {
    local name=$1 script=$2
    echo "== $name: bash $script"
    if bash "$script"; then
        echo "RESULT $name PASS"
    else
        echo "RESULT $name FAIL"
        FAILED=1
    fi
}

run_phase pkt scripts/xdp_pkt_test.sh
run_phase smoke scripts/xdp_netns_smoke.sh
[ "$WITH_IPV6" = 1 ] && run_phase ipv6 scripts/xdp_ipv6_smoke.sh

if [ "$FAILED" = 0 ]; then
    echo "RESULT xdp_ci PASS (kernel $KERNEL)"
    exit 0
fi
echo "RESULT xdp_ci FAIL (kernel $KERNEL)"
exit 1
