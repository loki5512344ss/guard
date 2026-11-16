#!/usr/bin/env bash
#
# check_default_secrets.sh — reject placeholder and weak secrets committed as
# real values in code, deploy configs, or docs.
#
# Catches:
#   1. the literal placeholder "changeme";
#   2. Compose-style fallbacks to weak defaults, e.g. ${REDIS_PASSWORD:-rampart_dev}
#      or ${GRAFANA_PASSWORD:-admin};
#   3. Redis `requirepass` with a weak or empty password.
#
# Intentional occurrences are whitelisted in two layers:
#   1. File level — the validation code itself:
#        src/bin/rampart-manager.rs  (startup guard rejecting the default)
#        src/manager/security.rs     (password/secret policy + placeholders)
#        src/manager/api/auth.rs     (login handler)
#   2. Line level — a matching line is skipped when it contains "must not be" or
#      "test" (case-insensitive), states the prohibition ("запр" root: запрет /
#      запрещено / запрещён — the project docs are partly Russian), or is a
#      comment / markdown table row (starts with '#', '//', '*', '|', '--').
#
# Any remaining occurrence is an offender -> exit 1, offending lines listed.

set -u

SCAN_DIRS="src deploy docs"
FILE_WHITELIST="src/bin/rampart-manager.rs src/manager/security.rs src/manager/api/auth.rs"

# "<extended regex>@@<human description>" pairs. The `|` inside alternations is
# safe because entries are split on the first `@@`.
PATTERNS=(
    'changeme@@placeholder password "changeme"'
    '\$\{[A-Za-z_][A-Za-z0-9_]*:-[[:space:]]*(rampart_dev|admin|password|secret|root)@@fallback to a weak default value'
    "requirepass[[:space:]]+[\"']?[[:space:]]*(rampart_dev|admin|password|redis|secret|root)@@requirepass with a weak password"
    "requirepass[[:space:]]*([\"']{2})?[[:space:]]*\$@@requirepass without a password"
)

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 1

offenders=$(mktemp)
trap 'rm -f "$offenders"' EXIT

for dir in $SCAN_DIRS; do
    [ -d "$dir" ] || continue
    for entry in "${PATTERNS[@]}"; do
        pattern="${entry%%@@*}"
        description="${entry#*@@}"
        while IFS= read -r match; do
            [ -n "$match" ] || continue
            file="${match%%:*}"
            rest="${match#*:}"
            lineno="${rest%%:*}"
            content="${rest#*:}"

            skip=0
            for whitelisted in $FILE_WHITELIST; do
                [ "$file" = "$whitelisted" ] && skip=1
            done
            if printf '%s' "$content" | grep -qiE 'must not be|test|запр'; then
                skip=1
            fi
            trimmed="${content#"${content%%[![:space:]]*}"}"
            if [ "${trimmed:0:2}" = "//" ] || [ "${trimmed:0:2}" = "--" ]; then
                skip=1
            fi
            case "${trimmed:0:1}" in
                '#'|'*'|'|') skip=1 ;;
            esac

            if [ "$skip" -eq 0 ]; then
                printf 'FAIL  %s:%s: %s [%s]\n' "$file" "$lineno" "$trimmed" "$description" >> "$offenders"
            fi
        done < <(grep -rnE --binary-files=without-match "$pattern" "$dir" 2>/dev/null)
    done
done

if [ -s "$offenders" ]; then
    sort -u "$offenders" >&2
    echo "secrets gate: FAIL — placeholder/weak secret used as a value (see lines above)" >&2
    exit 1
fi

echo "secrets gate: PASS — no placeholder or weak default secrets in: $SCAN_DIRS"
exit 0
