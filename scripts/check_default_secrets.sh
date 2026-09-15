#!/usr/bin/env bash
#
# check_default_secrets.sh — reject the placeholder secret "changeme"
# committed as a real value in code, deploy configs, or docs.
#
# Intentional occurrences are whitelisted in two layers:
#   1. File level — the validation code itself:
#        src/bin/rampart-manager.rs  (startup guard rejecting the default)
#        src/manager/api/auth.rs     (test constant)
#   2. Line level — only lines that *use* "changeme" as a value are reported.
#      A matching line is skipped when it contains "must not be" or "test"
#      (case-insensitive), states the prohibition ("запр" root: запрет /
#      запрещено / запрещён — the project docs are partly Russian), or is a
#      comment / markdown table row (starts with '#', '//', '*', '|', '--').
#
# Any remaining occurrence is an offender -> exit 1, offending lines listed.

set -u

PATTERN="changeme"
SCAN_DIRS="src deploy docs"
FILE_WHITELIST="src/bin/rampart-manager.rs src/manager/api/auth.rs"

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 1

found=0
for dir in $SCAN_DIRS; do
    [ -d "$dir" ] || continue
    while IFS= read -r match; do
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
            found=1
            printf 'FAIL  %s:%s: %s\n' "$file" "$lineno" "$trimmed" >&2
        fi
    done < <(grep -rn --binary-files=without-match "$PATTERN" "$dir" 2>/dev/null)
done

if [ "$found" -ne 0 ]; then
    echo "secrets gate: FAIL — 'changeme' used as a value (see lines above)" >&2
    exit 1
fi

echo "secrets gate: PASS — no unexpected '$PATTERN' occurrences in: $SCAN_DIRS"
exit 0
