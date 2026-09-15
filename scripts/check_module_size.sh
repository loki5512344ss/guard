#!/usr/bin/env bash
#
# check_module_size.sh — module size ratchet.
#
# Project standard (TODO.md §4): max 250 lines per .rs file; max 4 .rs files
# per source directory (top level, non-recursive, mod.rs included).
#
# Rationale — ratchet pattern: the gate blocks regressions immediately while
# legacy debt drains away file by file. Paths that currently violate the
# standard are pinned one-per-line in .module_size_baseline and are reported
# as WARN ("legacy, pending refactor"); only NEW violations fail the build.
# Baseline entries that no longer violate are stale and also fail, so the
# baseline never hides a shrink that should be locked in — regenerate it with
# --update-baseline and commit the result.
#
# Scope note: we scan src/ only and deliberately do NOT scan tests/.
# Cargo treats every top-level tests/*.rs as its own integration-test
# binary, so those files must stay "one file per binary" at tests/ root;
# splitting an oversized test into a module directory would break cargo's
# test discovery.

set -u

MAX_LINES=250
MAX_FILES=4
SRC_DIR="src"
BASELINE_FILE=".module_size_baseline"

export LC_ALL=C
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 1

UPDATE_BASELINE=0
for arg in "$@"; do
    case "$arg" in
        --update-baseline) UPDATE_BASELINE=1 ;;
        *) echo "usage: $0 [--update-baseline]" >&2; exit 2 ;;
    esac
done

count_lines() {
    wc -l < "$1" | tr -d '[:space:]'
}

count_dir_rs() {
    find "$1" -maxdepth 1 -type f -name '*.rs' | wc -l | tr -d '[:space:]'
}

# Print current violations, one path per line (dirs carry a trailing /), sorted.
current_violations() {
    {
        find "$SRC_DIR" -type f -name '*.rs' -not -path '*/target/*' 2>/dev/null |
        while IFS= read -r file; do
            [ "$(count_lines "$file")" -gt "$MAX_LINES" ] && printf '%s\n' "$file"
        done

        find "$SRC_DIR" -type d -not -path '*/target/*' 2>/dev/null |
        while IFS= read -r dir; do
            [ "$(count_dir_rs "$dir")" -gt "$MAX_FILES" ] && printf '%s/\n' "$dir"
        done
    } | sort
}

describe_entry() {
    entry="$1"
    case "$entry" in
        */)
            dir="${entry%/}"
            if [ -d "$dir" ]; then
                printf '%s — %d top-level .rs files (max %d)' "$dir" "$(count_dir_rs "$dir")" "$MAX_FILES"
            else
                printf '%s — directory no longer exists' "$dir"
            fi
            ;;
        *)
            if [ -f "$entry" ]; then
                printf '%s — %d lines (max %d)' "$entry" "$(count_lines "$entry")" "$MAX_LINES"
            else
                printf '%s — file no longer exists' "$entry"
            fi
            ;;
    esac
}

list_with_prefix() {
    # $1 = prefix, $2 = file with one path per line
    while IFS= read -r entry; do
        [ -n "$entry" ] && printf '  %s  %s\n' "$1" "$(describe_entry "$entry")"
    done < "$2"
}

current=$(current_violations)

if [ "$UPDATE_BASELINE" -eq 1 ]; then
    {
        echo "# Module size ratchet baseline — read by scripts/check_module_size.sh"
        echo "# Oversized files: plain path. Overcrowded directories: path with trailing /."
        echo "# Regenerate after a refactor: bash scripts/check_module_size.sh --update-baseline"
        printf '%s\n' "$current" | sed '/^$/d'
    } > "$BASELINE_FILE"
    entries=$(printf '%s\n' "$current" | sed '/^$/d' | wc -l | tr -d '[:space:]')
    echo "module-size: baseline regenerated — $entries entries written to $BASELINE_FILE"
    exit 0
fi

cur_f=$(mktemp) base_f=$(mktemp) new_f=$(mktemp) stale_f=$(mktemp) warn_f=$(mktemp)
trap 'rm -f "$cur_f" "$base_f" "$new_f" "$stale_f" "$warn_f"' EXIT

printf '%s\n' "$current" | sed '/^$/d' > "$cur_f"
have_base=0
if [ -f "$BASELINE_FILE" ]; then
    have_base=1
    sed -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*#/d' -e 's/[[:space:]]*$//' "$BASELINE_FILE" | sort > "$base_f"
else
    : > "$base_f"
fi

comm -23 "$cur_f" "$base_f" > "$new_f"     # violations not baselined  -> FAIL
comm -13 "$cur_f" "$base_f" > "$stale_f"   # baselined but compliant   -> FAIL (stale)
comm -12 "$cur_f" "$base_f" > "$warn_f"    # baselined and violating   -> WARN

echo "module-size gate: max $MAX_LINES lines per .rs file, max $MAX_FILES .rs files per directory (scope: $SRC_DIR/)"
echo

if [ "$have_base" -eq 0 ]; then
    echo "note: no $BASELINE_FILE found — all current violations count as new"
    echo
fi

if [ -s "$warn_f" ]; then
    echo "WARN (legacy, pending refactor):"
    list_with_prefix "WARN " "$warn_f"
    echo
fi

fail=0
if [ -s "$stale_f" ]; then
    fail=1
    echo "STALE baseline entries — these no longer violate the limits:"
    list_with_prefix "STALE" "$stale_f"
    echo "  fix: run 'bash scripts/check_module_size.sh --update-baseline' and commit $BASELINE_FILE"
    echo
fi
if [ -s "$new_f" ]; then
    fail=1
    echo "NEW violations:"
    list_with_prefix "FAIL " "$new_f"
    echo
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL — module size gate"
    exit 1
fi

warn_n=$(sed -n '$=' "$warn_f")
if [ "${warn_n:-0}" -gt 0 ]; then
    echo "PASS — module size gate ($warn_n legacy entries baselined as WARN, no new violations)"
else
    echo "PASS — module size gate (no violations)"
fi
exit 0
