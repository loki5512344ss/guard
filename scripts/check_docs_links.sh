#!/usr/bin/env bash
# Verifies that every relative Markdown link in the tracked documentation points
# at an existing file. External links are not fetched: CI must stay offline and
# deterministic, and a dead third-party URL is not a repo defect.
#
# Usage: bash scripts/check_docs_links.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import pathlib
import re
import sys

ROOTS = ["README.md", "TODO.md", "CHANGELOG.md"]
ROOTS += [str(p) for p in pathlib.Path("docs").rglob("*.md")]
ROOTS += [str(p) for p in pathlib.Path("deploy").rglob("*.md")]

LINK = re.compile(r"\]\(([^)]+)\)")
SKIP_PREFIX = ("http://", "https://", "mailto:", "#")

missing = []
for name in sorted(set(ROOTS)):
    path = pathlib.Path(name)
    if not path.is_file():
        continue
    base = path.parent
    for match in LINK.finditer(path.read_text(encoding="utf-8")):
        target = match.group(1).strip()
        # Drop the anchor and an optional title: ](file.md "title")
        target = target.split("#", 1)[0].split(" ", 1)[0]
        if not target or target.startswith(SKIP_PREFIX):
            continue
        resolved = (base / target).resolve()
        if not resolved.exists():
            missing.append(f"{name}: {match.group(1)}")

if missing:
    print("Broken documentation links:", file=sys.stderr)
    for item in missing:
        print(f"  {item}", file=sys.stderr)
    sys.exit(1)

print(f"Documentation links OK ({len(set(ROOTS))} files)")
PY
