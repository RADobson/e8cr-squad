#!/usr/bin/env bash
set -euo pipefail

# Recover deleted e8cr-edr folder from a historical commit into soc-migration/legacy-edr
# Usage: scripts/recover_edr_from_history.sh [commit]

COMMIT="${1:-c9015a7}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT_DIR/soc-migration/legacy-edr"

mkdir -p "$OUT"

while IFS= read -r path; do
  mkdir -p "$OUT/$(dirname "$path")"
  git -C "$ROOT_DIR" show "$COMMIT:$path" > "$OUT/$path"
done < <(git -C "$ROOT_DIR" ls-tree -r --name-only "$COMMIT" e8cr-edr)

echo "Recovered e8cr-edr from $COMMIT into $OUT/e8cr-edr"
