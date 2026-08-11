#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"

SINCE_LAST_PATCH=0
for arg in "$@"; do
  case "$arg" in
    --since-last-patch) SINCE_LAST_PATCH=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [ ! -d "$DEST_DIR/.git" ]; then
  echo "No git repo at $DEST_DIR -- run sanitize.py first." >&2
  exit 1
fi

OUT="$HERE/fix.patch"

if [ "$SINCE_LAST_PATCH" -eq 1 ]; then
  if ! git -C "$DEST_DIR" rev-parse -q --verify "last-applied" >/dev/null; then
    echo "No 'last-applied' tag in $DEST_DIR -- this sanitized repo predates --since-last-patch support (re-run sanitize.py, or tag last-applied manually)." >&2
    exit 1
  fi
  FROM_REF="last-applied"
else
  FROM_REF="$BASELINE_TAG"
fi

DIFF="$(git -C "$DEST_DIR" diff "$FROM_REF" HEAD)"

if [ -z "$DIFF" ]; then
  echo "No changes between $FROM_REF and HEAD -- nothing to patch."
  exit 0
fi

# Embed the source-commit hash recorded in the baseline commit message (see
# sanitize.py) as a comment header, so apply_patch.sh can later verify the
# real repo's HEAD has actually moved past that commit.
BASELINE_COMMIT="$(git -C "$DEST_DIR" rev-parse "$BASELINE_TAG")"
SOURCE_COMMIT="$(git -C "$DEST_DIR" log -1 --format=%B "$BASELINE_COMMIT" | sed -n 's/^source-commit: //p')"

# Embed the sanitized-repo commit this patch was diffed *to*, so
# apply_patch.sh --since-last-patch / --mark-resolved can advance the
# 'last-applied' tag to exactly this point once the patch is (or has been)
# successfully applied.
PATCH_HEAD="$(git -C "$DEST_DIR" rev-parse HEAD)"

{
  if [ -n "$SOURCE_COMMIT" ]; then
    echo "# source-commit: $SOURCE_COMMIT"
  fi
  echo "# patch-head: $PATCH_HEAD"
  printf '%s\n' "$DIFF"
} > "$OUT"

echo "Wrote $OUT"
echo
echo "--- sanity check: known placeholder tokens present in patch ---"
grep -n -E "REDACTED_[A-Z_]+" "$OUT" || echo "(none found)"
echo
echo "--- sanity check: anything that still looks like a live secret (full pattern list) ---"
python3 "$HERE/check_patch_secrets.py" "$OUT"
echo
echo "Review the above, then apply with: ./apply_patch.sh <real-repo-path> $OUT"
if [ "$SINCE_LAST_PATCH" -eq 1 ]; then
  echo "(diffed from 'last-applied' -- pass --since-last-patch to apply_patch.sh too)"
fi
