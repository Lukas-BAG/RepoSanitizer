#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"

echo "=== 1) content diff: SOURCE_DIR@$BRANCH vs DEST_DIR ==="
echo "Every changed line below should be an intentional REDACTED_* substitution."
echo "Anything else changed, or a secret-looking value NOT flagged as changed, needs a look."
TMP_SRC="$(mktemp -d)"
trap 'rm -rf "$TMP_SRC"' EXIT
git -C "$SOURCE_DIR" archive "$BRANCH" | tar -x -C "$TMP_SRC"
diff -ruN "$TMP_SRC" "$DEST_DIR" --exclude=.git || true
echo

echo "=== 2) our own pattern scan over DEST_DIR (check-only, no changes made) ==="
python3 "$HERE/rescan.py" "$DEST_DIR" --check-only
echo

echo "=== 3) gitleaks (if installed) ==="
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source "$DEST_DIR" --no-git -v || true
  echo "(If vendored libs make this noisy, gitleaks supports its own path-exclude config --"
  echo " see 'gitleaks detect --help' / .gitleaksignore. EXCLUDE_DIRS in config.sh only"
  echo " affects our own scanner above, not gitleaks/trufflehog.)"
else
  echo "gitleaks not installed -- skipping. (optional, catches more than our regex list: https://github.com/gitleaks/gitleaks)"
fi
echo

echo "=== 4) trufflehog (if installed) ==="
if command -v trufflehog >/dev/null 2>&1; then
  trufflehog filesystem --no-verification "$DEST_DIR" || true
else
  echo "trufflehog not installed -- skipping. (optional: https://github.com/trufflesecurity/trufflehog)"
fi
