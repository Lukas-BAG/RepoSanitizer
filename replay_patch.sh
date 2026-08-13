#!/usr/bin/env bash
# Replay sanitized-repo commits (last-applied..HEAD) one at a time into a
# real repo: patch one commit, try to apply it, show the resulting diff,
# ask for confirmation, commit with the original message on yes, discard on
# no. A conflict pauses the whole run for manual resolution (--continue) or
# discarding (--abort). See tickets/020-commit-by-commit-patch-replay.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$HERE/config.sh" ]; then
  echo "config.sh not found at $HERE/config.sh -- copy config.sh.example and edit it first." >&2
  exit 1
fi
source "$HERE/config.sh"

PENDING_FILE="$HERE/.replay-pending"

usage() {
  cat >&2 <<EOF
Usage: $0 [--repo <path>] [--no-placeholder-force] [--allow-redaction-residue]
       $0 --continue
       $0 --abort
EOF
  exit 1
}

MODE=start
REPO_OVERRIDE=""
PLACEHOLDER_FORCE=1
ALLOW_REDACTION_RESIDUE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --continue) MODE=continue; shift ;;
    --abort) MODE=abort; shift ;;
    --no-placeholder-force) PLACEHOLDER_FORCE=0; shift ;;
    --allow-redaction-residue) ALLOW_REDACTION_RESIDUE=1; shift ;;
    --repo)
      [ $# -ge 2 ] || usage
      REPO_OVERRIDE="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

if [ -n "$REPO_OVERRIDE" ]; then
  REPO="$REPO_OVERRIDE"
elif [ -n "${SOURCE_DIR:-}" ]; then
  REPO="$SOURCE_DIR"
else
  echo "No repo path given: pass --repo <path>, or set SOURCE_DIR in config.sh." >&2
  exit 1
fi

if [ ! -d "$REPO/.git" ]; then
  echo "Not a git repo: $REPO" >&2
  exit 1
fi
if [ ! -d "$DEST_DIR/.git" ]; then
  echo "Not a git repo: $DEST_DIR (DEST_DIR from config.sh)" >&2
  exit 1
fi
REPO="$(cd "$REPO" && pwd)"

read_pending() {
  PENDING_SHA=""
  PENDING_REPO=""
  if [ -f "$PENDING_FILE" ]; then
    PENDING_SHA="$(sed -n 's/^sha=//p' "$PENDING_FILE")"
    PENDING_REPO="$(sed -n 's/^repo=//p' "$PENDING_FILE")"
  fi
}

commit_meta() {
  # Prints: author name+email, then author date (raw), then a blank line, then
  # the full commit message -- read by callers with a fixed-line-count `read`.
  git -C "$DEST_DIR" log -1 --format='%an <%ae>%n%ad%n%B' --date=raw "$1"
}

discard_working_tree() {
  git -C "$REPO" reset --hard -q HEAD
  git -C "$REPO" clean -fdq
}

check_redaction_residue() {
  # REDACTED_<LABEL>_<ID> text has no legitimate reason to exist in $REPO --
  # a match means an earlier commit into $REPO is wrong (e.g. an unamended
  # force-applied hunk from ticket 024, or a hand-resolved conflict that
  # copied placeholder text instead of the real secret). See
  # tickets/025-warn-stop-on-existing-redaction-residue-in-target.md.
  local output rc=0
  output="$(python3 "$HERE/check_redaction_residue.py" "$REPO" "${EXCLUDE_DIRS:-}")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  echo "$output" >&2
  if [ "$ALLOW_REDACTION_RESIDUE" -eq 1 ]; then
    echo "WARNING: REDACTED_* placeholder text found in $REPO (above) -- proceeding anyway (--allow-redaction-residue)." >&2
    return 0
  fi
  echo >&2
  echo "Stopping: REDACTED_* placeholder text found in $REPO (above). That has no legitimate reason to be in the real repo -- it usually means an earlier commit wrote placeholder text over a real secret instead of the actual value (e.g. an unamended force-applied hunk from ticket 024)." >&2
  echo "Fix it by hand (git commit --amend the real value in, or edit and recommit), then re-run. Or pass --allow-redaction-residue to proceed anyway." >&2
  return 1
}

commit_pending_sha() {
  local sha="$1"
  git -C "$REPO" add -A
  if git -C "$REPO" diff --cached --quiet; then
    git -C "$DEST_DIR" tag -f last-applied "$sha" >/dev/null
    echo "No changes remain after resolving $sha -- treating as already satisfied."
    echo "Advanced 'last-applied' in $DEST_DIR to $sha without creating a commit."
    return 0
  fi
  local author authordate message
  {
    IFS= read -r author
    IFS= read -r authordate
    message="$(cat)"
  } < <(commit_meta "$sha")
  git -C "$REPO" commit -q --author="$author" --date="$authordate" -m "$message"
  git -C "$DEST_DIR" tag -f last-applied "$sha" >/dev/null
  echo "Committed in $REPO and advanced 'last-applied' in $DEST_DIR to $sha."
}

read_pending

if [ "$MODE" = "continue" ] || [ "$MODE" = "abort" ]; then
  if [ -z "$PENDING_SHA" ]; then
    echo "No paused replay found ($PENDING_FILE doesn't exist) -- nothing to $MODE." >&2
    exit 1
  fi
  if [ "$PENDING_REPO" != "$REPO" ]; then
    echo "Paused replay is against $PENDING_REPO, not $REPO -- pass --repo $PENDING_REPO or omit --repo." >&2
    exit 1
  fi
fi

if [ "$MODE" = "abort" ]; then
  discard_working_tree
  find "$REPO" -name "*.rej" -not -path "*/.git/*" -delete
  rm -f "$PENDING_FILE"
  echo "Aborted paused commit $PENDING_SHA. 'last-applied' in $DEST_DIR is unchanged."
  exit 0
fi

if [ "$MODE" = "continue" ]; then
  UNMERGED="$(git -C "$REPO" diff --name-only --diff-filter=U)"
  REJ_FILES="$(find "$REPO" -name "*.rej" -not -path "*/.git/*")"
  if [ -n "$UNMERGED" ] || [ -n "$REJ_FILES" ]; then
    echo "Still unresolved in $REPO:" >&2
    [ -n "$UNMERGED" ] && echo "$UNMERGED" >&2
    [ -n "$REJ_FILES" ] && echo "$REJ_FILES" >&2
    echo "Resolve these (git add the fixed files, delete .rej files once handled), then re-run --continue." >&2
    exit 1
  fi
  check_redaction_residue || exit 1
  commit_pending_sha "$PENDING_SHA"
  rm -f "$PENDING_FILE"
  # Fall through to resume the loop at the next commit after PENDING_SHA.
elif [ -n "$PENDING_SHA" ]; then
  echo "A previous replay is paused on commit $PENDING_SHA (conflict) -- run:" >&2
  echo "  $0 --continue   (after resolving by hand)" >&2
  echo "  $0 --abort      (to discard the attempt and stop)" >&2
  exit 1
fi

if [ "$MODE" = "start" ]; then
  if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
    echo "Working tree at $REPO is not clean. Commit or stash before running replay_patch.sh." >&2
    exit 1
  fi
  check_redaction_residue || exit 1
fi

if git -C "$DEST_DIR" rev-parse -q --verify last-applied >/dev/null; then
  FROM_REF="last-applied"
else
  FROM_REF="$BASELINE_TAG"
fi

COMMITS=$(git -C "$DEST_DIR" rev-list --reverse "$FROM_REF..HEAD")
if [ -z "$COMMITS" ]; then
  echo "Nothing to replay -- $DEST_DIR's HEAD matches $FROM_REF."
  exit 0
fi

for sha in $COMMITS; do
  subject="$(git -C "$DEST_DIR" log -1 --format=%s "$sha")"
  echo
  echo "=== $sha: $subject ==="

  PATCH_FILE="$(mktemp)"
  git -C "$DEST_DIR" format-patch -1 "$sha" --stdout > "$PATCH_FILE"

  echo "--- sanity check: known placeholder tokens present in this commit's patch ---"
  grep -n -E "REDACTED_[A-Z_]+" "$PATCH_FILE" || echo "(none found)"
  echo "--- sanity check: anything that still looks like a live secret ---"
  python3 "$HERE/check_patch_secrets.py" "$PATCH_FILE"

  APPLIED_VIA=""
  if git -C "$REPO" apply --check "$PATCH_FILE" 2>/dev/null; then
    git -C "$REPO" apply "$PATCH_FILE"
    APPLIED_VIA="clean"
  else
    THREEWAY_RC=0
    git -C "$REPO" apply -3 "$PATCH_FILE" 2>/dev/null || THREEWAY_RC=$?
    if [ -n "$(git -C "$REPO" diff --name-only --diff-filter=U)" ]; then
      # -3 left real conflict markers -- do NOT also try --reject on top of
      # that, or it re-attempts the same hunk against now-conflict-marked
      # content and produces a redundant, confusing .rej file.
      APPLIED_VIA="conflict"
    elif [ "$THREEWAY_RC" -eq 0 ]; then
      APPLIED_VIA="3way"
    else
      # -3 didn't even find a base to merge against (blobs unavailable) --
      # nothing was written, so it's safe to try the --reject fallback.
      git -C "$REPO" apply --reject "$PATCH_FILE" 2>/dev/null || true
      if [ "$PLACEHOLDER_FORCE" -eq 1 ]; then
        python3 "$HERE/force_apply_rejects.py" "$REPO" "$sha" "$subject" || true
      fi
      if [ -n "$(find "$REPO" -name "*.rej" -not -path "*/.git/*")" ]; then
        APPLIED_VIA="conflict"
      else
        APPLIED_VIA="forced"
      fi
    fi
  fi
  rm -f "$PATCH_FILE"

  if [ "$APPLIED_VIA" = "conflict" ]; then
    {
      echo "sha=$sha"
      echo "repo=$REPO"
    } > "$PENDING_FILE"
    echo
    echo "Conflict applying $sha -- paused, nothing committed."
    UNMERGED="$(git -C "$REPO" diff --name-only --diff-filter=U)"
    REJ_FILES="$(find "$REPO" -name "*.rej" -not -path "*/.git/*")"
    [ -n "$UNMERGED" ] && { echo "Unmerged (conflict markers) in:"; echo "$UNMERGED"; }
    [ -n "$REJ_FILES" ] && { echo "Unapplied hunks left in:"; echo "$REJ_FILES"; }
    echo
    echo "Resolve by hand (this is also the place to fix up a hunk a redaction placeholder"
    echo "mangled), 'git add' the resolved files, delete any handled .rej files, then run:"
    echo "  $0 --continue"
    echo "Or discard this commit's attempt entirely:"
    echo "  $0 --abort"
    exit 1
  fi

  echo
  case "$APPLIED_VIA" in
    clean) echo "--- applied cleanly -- resulting diff in $REPO ---" ;;
    3way) echo "--- applied via 3-way merge, no conflicts -- resulting diff in $REPO ---" ;;
    forced) echo "--- applied via reject fallback; hunk(s) above were force-applied over a likely-real secret -- review carefully -- resulting diff in $REPO ---" ;;
  esac
  git -C "$REPO" diff
  echo
  CONFIRM=""
  read -r -p "Commit this as \"$subject\"? [y/N] " CONFIRM || true
  if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
    commit_pending_sha "$sha"
  else
    discard_working_tree
    echo "Rejected -- discarded the uncommitted change. 'last-applied' in $DEST_DIR is unchanged at the last confirmed commit."
    exit 1
  fi
done

echo
echo "Replay complete -- $DEST_DIR's HEAD and 'last-applied' now match."
