# Sanitized AI workspace — usage

Tooling to work on a bug fix with AI, without ever exposing the real repo
(or its secrets) to the AI. Flow: snapshot → redact → AI works in a throwaway
git repo → extract a patch → apply the patch back to the real repo.

## 0. One-time setup

Edit `config.sh`:

```sh
SOURCE_DIR="/path/to/real/project"   # <-- the real project's path
DEST_DIR="/mnt/c/Main/Everything/260070/sanitized"
BASELINE_TAG="baseline"   # internal git tag inside the sanitized repo only,
                          # unrelated to any branch name in the real repo
BRANCH="master"           # which branch of SOURCE_DIR to snapshot
EXCLUDE_DIRS=""           # comma-separated dir names/globs to skip when
                          # scanning for secrets, e.g. "vendor,third_party_libs"
```

Nothing else to set up — there's no `secrets_map.json` anymore; known secret
values are entered interactively when you run `sanitize.py` (see below), so
they never touch disk.

`sanitize.py` refuses to run if `DEST_DIR` already exists and has content in
it — it never silently wipes a directory that might hold AI work you care
about. Remove it yourself first if you really want to start over.

`EXCLUDE_DIRS` skips directories from the *secret search* only (files inside
still get copied/exported normally) — use it for vendored libraries or test
fixtures that legitimately contain words like "password" a lot but hold no
real secrets, so they don't clutter `verify.sh`'s output or `rescan.py`.

## 1. Create the sanitized snapshot

```sh
python3 sanitize.py
```

This:
- runs `git archive BRANCH` against `SOURCE_DIR` and extracts it into
  `DEST_DIR` — i.e. exactly what's committed on that branch, regardless of
  what's currently checked out or any uncommitted changes in the working
  tree. No `.git`, no history, carried over.
- prompts you interactively (input hidden via `getpass`, nothing written to
  disk or shell history) for any exact secret values you want redacted,
  one at a time, blank line to stop. After each value you can optionally
  give it a name (letters/digits/underscore) so it redacts to
  `REDACTED_<NAME>_<ID>` instead of the generic `REDACTED_MANUAL_<ID>` —
  handy for telling e.g. "the DB password" apart from "the API key" in the
  sanitized tree. Re-entering the same name on a later run reuses that
  name's existing ID instead of allocating a new one.
- redacts common secret patterns too (AWS keys, private key blocks,
  connection strings, bearer tokens, Slack/Stripe tokens, generic
  password/API-key assignments, JWTs) — value-in-place, so line numbers stay
  aligned with the real files wherever possible. By default it asks you to
  confirm each unique matched value before redacting it (a regex can mistake
  ordinary prose for a credential). Pass `--no-prompt` to redact every match
  automatically without asking, or `--manual-only` to skip the pattern scan
  entirely and redact only the exact values you typed into the known-secret
  prompt above (the two flags are mutually exclusive)
- writes `redaction_log.txt` (file + line + pattern type only, never the
  actual secret) next to `DEST_DIR`, for your own audit — this file is *not*
  committed into the sanitized repo and the AI never sees it
- `git init`s `DEST_DIR` and makes one baseline commit tagged `BASELINE_TAG`,
  recording the source branch name and its commit hash in the commit message

Pass `--show-diff` to also print each redaction's *original* value straight
to your terminal as it's found (e.g. `[diff] config.py:3: 'sk_live_...' ->
'REDACTED_STRIPE_LIVE_KEY_01'`). This is for your own review only — it's
never written to `redaction_log.txt` or any other file, only stdout.

Every placeholder gets a per-label sequential ID (`_01`, `_02`, ...) instead
of a bare `REDACTED_<LABEL>`, so two different secrets of the same type are
distinguishable and you can tell at a glance whether two occurrences were
originally the same value. IDs are computed by scanning `DEST_DIR` for the
highest ID already used per label, so they keep incrementing across
`rescan.py` runs without any separate counter file — no state to lose or
get out of sync.

## 2. Check whether anything was missed

```sh
./verify.sh
```

Runs four checks against `DEST_DIR`:
1. A plain content `diff` against a fresh export of `SOURCE_DIR@BRANCH`.
   Every changed line should be an intentional `REDACTED_*` swap — anything
   else that changed, or a secret-looking value that *didn't* change, is
   worth a look.
2. Our own pattern scan in check-only mode (no changes made) — catches
   anything the tool's regex list would flag.
3. `gitleaks` (if installed) — broader, entropy-aware detection than our
   regex list. `EXCLUDE_DIRS` doesn't apply to it; consult its own docs
   (`.gitleaksignore` / allowlist config) if vendored code makes it noisy.
4. `trufflehog` (if installed) — same idea, different engine. Run with
   `--no-verification` so it only reports pattern/entropy matches and never
   makes a live network call to confirm a found credential is still active.

Our regex list is intentionally narrow (a handful of known secret shapes)
and both the diff-check and rescan below only catch what SOURCE_DIR and
DEST_DIR actually differ on or match a pattern — they can't prove a negative.
Installing `gitleaks` and/or `trufflehog` is the closest to "actually
checked" and only takes a minute; the built-in checks are a decent first
pass but treat a clean run from those alone as inconclusive, not confirmed.

This isn't hypothetical: in testing, a plain opaque token assigned to a
name like `INTERNAL_SVC_TOKEN` (no recognizable prefix, no connection-string
or JWT shape) passed the diff-check, the regex scan, gitleaks, *and*
trufflehog without being flagged by any of them — it was only caught by a
human reading the file. Any custom internal token/API key your project uses
that doesn't match a well-known vendor format is exactly this case. If you
know your codebase has secrets shaped like that, don't rely on any
automated check here — grep for the specific names/prefixes you use (env
var names, internal token prefixes, etc.) and/or enter their exact values
into the known-secret prompt yourself.

## 3. Redact anything `verify.sh` turns up

```sh
python3 rescan.py
```

Unlike `sanitize.py`, this never re-exports from `SOURCE_DIR` and never wipes
`DEST_DIR` — it redacts additional secrets **in place**, so you don't need to
re-enter values you already handled on a previous pass (they're already gone
from the files, there's nothing left there to match). It reuses the same
known-value prompt, pattern list, `EXCLUDE_DIRS`, and `--show-diff` as
`sanitize.py`. Add `--check-only` to just report matches without touching
anything (that's what `verify.sh` uses it for).

What happens to the `baseline` tag after a redaction depends on whether AI
has committed anything yet:
- **No commits on top of baseline yet** (the common case — you're doing this
  before turning AI loose): the baseline commit is amended in place. Simple,
  no history rewriting concerns.
- **AI already committed on top of baseline**: redacting a value that was
  already present *in the baseline snapshot* and committing it normally would
  add a commit whose diff has the real secret as the "before" line — if that
  ends up in `fix.patch` later, `git apply` would find and overwrite that
  same real secret in your REAL repo with the placeholder. `rescan.py` detects
  this, leaves the fix staged but **uncommitted**, and warns instead of
  committing it. Re-run with `--fixup-into-baseline` to fold it into the
  baseline commit itself via an autosquash rebase (rewrites history in the
  sanitized repo only; AI's later commits are replayed on top unchanged). If
  that hits a conflict, it aborts cleanly and tells you to resolve by hand.

Either path rewrites a commit rather than editing it — the old commit, tree,
and blob (with the real secret) are still sitting in `DEST_DIR/.git/objects`
afterwards, just unreferenced by the current branch/tag. `git`'s reflog would
also keep them reachable by SHA for its default 90-day expiry. Both paths
immediately run `git reflog expire --expire=now --all` and `git gc
--prune=now` in `DEST_DIR` right after the rewrite, so the pre-redaction
object is actually gone from disk, not just unreferenced. This only covers
`DEST_DIR`; handing someone the raw `.git` directory (instead of a fresh
export or checkout) reopens the same window after any later rescan cycle.

## 4. Extract the fix as a patch

```sh
./make_patch.sh
```

Produces `fix.patch` (diff from `baseline` to `HEAD` in the sanitized repo).
The script also greps the patch for your placeholder tokens and known secret
patterns as a last sanity check before you hand it to the real repo — review
that output.

## 5. Apply the patch to the real repo

```sh
./apply_patch.sh
```

With `config.sh` set up, both arguments are optional: the patch file defaults
to `fix.patch` next to the scripts, and the target repo defaults to
`SOURCE_DIR`. Override either explicitly if needed:

```sh
./apply_patch.sh --repo /path/to/somewhere/else other.patch
```

The old two-argument form (`./apply_patch.sh /path/to/real/project fix.patch`)
still works too.

Before applying, `apply_patch.sh` compares the patch's `# patch-head` header
(the sanitized-repo commit it was diffed to) against `DEST_DIR`'s current
`HEAD`. If they don't match — because more commits or a `rescan.py` landed in
the sanitized repo after this patch was generated — it refuses to apply and
tells you to re-run `make_patch.sh` instead of silently applying a stale diff.

Applying itself tries a clean `git apply`. If some hunks don't match (this can
happen if the fix touches a line adjacent to a redacted secret, since the
context differs), it falls back to `git apply --reject`, applying everything
that matches and leaving `.rej` files for the rest — fix only those hunks by
hand, then `git add` + `git commit` in the real repo.

## 6. Incremental patches across multiple make/apply cycles (optional)

If AI keeps working in the sanitized repo after you've already applied a
patch once, re-running the plain flow above re-diffs from the *original*
`BASELINE_TAG`, which re-includes changes you already handed off — against a
real repo that's since moved on, that's a recipe for spurious conflicts.

`sanitize.py` also creates a `last-applied` tag (starting at the same commit
as `BASELINE_TAG`) for this case:

```sh
./make_patch.sh --since-last-patch
./apply_patch.sh /path/to/real/project fix.patch --since-last-patch
```

- `make_patch.sh --since-last-patch` diffs `last-applied..HEAD` instead of
  `BASELINE_TAG..HEAD`, and embeds a `# patch-head: <hash>` header (the
  sanitized-repo commit the diff was taken *to*) in `fix.patch`.
- `apply_patch.sh --since-last-patch` applies with `git apply -3` (a 3-way
  merge using the blob IDs recorded in the patch) instead of the
  clean-apply-then-`--reject` fallback:
  - **Clean 3-way apply** → success. `last-applied` in the sanitized repo is
    automatically moved to the `patch-head` recorded in the patch.
  - **Conflict** → real `<<<<<<<` conflict markers are left in the affected
    files (nothing is committed, nothing is auto-resolved). `last-applied`
    is **not** advanced, so a future `--since-last-patch` run would
    regenerate the same diff rather than silently skip it.
- After resolving a conflicted apply by hand and committing in the real
  repo, tell the tooling it's done:
  ```sh
  ./apply_patch.sh --mark-resolved fix.patch
  ```
  This just moves `last-applied` in the sanitized repo to that patch's
  `patch-head` — it doesn't re-attempt the apply. There's no automatic
  detection of "did you actually resolve this"; it's on you to only run it
  once the real repo reflects the resolved patch.

Default (no `--since-last-patch`) behavior of both scripts is unchanged.

Note: `git apply -3` needs the patch's blob IDs to resolve against objects
already reachable in the real repo (normal `git diff` output includes
these) — since the sanitized and real repos are different histories, this
only works because the surrounding context of the relevant hunks still
matches closely enough for the 3-way merge to find a base.

## 7. Interactive alternative: replay commits one at a time

Steps 4-6 above always work with one flat diff, applied (and committed)
as a single unit. `replay_patch.sh` is a different, opt-in tool that does
steps 4 and 5 together, one sanitized-repo commit at a time, so you can
review and accept (or reject) each one individually instead of the fix
landing as one lump:

```sh
./replay_patch.sh
```

For each commit between `last-applied` (or `baseline`, if nothing's been
applied yet) and `HEAD` in the sanitized repo, oldest first, it:

1. Generates a patch for just that commit and runs the same redaction/secret
   sanity checks `make_patch.sh` does, scoped to that one commit.
2. Tries to apply it to the real repo's working tree (uncommitted).
3. **Clean apply:** shows the resulting diff and asks
   `Commit this as "<original commit message>"? [y/N]`.
   - **y:** commits with the sanitized commit's original message, author,
     and date, advances `last-applied` to it, and moves on to the next
     commit.
   - **anything else:** discards the uncommitted attempt and stops the
     whole run. `last-applied` stays at the last commit you confirmed, so
     re-running `replay_patch.sh` later picks back up at the commit you
     just declined.
4. **Conflict:** pauses with nothing committed, leaving either real
   `<<<<<<<` conflict markers (if `git apply -3` found a base to merge
   against) or `.rej` files (if it didn't) in the real repo for you to
   resolve by hand — this is also the place to fix up a hunk a redaction
   placeholder mangled. Then either:
   - `./replay_patch.sh --continue` — commits your manually-resolved working
     tree with the paused commit's original message, advances
     `last-applied`, and resumes the loop; or
   - `./replay_patch.sh --abort` — discards the conflicted attempt entirely
     and stops, leaving `last-applied` untouched.

Like `apply_patch.sh`, the target repo defaults to `config.sh`'s
`SOURCE_DIR` and can be overridden with `--repo <path>`. Requires a clean
working tree in the real repo before starting a fresh commit's attempt
(not required for `--continue`/`--abort`, which operate on the paused
state). A rejected or aborted commit blocks the run from proceeding past
it even if later commits would apply cleanly — there's no "skip this one,
come back later." If the AI's sanitized-repo history has noisy WIP/fixup
commits you don't want replayed verbatim, clean it up (rebase/squash) in
`DEST_DIR` before running `replay_patch.sh`.

## Notes / limits

- Redaction is regex + known-value based, not a guarantee of completeness —
  see step 2. Spot-check `DEST_DIR` yourself, don't rely on any one check alone.
- If the fix needs to touch a line that also holds a secret, that hunk won't
  auto-apply in step 5 — that's expected, not a bug in the tooling.
- `sanitize.py` will not overwrite an existing non-empty `DEST_DIR` (see step
  0). To start completely over, remove `DEST_DIR` yourself first. To add
  redactions to an existing sanitized copy without starting over, use
  `rescan.py` (step 3) instead.
