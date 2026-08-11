#!/usr/bin/env python3
"""Re-scan an already-sanitized directory in place for missed secrets.

Unlike sanitize.py, this never re-exports from SOURCE_DIR and never wipes
anything -- it only touches files that still contain a match, so anything
already redacted on a prior run is left alone (there's nothing left to find).
"""
import argparse
import os
import subprocess
import sys

import redact_lib as rl

HERE = os.path.dirname(os.path.abspath(__file__))


def git(dest_dir, *args, check=True, capture=False):
    cmd = ["git", "-C", dest_dir, *args]
    if capture:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    return subprocess.run(cmd, check=check)


def refs_holding(dest_dir, commit):
    """Which refs (tags, branches, anything under refs/) still keep `commit`
    reachable. Used right before pruning to verify -- not assume -- that an
    abandoned commit is actually unreachable, since `git gc --prune=now`
    silently no-ops on any object still reachable from some ref we forgot
    about, rather than erroring."""
    refs = git(dest_dir, "for-each-ref", "--format=%(refname)", capture=True).stdout.split()
    return [ref for ref in refs
            if git(dest_dir, "merge-base", "--is-ancestor", commit, ref,
                   check=False, capture=True).returncode == 0]


def purge_rewritten_objects(dest_dir, abandoned_commit=None):
    """Drop any objects made unreachable by an amend/rebase, and stop the reflog
    from keeping them reachable anyway. Without this, the pre-redaction blob
    (with the real secret) just sits in .git/objects until some future `git gc`
    happens to run -- which nothing in this tool's flow ever triggers.

    If `abandoned_commit` is given, first verify no ref still keeps it
    reachable -- otherwise the gc below would silently no-op on it and we'd
    report success while the real secret is still sitting on disk."""
    if abandoned_commit is not None:
        holding = refs_holding(dest_dir, abandoned_commit)
        if holding:
            sys.exit(
                f"Refusing to prune: commit {abandoned_commit[:12]} (the pre-redaction "
                f"commit we just abandoned) is still reachable via: {', '.join(holding)}.\n"
                "Pruning now would silently no-op and leave the real secret on disk while "
                "reporting success. Move or delete the ref(s) above, then re-run to redact "
                "and prune, or run manually:\n"
                f"  git -C {dest_dir} reflog expire --expire=now --all\n"
                f"  git -C {dest_dir} gc --prune=now"
            )
    git(dest_dir, "reflog", "expire", "--expire=now", "--all")
    git(dest_dir, "gc", "--prune=now", "-q")


def last_applied_offset(dest_dir, old_baseline_commit):
    """How many commits 'last-applied' currently sits ahead of the (pre-rewrite)
    baseline commit, so it can be remapped onto the rewritten history afterwards.
    Returns None if there's nothing to remap (no tag) or it's in an unexpected
    spot (not a descendant of baseline) -- callers must leave the tag alone then."""
    la = git(dest_dir, "rev-parse", "--verify", "last-applied", check=False, capture=True)
    if la.returncode != 0:
        return None
    old_la = la.stdout.strip()
    if old_la == old_baseline_commit:
        return 0
    is_ancestor = git(dest_dir, "merge-base", "--is-ancestor", old_baseline_commit, old_la,
                       check=False, capture=True)
    if is_ancestor.returncode != 0:
        return None
    count = git(dest_dir, "rev-list", "--count", f"{old_baseline_commit}..{old_la}", capture=True)
    return int(count.stdout.strip())


def remap_last_applied(dest_dir, new_baseline_commit, offset):
    """Move 'last-applied' the same number of commits past the *new* baseline
    that it used to be past the old one, so a rewrite (amend/rebase) doesn't
    strand it on the pre-redaction commit -- which would keep that commit (and
    the real secret in its tree) permanently reachable and un-prunable."""
    if offset is None:
        print("WARNING: could not remap the 'last-applied' tag onto the rewritten history -- "
              "leaving it where it was. Check it by hand (`git log --all`) before trusting "
              "--since-last-patch output, and see if it still points at a pre-redaction commit.",
              file=sys.stderr)
        return
    if offset == 0:
        new_la = new_baseline_commit
    else:
        commits = git(dest_dir, "rev-list", "--reverse", f"{new_baseline_commit}..HEAD",
                       capture=True).stdout.strip().splitlines()
        if offset > len(commits):
            print("WARNING: could not remap the 'last-applied' tag onto the rewritten history "
                  "(fewer commits after the rewrite than before) -- leaving it where it was. "
                  "Check it by hand before trusting --since-last-patch output.", file=sys.stderr)
            return
        new_la = commits[offset - 1]
    git(dest_dir, "tag", "-f", "last-applied", new_la)


def fixup_into_baseline(dest_dir, baseline_tag):
    baseline_commit = git(dest_dir, "rev-parse", baseline_tag, capture=True).stdout.strip()
    la_offset = last_applied_offset(dest_dir, baseline_commit)

    git(dest_dir, "add", "-A")
    git(dest_dir, "commit", f"--fixup={baseline_commit}")

    has_parent = git(dest_dir, "rev-parse", "--verify", f"{baseline_commit}^",
                      check=False, capture=True).returncode == 0
    rebase_target = [f"{baseline_commit}^"] if has_parent else ["--root"]

    env = dict(os.environ, GIT_SEQUENCE_EDITOR="true")
    result = subprocess.run(
        ["git", "-C", dest_dir, "rebase", "-i", "--autosquash", *rebase_target],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        subprocess.run(["git", "-C", dest_dir, "rebase", "--abort"], check=False)
        sys.exit(
            "Autosquash rebase failed (likely a conflict with the AI's own commits) -- "
            "aborted, nothing changed. Resolve by hand: `git commit --fixup=<baseline-commit>` "
            "then `git rebase -i --autosquash <parent-of-baseline>` yourself and fix conflicts."
        )

    new_baseline = git(dest_dir, "rev-list", "--max-parents=0", "HEAD",
                        capture=True).stdout.strip().splitlines()[0]
    git(dest_dir, "tag", "-f", baseline_tag, new_baseline)
    remap_last_applied(dest_dir, new_baseline, la_offset)
    purge_rewritten_objects(dest_dir, abandoned_commit=baseline_commit)
    print(f"Folded the redaction into the baseline commit ({new_baseline[:12]}) "
          "and replayed later commits on top.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target_dir", nargs="?",
                         help="Directory to rescan. Defaults to DEST_DIR from config.sh.")
    parser.add_argument("--check-only", action="store_true",
                         help="Report matches without modifying any file or git state.")
    parser.add_argument("--show-diff", action="store_true",
                         help="Print each match's original value to stdout. Never written to a file.")
    parser.add_argument("--no-prompt", action="store_true",
                         help="Redact every pattern match automatically without asking. "
                              "Default behavior asks once per unique matched value (same "
                              "value everywhere is redacted-or-not together).")
    parser.add_argument("--manual-only", action="store_true",
                         help="Skip the automatic PATTERNS scan entirely -- redact only the "
                              "exact values entered via the known-secrets prompt. Mutually "
                              "exclusive with --no-prompt.")
    parser.add_argument("--fixup-into-baseline", action="store_true",
                         help="If AI has already committed on top of the baseline snapshot, "
                              "fold this redaction into the baseline commit via an autosquash "
                              "rebase instead of leaving it as a separate commit. Rewrites history "
                              "in the sanitized repo only -- never touches SOURCE_DIR.")
    args = parser.parse_args()

    if args.manual_only and args.no_prompt:
        sys.exit("--manual-only and --no-prompt are mutually exclusive: one says \"never "
                  "touch patterns\", the other says \"touch patterns without asking\".")

    cfg = rl.load_config(os.path.join(HERE, "config.sh"))
    target_dir = args.target_dir or cfg.get("DEST_DIR")
    baseline_tag = cfg.get("BASELINE_TAG", "baseline")
    exclude_patterns = rl.parse_exclude_dirs(cfg)

    if not target_dir or not os.path.isdir(target_dir):
        sys.exit(f"Target directory does not exist: {target_dir}")

    is_git_repo = os.path.isdir(os.path.join(target_dir, ".git"))
    if not is_git_repo and not args.check_only:
        sys.exit(f"{target_dir} is not a git repo -- run sanitize.py first, or pass --check-only.")

    allocator = rl.RedactionIdAllocator(target_dir, exclude_patterns)
    known_map = rl.prompt_known_secrets(allocator)
    if not args.manual_only:
        rl.resolve_pattern_redaction(target_dir, exclude_patterns, known_map, args.no_prompt, allocator)

    log_lines, changed_files, skipped_files = rl.redact_tree(
        target_dir, known_map, exclude_patterns,
        check_only=args.check_only, show_diff=args.show_diff,
    )

    if skipped_files:
        print(f"WARNING: skipped {len(skipped_files)} file(s) that could not be decoded as "
              "UTF-8 -- these were NOT scanned for secrets:")
        for rel_path, reason in skipped_files:
            print(f"  {rel_path}: {reason}")
        print()

    if not changed_files:
        print("No matches found. Nothing to do." if not skipped_files else
              "No matches found in the files that could be scanned.")
        return

    verb = "Would redact" if args.check_only else "Redacted"
    print(f"{verb} {len(changed_files)} file(s):")
    for line in log_lines:
        print(f"  {line}")

    if args.check_only:
        return

    baseline_exists = git(target_dir, "rev-parse", "--verify", baseline_tag,
                           check=False, capture=True).returncode == 0
    if not baseline_exists:
        git(target_dir, "add", "-A")
        print(f"No '{baseline_tag}' tag found -- left changes staged/uncommitted for you to review and commit.")
        return

    head = git(target_dir, "rev-parse", "HEAD", capture=True).stdout.strip()
    baseline_commit = git(target_dir, "rev-parse", baseline_tag, capture=True).stdout.strip()

    if head == baseline_commit:
        la_offset = last_applied_offset(target_dir, baseline_commit)
        git(target_dir, "add", "-A")
        git(target_dir, "commit", "--amend", "--no-edit", "-q")
        git(target_dir, "tag", "-f", baseline_tag)
        new_baseline = git(target_dir, "rev-parse", baseline_tag, capture=True).stdout.strip()
        remap_last_applied(target_dir, new_baseline, la_offset)
        purge_rewritten_objects(target_dir, abandoned_commit=baseline_commit)
        print(f"Amended the baseline commit in place (no commits existed on top of it yet).")
        return

    if args.fixup_into_baseline:
        fixup_into_baseline(target_dir, baseline_tag)
        return

    git(target_dir, "add", "-A")
    print(
        "\nWarning: there are already commit(s) on top of the baseline snapshot "
        "(the AI has started working). The redaction above is staged but NOT committed.\n"
        "Committing it as a normal commit would make it show up as its own hunk in the "
        "eventual fix.patch (baseline..HEAD) -- and that hunk's 'before' side is the real "
        "secret value, which git apply would then match against and silently overwrite in "
        "your REAL repo. Do not just commit this and move on.\n\n"
        "Options:\n"
        "  1. Re-run with --fixup-into-baseline to fold this into the baseline commit itself "
        "(rewrites the sanitized repo's history only; later commits are replayed on top).\n"
        "  2. If that hits a conflict, resolve it manually with an interactive autosquash rebase.\n"
    )


if __name__ == "__main__":
    main()
