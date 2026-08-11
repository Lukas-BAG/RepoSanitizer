#!/usr/bin/env python3
"""Snapshot a branch of SOURCE_DIR into DEST_DIR (no git history), redact secrets, init a fresh repo."""
import argparse
import os
import shutil
import subprocess
import sys

import redact_lib as rl

HERE = os.path.dirname(os.path.abspath(__file__))


def export_branch(source_dir, dest_dir, branch):
    """Export exactly what's committed on `branch`, ignoring the working tree
    and any other branch currently checked out in source_dir."""
    verify = subprocess.run(
        ["git", "-C", source_dir, "rev-parse", "--verify", branch],
        capture_output=True, text=True,
    )
    if verify.returncode != 0:
        sys.exit(f"Branch '{branch}' not found in {source_dir}: {verify.stderr.strip()}")

    if os.path.exists(dest_dir) and os.listdir(dest_dir):
        sys.exit(
            f"Refusing to continue: {dest_dir} already exists and is not empty.\n"
            "Running this would permanently wipe it, including any AI work already\n"
            "committed there. If you're sure you want to discard it, remove it yourself\n"
            "first (e.g. `rm -rf` it) and re-run. To keep existing work and only redact\n"
            "additional secrets found later, use rescan.py instead."
        )
    elif os.path.exists(dest_dir):
        os.rmdir(dest_dir)  # exists but empty

    os.makedirs(dest_dir)

    archive = subprocess.Popen(
        ["git", "-C", source_dir, "archive", branch], stdout=subprocess.PIPE,
    )
    subprocess.run(["tar", "-x", "-C", dest_dir], stdin=archive.stdout, check=True)
    archive.stdout.close()
    ret = archive.wait()
    if ret != 0:
        sys.exit(f"git archive failed with exit code {ret}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--show-diff", action="store_true",
                         help="Print each redaction's original value to stdout as it's found. "
                              "Never written to any file.")
    parser.add_argument("--no-prompt", action="store_true",
                         help="Redact every pattern match automatically without asking. "
                              "Default behavior asks once per unique matched value (same "
                              "value everywhere is redacted-or-not together).")
    parser.add_argument("--manual-only", action="store_true",
                         help="Skip the automatic PATTERNS scan entirely -- redact only the "
                              "exact values entered via the known-secrets prompt. Mutually "
                              "exclusive with --no-prompt.")
    args = parser.parse_args()

    if args.manual_only and args.no_prompt:
        sys.exit("--manual-only and --no-prompt are mutually exclusive: one says \"never "
                  "touch patterns\", the other says \"touch patterns without asking\".")

    cfg = rl.load_config(os.path.join(HERE, "config.sh"))
    source_dir = cfg.get("SOURCE_DIR")
    dest_dir = cfg.get("DEST_DIR")
    baseline_tag = cfg.get("BASELINE_TAG", "baseline")
    branch = cfg.get("BRANCH", "master")
    exclude_patterns = rl.parse_exclude_dirs(cfg)

    if not source_dir or source_dir == "/path/to/real/project":
        sys.exit("Edit config.sh: set SOURCE_DIR to the real project path first.")
    if not os.path.isdir(source_dir):
        sys.exit(f"SOURCE_DIR does not exist: {source_dir}")
    if not os.path.isdir(os.path.join(source_dir, ".git")):
        sys.exit(f"SOURCE_DIR is not a git repo: {source_dir}")

    print(f"Exporting branch '{branch}' from {source_dir} -> {dest_dir} ...")
    export_branch(source_dir, dest_dir, branch)

    allocator = rl.RedactionIdAllocator(dest_dir, exclude_patterns)
    known_map = rl.prompt_known_secrets(allocator)
    if not args.manual_only:
        rl.resolve_pattern_redaction(dest_dir, exclude_patterns, known_map, args.no_prompt, allocator)

    log_lines, changed_files, skipped_files = rl.redact_tree(
        dest_dir, known_map, exclude_patterns, show_diff=args.show_diff,
    )

    if skipped_files:
        log_lines.append("")
        log_lines.append(f"Skipped {len(skipped_files)} file(s) that could not be decoded "
                          "as UTF-8 (NOT scanned for secrets):")
        for rel_path, reason in skipped_files:
            log_lines.append(f"  {rel_path}: {reason}")

    log_path = os.path.join(HERE, "redaction_log.txt")
    with open(log_path, "w") as f:
        f.write("\n".join(log_lines) + ("\n" if log_lines else ""))
    print(f"Redaction log written to {log_path} ({len(log_lines)} matches). Not copied into DEST_DIR.")

    if skipped_files:
        print(f"\nWARNING: skipped {len(skipped_files)} file(s) that could not be decoded as "
              "UTF-8 -- these were NOT scanned for secrets:")
        for rel_path, reason in skipped_files:
            print(f"  {rel_path}: {reason}")
        print("Review these manually before pointing AI at the sanitized copy.")

    source_hash = subprocess.check_output(
        ["git", "-C", source_dir, "rev-parse", branch],
        text=True, stderr=subprocess.DEVNULL,
    ).strip()

    subprocess.run(["git", "-C", dest_dir, "init", "-q"], check=True)
    subprocess.run(["git", "-C", dest_dir, "add", "-A"], check=True)
    commit_msg = f"Sanitized baseline snapshot\n\nsource-branch: {branch}\nsource-commit: {source_hash}"
    subprocess.run(["git", "-C", dest_dir, "commit", "-q", "-m", commit_msg], check=True)
    subprocess.run(["git", "-C", dest_dir, "tag", baseline_tag], check=True)
    subprocess.run(["git", "-C", dest_dir, "tag", "last-applied"], check=True)

    print(f"Done. Sanitized repo ready at {dest_dir}.")
    print(f"Tag '{baseline_tag}' marks this snapshot commit inside the sanitized repo -- ")
    print(f"make_patch.sh diffs against it. It has no relation to branches in {source_dir}.")
    print("Tag 'last-applied' starts at the same commit -- it's used by "
          "make_patch.sh/apply_patch.sh --since-last-patch to track incremental patches.")
    print("Spot-check the sanitized copy before pointing AI at it, then work there normally.")


if __name__ == "__main__":
    main()
