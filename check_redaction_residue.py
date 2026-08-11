#!/usr/bin/env python3
"""Scan a repo's current working tree for leftover REDACTED_<LABEL>_<ID>
placeholder text -- which has no legitimate reason to exist outside DEST_DIR,
the sanitized mirror. Any match means some earlier commit written into this
repo is wrong: e.g. an unamended force-applied hunk (ticket 024), or a
hand-resolved conflict that copied placeholder text instead of the real
secret. See tickets/025-warn-stop-on-existing-redaction-residue-in-target.md.

Called from replay_patch.sh before it starts a run and before --continue
finalizes a paused commit. Prints one line per match ("path:line: TOKEN") and
exits 1 if any are found, 0 otherwise.
"""
import sys

import redact_lib as rl


def find_residue(repo_dir, exclude_patterns):
    matches = []
    for path, rel_path in rl.iter_target_files(repo_dir, exclude_patterns):
        if not rl.is_probably_text(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(content.split("\n"), start=1):
            for m in rl.REDACTION_ID_RE.finditer(line):
                matches.append((rel_path, line_no, m.group(0)))
    return matches


def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <repo-dir> <exclude-dirs-csv>")
    repo_dir, exclude_dirs_csv = sys.argv[1], sys.argv[2]
    exclude_patterns = rl.parse_exclude_dirs({"EXCLUDE_DIRS": exclude_dirs_csv})

    matches = find_residue(repo_dir, exclude_patterns)
    for rel_path, line_no, token in matches:
        print(f"{rel_path}:{line_no}: {token}")
    sys.exit(1 if matches else 0)


if __name__ == "__main__":
    main()
