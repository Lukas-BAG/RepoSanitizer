#!/usr/bin/env python3
"""Force-apply .rej hunks that only fail because their context/removed lines
contain a REDACTED_<LABEL>_<ID> placeholder instead of the real repo's actual
secret value at that spot.

Called from replay_patch.sh's `git apply --reject` fallback branch (see
tickets/024-force-apply-placeholder-mismatch-rejects.md). For every *.rej file
under the given repo dir, each hunk's context/removed lines are matched
against the real file's current content with REDACTION_ID_RE spans treated as
wildcards. A hunk that matches this way gets force-applied (its '+' lines
written verbatim, its '-' lines removed) -- an intentional overwrite of a real
secret value with literal placeholder text, meant to be restored by hand
afterward. A hunk that doesn't match this way is left in the .rej untouched,
same as today's manual-resolution path.

Exits 0 if every .rej under repo dir was fully resolved (deleted), 1 if any
hunk anywhere is still unresolved (a real conflict remains).
"""
import os
import re
import sys

import redact_lib as rl

REJ_HEADER_RE = re.compile(r"^diff a/(.+) b/(.+)$")
HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def build_line_regex(text):
    """Turn one patch line's text into a regex that matches it exactly, except
    any REDACTED_<LABEL>_<ID> span (rl.REDACTION_ID_RE) is a wildcard -- since
    that's exactly the text a sanitized-repo patch has in place of whatever
    real secret value lives at that spot in the real repo."""
    parts = []
    last = 0
    for m in rl.REDACTION_ID_RE.finditer(text):
        parts.append(re.escape(text[last:m.start()]))
        parts.append(".*")
        last = m.end()
    parts.append(re.escape(text[last:]))
    return re.compile("^" + "".join(parts) + "$")


def parse_rej(text):
    """Returns (target_rel_path, header_line, hunks) or (None, None, []) if the
    file doesn't look like a .rej. Each hunk is {'old_start', 'body', 'raw'}:
    'body' is [(marker, text), ...] for ' '/'-'/'+' lines (used for matching
    and force-apply), 'raw' is the hunk's original lines verbatim (used to
    re-emit it untouched if it stays unresolved)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None, None, []

    header_line = lines[0]
    m = REJ_HEADER_RE.match(header_line.split("\t")[0])
    if not m:
        return None, None, []
    target_rel = m.group(2)

    hunks = []
    current = None
    for line in lines[1:]:
        if line.startswith("@@ "):
            if current is not None:
                hunks.append(current)
            hm = HUNK_HEADER_RE.match(line)
            old_start = int(hm.group(1)) if hm else 1
            current = {"old_start": old_start, "body": [], "raw": [line]}
        else:
            if current is None:
                continue
            current["raw"].append(line)
            if line[:1] in (" ", "-", "+"):
                current["body"].append((line[0], line[1:]))
    if current is not None:
        hunks.append(current)
    return target_rel, header_line, hunks


def find_match_start(file_lines, regexes, hint_old_start):
    """Find where a contiguous run of file_lines matches every regex in order.
    Returns the 0-based start index, or None if no run matches. If more than
    one run matches, picks the one closest to hint_old_start (the hunk's
    original 1-based line number in the patch) -- a best-effort tiebreak, not
    a correctness requirement, since an exact multi-line block match is
    already unlikely to occur more than once by chance."""
    n = len(regexes)
    if n == 0 or n > len(file_lines):
        return None
    candidates = []
    for i in range(len(file_lines) - n + 1):
        if all(regexes[j].match(file_lines[i + j]) for j in range(n)):
            candidates.append(i)
    if not candidates:
        return None
    hint_idx = max(hint_old_start - 1, 0)
    candidates.sort(key=lambda c: abs(c - hint_idx))
    return candidates[0]


def process_rej_file(rej_path, repo_dir, sha, subject, warnings):
    """Returns True if the .rej was fully resolved and deleted, False if it
    still has (or ended up with) unresolved hunks left in it."""
    with open(rej_path, "r", encoding="utf-8", errors="surrogateescape") as f:
        text = f.read()
    target_rel, header_line, hunks = parse_rej(text)
    if target_rel is None or not hunks:
        return False

    target_path = os.path.join(repo_dir, target_rel)
    if not os.path.isfile(target_path):
        return False

    with open(target_path, "r", encoding="utf-8", errors="surrogateescape") as f:
        content = f.read()
    ends_with_newline = content.endswith("\n")
    file_lines = content.split("\n")
    if ends_with_newline:
        file_lines.pop()

    changed = False
    remaining_hunks = []
    for hunk in hunks:
        old_entries = [(mk, tx) for mk, tx in hunk["body"] if mk in (" ", "-")]
        if not old_entries:
            remaining_hunks.append(hunk)
            continue

        regexes = [build_line_regex(tx) for _, tx in old_entries]
        start = find_match_start(file_lines, regexes, hunk["old_start"])
        if start is None:
            remaining_hunks.append(hunk)
            continue

        new_block = []
        idx = start
        for marker, tx in hunk["body"]:
            if marker == " ":
                new_block.append(file_lines[idx])
                idx += 1
            elif marker == "-":
                idx += 1
            elif marker == "+":
                new_block.append(tx)
        end = start + len(old_entries)
        file_lines = file_lines[:start] + new_block + file_lines[end:]
        changed = True

        old_end = hunk["old_start"] + len(old_entries) - 1
        warnings.append(
            f'WARNING: force-applied hunk in {target_rel} (patch lines '
            f'{hunk["old_start"]}-{old_end}) for commit {sha} ("{subject}") -- '
            f"placeholder text was written over what was very likely a real "
            f"secret value there. Review this commit before trusting it."
        )

    if changed:
        new_content = "\n".join(file_lines)
        if ends_with_newline:
            new_content += "\n"
        with open(target_path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(new_content)

    if remaining_hunks:
        out_lines = [header_line]
        for h in remaining_hunks:
            out_lines.extend(h["raw"])
        with open(rej_path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write("\n".join(out_lines) + "\n")
        return False

    os.remove(rej_path)
    return True


def find_rej_files(repo_dir):
    rej_files = []
    for root, dirs, files in os.walk(repo_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        for name in files:
            if name.endswith(".rej"):
                rej_files.append(os.path.join(root, name))
    return sorted(rej_files)


def main():
    if len(sys.argv) != 4:
        sys.exit(f"Usage: {sys.argv[0]} <repo-dir> <sha> <subject>")
    repo_dir, sha, subject = sys.argv[1], sys.argv[2], sys.argv[3]

    warnings = []
    all_resolved = True
    for rej_path in find_rej_files(repo_dir):
        resolved = process_rej_file(rej_path, repo_dir, sha, subject, warnings)
        all_resolved = all_resolved and resolved

    for w in warnings:
        print(w)

    sys.exit(0 if all_resolved else 1)


if __name__ == "__main__":
    main()
