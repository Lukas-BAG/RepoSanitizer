#!/usr/bin/env python3
"""Scan a patch file against the full secret-pattern list in redact_lib.PATTERNS.

Used by make_patch.sh as the last sanity check before fix.patch is handed to
the real repo, so there's exactly one place (redact_lib.PATTERNS) that defines
what counts as a secret -- instead of a hand-copied, easily stale subset.
"""
import sys

import redact_lib as rl

if len(sys.argv) != 2:
    sys.exit(f"Usage: {sys.argv[0]} <patch-file>")

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()

matches = rl.scan_patterns(text)
if not matches:
    print("(none found)")
else:
    for label, line_no in matches:
        print(f"{path}:{line_no}: pattern '{label}' matched")
