"""Shared redaction logic used by sanitize.py and rescan.py."""
import fnmatch
import getpass
import os
import re
import subprocess
import sys

CONFIG_KEYS = ["SOURCE_DIR", "DEST_DIR", "BASELINE_TAG", "BRANCH", "EXCLUDE_DIRS"]

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".exe", ".dll", ".so", ".dylib", ".pyc", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".class", ".jar", ".sqlite",
    ".db",
}

# (label, compiled regex, value_group) -- value_group is None to redact the whole
# match, or a group index to redact only that group (keeping the rest of the
# match, e.g. the key name and operator, intact).
PATTERNS = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), None),
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL), None),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), None),
    ("connection_string", re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+"), None),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.=]{10,}"), None),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), None),
    ("stripe_live_key", re.compile(r"sk_live_[0-9a-zA-Z]{16,}"), None),
    # Negative lookahead on the value excludes our own placeholders (they're
    # 16+ chars and would otherwise re-match on every subsequent scan).
    # Quotes are optional so unquoted .env-style `KEY=value` lines match too.
    # The value must contain a digit and run 8+ chars, so plain English words
    # after "password=" / "secret:" in prose (ticket 007) don't qualify.
    ("generic_password_assignment", re.compile(
        r"(?i)(password|passwd|pwd|secret)(\s*[=:]\s*)(['\"]?)(?!REDACTED_)"
        r"((?=[^\s'\"\n]*[0-9])[^\s'\"\n]{8,})(['\"]?)"), 4),
    ("generic_api_key_assignment", re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?token)(\s*[=:]\s*)(['\"]?)(?!REDACTED_)([A-Za-z0-9_\-]{16,})(['\"]?)"), 4),
]


def load_config(config_path):
    """Get config values by actually sourcing config.sh in bash and echoing them
    back out, so Python sees exactly what the shell scripts (make_patch.sh,
    apply_patch.sh, verify.sh) see -- no second, hand-rolled parser that can
    silently diverge on quoting, inline comments, or shell expansions."""
    echoes = "; ".join(f'echo "{k}=${{{k}}}"' for k in CONFIG_KEYS)
    script = f'set -a; source "{config_path}" >/dev/null 2>&1; {echoes}'
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True,
    )
    cfg = {}
    for line in result.stdout.splitlines():
        key, _, val = line.partition("=")
        cfg[key] = val
    return cfg


def parse_exclude_dirs(cfg):
    raw = cfg.get("EXCLUDE_DIRS", "")
    return [p.strip() for p in raw.split(",") if p.strip()]


def is_excluded_dir(dir_name, rel_path, exclude_patterns):
    for pat in exclude_patterns:
        if fnmatch.fnmatch(dir_name, pat) or fnmatch.fnmatch(rel_path, pat):
            return True
    return False


def is_probably_text(path, sniff_bytes=4096):
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


def iter_target_files(root_dir, exclude_patterns):
    for root, dirs, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)
        kept = []
        for d in dirs:
            if d == ".git":
                continue
            rel_d = d if rel_root == "." else os.path.join(rel_root, d)
            if is_excluded_dir(d, rel_d, exclude_patterns):
                continue
            kept.append(d)
        dirs[:] = kept
        for name in files:
            path = os.path.join(root, name)
            rel_path = os.path.relpath(path, root_dir)
            yield path, rel_path


REDACTION_ID_RE = re.compile(r"REDACTED_([A-Z0-9_]+)_([0-9]{2,})\b")


class RedactionIdAllocator:
    """Assigns per-label sequential IDs (01, 02, ...) for REDACTED_<LABEL>_<ID>
    placeholders, continuing from whatever IDs are already present in the tree
    instead of persisting counter state to disk. This means IDs stay stable
    across separate sanitize.py/rescan.py runs on the same tree (new secrets
    get new, never-before-used IDs) without needing a state file -- at the
    cost that the same secret value redacted independently in two unrelated
    trees could end up with different IDs, which is fine for this tool's
    purposes."""

    def __init__(self, root_dir, exclude_patterns):
        self._max_ids = find_max_redaction_ids(root_dir, exclude_patterns)
        self._next = {label: max_id + 1 for label, max_id in self._max_ids.items()}
        self._named_cache = {}

    def next_id(self, label):
        label = label.lower()
        n = self._next.get(label, 1)
        self._next[label] = n + 1
        return n

    def placeholder(self, label):
        return f"REDACTED_{label.upper()}_{self.next_id(label):02d}"

    def named_placeholder(self, name):
        """Like placeholder(), but for user-named manual redactions: re-entering
        the same name reuses whatever ID that name already has in the tree (or
        was already assigned earlier this run) instead of bumping to a new one,
        so a name keeps meaning "this exact secret" across repeated runs.

        The resulting placeholder still carries a _<ID> suffix even though a
        name is already 1:1 with its secret and the ID adds no disambiguation
        here -- kept anyway so named placeholders stay parseable by the same
        REDACTION_ID_RE regex find_max_redaction_ids() and other tooling rely
        on for every other placeholder shape. Accepted redundancy, see ticket
        017's notes."""
        label = name.lower()
        if label in self._named_cache:
            return self._named_cache[label]
        if label in self._max_ids:
            id_ = self._max_ids[label]
        else:
            id_ = self.next_id(label)
        placeholder = f"REDACTED_{label.upper()}_{id_:02d}"
        self._named_cache[label] = placeholder
        return placeholder


def find_max_redaction_ids(root_dir, exclude_patterns):
    """Scan root_dir for existing REDACTED_<LABEL>_<ID> placeholders and return
    {label (lowercase): highest ID seen}. Used to seed RedactionIdAllocator so
    IDs keep incrementing across runs without a separate state file."""
    max_ids = {}
    for path, rel_path in iter_target_files(root_dir, exclude_patterns):
        if not is_probably_text(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        for m in REDACTION_ID_RE.finditer(content):
            label = m.group(1).lower()
            num = int(m.group(2))
            if num > max_ids.get(label, 0):
                max_ids[label] = num
    return max_ids


NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


def prompt_known_secrets(allocator):
    """Collect exact secret values to redact interactively. Never echoed, never written to disk.

    After each value, optionally prompts for a name (e.g. "db_password") to use as the
    placeholder label instead of the generic "manual" bucket -- so the value redacts to
    REDACTED_<NAME>_<ID> instead of REDACTED_MANUAL_<ID>. Asking for the name after the
    hidden value (rather than a single "name=value" line) avoids ambiguity with '=' inside
    the secret itself, at the cost of one extra prompt per value. A blank name keeps
    today's REDACTED_MANUAL_<ID> behavior.
    """
    if not sys.stdin.isatty():
        print("No interactive terminal attached -- skipping known-value prompt "
              "(pattern-based scan still runs).")
        return {}

    print("Enter known secret values to redact one at a time (input is hidden).")
    print("Press Enter on an empty prompt when you're done.")
    print("After each value, you can optionally name it (letters/digits/underscore) so it "
          "redacts to REDACTED_<NAME>_<ID> instead of REDACTED_MANUAL_<ID>; leave blank to skip.")
    known_map = {}
    i = 1
    while True:
        value = getpass.getpass(f"  secret value #{i} (blank to finish): ")
        if not value:
            break
        name = input(f"  name for secret value #{i} (optional, letters/digits/_ only): ").strip()
        while name and not NAME_RE.match(name):
            print("  invalid name -- use only letters, digits, and underscores.")
            name = input(f"  name for secret value #{i} (optional, letters/digits/_ only): ").strip()
        if name:
            known_map[value] = allocator.named_placeholder(name)
        else:
            known_map[value] = allocator.placeholder("manual")
        i += 1
    return known_map


def redact_file(path, known_map, log_lines, rel_path, check_only=False, show_diff=False):
    """Returns True if the file has (or, in check_only mode, would have) changed.

    Raises UnicodeDecodeError/OSError on unreadable files -- callers (redact_tree)
    are responsible for catching those and tracking them as skipped, so a file
    that can't be scanned is never silently treated as "nothing to redact."

    Only redacts exact values already present in known_map -- callers are
    responsible for deciding which PATTERNS matches belong in known_map (and
    under which REDACTED_<LABEL>_<ID> placeholder) before calling this, via
    resolve_pattern_redaction. That keeps placeholder-ID assignment in one
    place regardless of whether the match was confirmed interactively or
    auto-confirmed with --no-prompt.
    """
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        content = f.read()

    changed = False

    for real_value, placeholder in known_map.items():
        if real_value and real_value in content:
            count = content.count(real_value)
            line_no = content[: content.find(real_value)].count("\n") + 1
            log_lines.append(f"{rel_path}:{line_no}: known-value match x{count} -> {placeholder}")
            if show_diff:
                print(f"[diff] {rel_path}:{line_no}: {real_value!r} -> {placeholder!r}")
            content = content.replace(real_value, placeholder)
            changed = True

    if changed and not check_only:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    return changed


def scan_patterns(text):
    """Read-only scan of arbitrary text (e.g. a patch file) against the full
    PATTERNS list, with no substitution. Returns [(label, line_no), ...].
    Used wherever a "does this still look like a live secret" check is needed
    outside of a redact_tree pass, so there's exactly one pattern list."""
    matches = []
    for label, pattern, _value_group in PATTERNS:
        for m in pattern.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            matches.append((label, line_no))
    return matches


def redact_tree(root_dir, known_map, exclude_patterns, check_only=False, show_diff=False):
    """Walk root_dir and redact every text file in place.

    Returns (log_lines, changed_files, skipped_files). skipped_files holds
    (rel_path, reason) for anything that looked like text (extension/no null
    bytes) but couldn't actually be read as UTF-8 -- those files are NOT
    scanned for secrets at all, so callers must surface them loudly rather
    than let them pass through silently.
    """
    log_lines = []
    changed_files = []
    skipped_files = []
    for path, rel_path in iter_target_files(root_dir, exclude_patterns):
        if not is_probably_text(path):
            continue
        try:
            if redact_file(path, known_map, log_lines, rel_path, check_only=check_only,
                            show_diff=show_diff):
                changed_files.append(rel_path)
        except UnicodeDecodeError:
            skipped_files.append((rel_path, "not valid UTF-8"))
        except OSError as e:
            skipped_files.append((rel_path, str(e)))
    return log_lines, changed_files, skipped_files


def collect_pattern_matches(root_dir, exclude_patterns):
    """Read-only first pass: walk the tree and collect every distinct value
    that PATTERNS would redact, without modifying anything. Returns a list
    of (value, label) deduplicated by value, in first-seen order.

    Files that can't be read as UTF-8 are silently skipped here -- the normal
    redact_tree pass that runs afterward reports those as skipped_files.
    """
    seen = {}
    for path, rel_path in iter_target_files(root_dir, exclude_patterns):
        if not is_probably_text(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern, value_group in PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(value_group) if value_group is not None else m.group(0)
                if value not in seen:
                    seen[value] = label
    return list(seen.items())


def prompt_pattern_confirmations(matches, allocator):
    """Ask once per unique (value, label) pair from collect_pattern_matches.

    Returns {value: placeholder} for every value the user confirmed is a
    real secret, each placeholder assigned the next REDACTED_<LABEL>_<ID>
    for its label via allocator. Declined values are simply absent from the
    returned map -- callers must not redact them and must not log them as
    matches, and must not consume an ID for them.
    """
    confirmed = {}
    if not matches:
        print("No pattern matches found to review.")
        return confirmed

    print(f"Reviewing {len(matches)} unique pattern match(es) -- confirm each is a real secret.")
    for value, label in matches:
        answer = input(f"  [{label}] {value!r} -- redact this? [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            confirmed[value] = allocator.placeholder(label)
    return confirmed


def resolve_pattern_redaction(root_dir, exclude_patterns, known_map, no_prompt, allocator):
    """Decide how PATTERNS matches get redacted for this run, and mutate
    known_map in place with the resulting REDACTED_<LABEL>_<ID> placeholders.

    Default: prompt once per unique matched value and fold confirmed values
    into known_map. Falls back to auto-confirming every PATTERNS match if
    no_prompt is set, or if there's no interactive terminal to ask on.
    Every match -- prompted or auto-confirmed -- is routed through known_map
    so redact_tree only ever does exact-value substitution, which keeps
    placeholder-ID assignment in this one place regardless of path taken.
    """
    matches = collect_pattern_matches(root_dir, exclude_patterns)
    if no_prompt:
        known_map.update({value: allocator.placeholder(label) for value, label in matches})
        return
    if not sys.stdin.isatty():
        print("No interactive terminal attached -- skipping per-match secret prompt "
              "(pattern-based matches will be redacted automatically). Pass --no-prompt "
              "to silence this message.")
        known_map.update({value: allocator.placeholder(label) for value, label in matches})
        return
    known_map.update(prompt_pattern_confirmations(matches, allocator))
