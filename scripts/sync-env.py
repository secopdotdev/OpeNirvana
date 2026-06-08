#!/usr/bin/env python3
"""
sync-env.py — Sync .env from .env.example without losing configured values.

For every key in .env.example:
  - Key EXISTS in .env with a non-empty value  → keep the .env value
  - Key EXISTS in .env with an empty value     → keep it blank (user cleared it intentionally)
  - Key NOT in .env                            → add it with the .env.example default

Keys in .env that are not in .env.example are preserved at the bottom.
Structure (section headers, blank lines, inline comments) is taken from .env.example.

Usage:
    python3 scripts/sync-env.py [--dry-run] [--no-backup] [path/to/.env]
    (defaults to <unified-stack>/.env)
"""

import argparse
import re
import sys
from pathlib import Path


# ── Renamed variables ──────────────────────────────────────────────────────────

# Variables renamed across .env.example revisions: {old_name: new_name}.
# When .env still carries an old name, its value is migrated to the new name
# and the stale old key is dropped (not preserved as an extra key).
RENAMES: dict[str, str] = {
    "CROWDSEC_BOUNCER_KEY":    "CROWDSEC_BOUNCER_API_KEY",
    "CROWDSEC_ENROLL_KEY":     "CROWDSEC_ENROLL_API_KEY",
    "DOCKER_SUPPLEMENTAL_GID": "DOCKER_GID",
}


# ── Parsing helpers ────────────────────────────────────────────────────────────

_INLINE_COMMENT = re.compile(r"\s+#.*$")


def parse_env(text: str) -> dict[str, str]:
    """
    Return {KEY: value} for every KEY= line, including keys with empty values.
    Keys present with empty values are distinguished from absent keys — the
    caller uses this to respect intentional blanks.
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, rest = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        result[key] = _INLINE_COMMENT.sub("", rest).strip()
    return result


def split_line(line: str) -> tuple[str | None, str, str]:
    """
    Split 'KEY=value   # comment' into (key, value, comment_suffix).
    comment_suffix includes all leading whitespace before '#'.
    Returns (None, '', '') for comment lines, blank lines, and non-assignment lines.
    """
    if "=" not in line:
        return None, "", ""
    key_part, rest = line.split("=", 1)
    key = key_part.strip()
    if not key or key.startswith("#"):
        return None, "", ""

    # Find the first inline comment: whitespace followed by '#'.
    # Walk character-by-character; skip '#' that has no preceding whitespace.
    comment_start = -1
    for i in range(1, len(rest)):
        if rest[i] == "#" and rest[i - 1] in " \t":
            # Include all contiguous whitespace before '#'
            j = i - 1
            while j > 0 and rest[j - 1] in " \t":
                j -= 1
            comment_start = j
            break

    if comment_start >= 0:
        value = rest[:comment_start].rstrip()
        comment_suffix = rest[comment_start:].rstrip()
    else:
        value = rest.rstrip()
        comment_suffix = ""

    return key, value, comment_suffix


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    default_env = Path(__file__).resolve().parent.parent / ".env"
    parser = argparse.ArgumentParser(
        description="Sync .env from .env.example without losing configured values."
    )
    parser.add_argument(
        "env_file", nargs="?", default=str(default_env),
        metavar="PATH", help="Path to .env (default: <unified-stack>/.env)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing to disk",
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="Skip creating .env.bak before writing",
    )
    args = parser.parse_args()

    env_path    = Path(args.env_file).resolve()
    example_path = env_path.parent / ".env.example"

    if not example_path.exists():
        print(f"ERROR: .env.example not found at {example_path}", file=sys.stderr)
        return 1

    example_text = example_path.read_text(encoding="utf-8")
    env_text     = env_path.read_text(encoding="utf-8") if env_path.exists() else ""

    # Parse existing .env — includes keys with empty values so we can
    # distinguish "key absent" (add from example) vs "key set blank" (keep blank).
    env_values    = parse_env(env_text)
    example_keys: set[str] = set()

    output_lines: list[str] = []
    added:   list[str] = []   # new keys pulled from .env.example
    updated: list[str] = []   # existing keys whose value changed in .env
    renamed: list[str] = []   # values migrated from a renamed old key

    # Reverse rename map + set of old keys consumed by a rename (excluded from extras).
    _new_to_old: dict[str, str] = {new: old for old, new in RENAMES.items()}
    consumed_old_keys: set[str] = set()

    for line in example_text.splitlines():
        key, ex_value, comment = split_line(line)

        if key is None:
            # Comment / blank / non-assignment — pass through verbatim
            output_lines.append(line)
            continue

        example_keys.add(key)

        # If this key was renamed from an old name still present in .env, retire
        # the old key regardless of whether its value ends up being migrated.
        old_name = _new_to_old.get(key)
        if old_name and old_name in env_values:
            consumed_old_keys.add(old_name)

        env_val = env_values.get(key)                 # None=absent, ""=blank
        old_val = env_values.get(old_name, "") if old_name else ""

        if env_val:
            # Non-empty in .env — use that value, keep .env.example comment
            chosen = env_val
            if env_val != ex_value:
                updated.append(f"  ~ {key}: '{ex_value}' -> '{env_val}'")
        elif old_val:
            # New key absent/blank but the renamed old key carries a value — migrate it
            chosen = old_val
            renamed.append(f"  ~ {old_name} -> {key} (value migrated)")
        elif key in env_values:
            # Present but intentionally blank — keep blank with example comment
            chosen = ""
        else:
            # Brand-new key — use the .env.example default (may be blank)
            chosen = ex_value
            added.append(f"  + {key}={ex_value}" if ex_value else f"  + {key}= (blank default)")

        if chosen:
            output_lines.append(f"{key}={chosen}{comment}")
        else:
            output_lines.append(f"{key}={comment}" if comment else f"{key}=")

    # Keys present in .env but absent from .env.example (excluding retired old names)
    extra = {k: v for k, v in env_values.items()
             if k not in example_keys and k not in consumed_old_keys}
    if extra:
        output_lines.append("")
        output_lines.append("# ── Values from .env not present in .env.example ─────────────")
        for k, v in extra.items():
            output_lines.append(f"{k}={v}")

    new_text = "\n".join(output_lines) + "\n"

    # ── Report ─────────────────────────────────────────────────────────────────
    print(f".env.example: {len(example_keys)} keys")
    print(f".env current: {len(env_values)} keys")

    if added:
        print(f"\nNew keys from .env.example ({len(added)}):")
        for msg in added:
            print(msg)

    if updated:
        print(f"\nExisting values kept from .env ({len(updated)}):")
        for msg in updated:
            print(msg)

    if renamed:
        print(f"\nRenamed variables migrated ({len(renamed)}):")
        for msg in renamed:
            print(msg)

    if extra:
        print(f"\nExtra keys not in .env.example (preserved, {len(extra)}):")
        for k in extra:
            print(f"  > {k}")

    if not added and not updated and not renamed and not extra:
        print("\nNo changes — .env is already in sync with .env.example.")

    # ── Write ──────────────────────────────────────────────────────────────────
    if args.dry_run:
        print("\n[dry-run] No files written.")
        return 0

    if new_text == env_text:
        print("\n.env is already identical to the merged result — nothing written.")
        return 0

    if env_path.exists() and not args.no_backup:
        backup = env_path.with_suffix(".bak")
        backup.write_text(env_text, encoding="utf-8")
        print(f"\nBackup: {backup}")

    env_path.write_text(new_text, encoding="utf-8")
    print(f"Written: {env_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
