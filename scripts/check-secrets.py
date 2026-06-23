#!/usr/bin/env python3
"""check-secrets.py — Verify that all keys from .env.example are present in .env.

Parses the .env.example template to extract required key names (skipping comments
and blank lines), then checks each against the live .env file. Exits 0 if all
keys are present and non-empty, exits 1 if any are missing.

Usage
-----
    # Check default paths (project-root .env.example vs .env)
    python3 scripts/check-secrets.py

    # Explicit paths
    python3 scripts/check-secrets.py \\
        --example /path/to/.env.example --env /path/to/.env

    # Verbose: print status for every key
    python3 scripts/check-secrets.py --verbose

Exit codes
----------
    0  — all required keys present and non-empty
    1  — one or more keys missing or empty
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ── Path bootstrap ──────────────────────────────────────────────────────────────
_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPTS_DIR.parent
sys.path.insert(0, str(_SCRIPTS_DIR))

from cred_store import EnvStore  # noqa: E402

_DEFAULT_EXAMPLE = _REPO_ROOT / ".env.example"
_DEFAULT_ENV = _REPO_ROOT / ".env"


# ── Parsing ─────────────────────────────────────────────────────────────────────

def _parse_example_keys(example_path: Path) -> list[str]:
    """Return required key names from a .env.example file.

    Lines that are blank or start with # are skipped.
    Lines of the form KEY= or KEY=<default> contribute KEY.
    """
    keys: list[str] = []
    for line in example_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key:
                keys.append(key)
    return keys


# ── Check ────────────────────────────────────────────────────────────────────────

def check(
    example_path: Path,
    env_path: Path,
    verbose: bool = False,
) -> tuple[list[str], list[str]]:
    """Return (present_keys, missing_keys)."""
    if not example_path.exists():
        raise FileNotFoundError(f".env.example not found: {example_path}")

    keys = _parse_example_keys(example_path)
    store = EnvStore(env_path)
    present: list[str] = []
    missing: list[str] = []

    for key in keys:
        if store.retrieve(key) is not None:
            present.append(key)
            if verbose:
                print(f"  OK       {key}")
        else:
            missing.append(key)
            if verbose:
                print(f"  MISSING  {key}")

    return present, missing


# ── CLI ─────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check-secrets.py",
        description="Verify .env contains all keys declared in .env.example.",
    )
    p.add_argument("--example", type=Path, default=_DEFAULT_EXAMPLE, metavar="PATH",
                   help=f".env.example template (default: {_DEFAULT_EXAMPLE})")
    p.add_argument("--env", type=Path, default=_DEFAULT_ENV, metavar="PATH",
                   help=f"Live .env file (default: {_DEFAULT_ENV})")
    p.add_argument("--verbose", action="store_true",
                   help="Print OK/MISSING status for every key.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        present, missing = check(args.example, args.env, verbose=args.verbose)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    total = len(present) + len(missing)
    if missing:
        print(f"FAIL: {len(missing)}/{total} required secret(s) missing from {args.env}:")
        for key in missing:
            print(f"  - {key}")
        return 1

    print(f"OK: all {total} required secret(s) present in {args.env}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
