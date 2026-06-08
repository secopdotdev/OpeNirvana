#!/usr/bin/env python3
"""gen-service-artifacts.py — single registration-point tooling for the service catalog (Rec 1).

Phase 1 (this file, VALIDATE-ONLY): `--check` cross-validates the service catalog across the three
independent representations that today can silently diverge — the exact "parallel service lists"
gap the comparative review flagged (Agent B#7):

  1. profiles.toml        (via profiles.PROFILES)        — which services deploy together
  2. docker-compose.yml   (top-level `services:` keys)   — which services are actually defined
  3. check-versions.py    (REGISTRY keys)                — which services are version-monitored

Exit non-zero on BLOCKING drift (a profile references a service that does not exist in compose — a
silent-misconfiguration bug). Ghost-monitored entries (REGISTRY keys with no compose service) are a
WARNING, not a failure, because the mapping is intentionally partial.

Validate-only is deliberate (adopt-from-prod-host Rec 1, user decision): prove the drift contract
before any generation. A later phase adds generation of Caddy snippets / .env keys FROM profiles.toml
(only-if-blank, human > inference > blank). Stdlib-only — the compose parse is a small regex, not a
YAML dependency (ADR-0001).

Usage:
    python3 scripts/gen-service-artifacts.py --check
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
_STACK = _SCRIPTS.parent
_COMPOSE = _STACK / "docker-compose.yml"


def _load(module_name: str, filename: str):
    """Import a sibling script (handles hyphenated filenames) and return the module."""
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS / filename)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def compose_services(compose_path: Path | None = None) -> set[str]:
    """Top-level service names under `services:` in docker-compose.yml.

    Stdlib regex parse (no YAML dep): service names are exactly 2-space-indented keys inside the
    `services:` block; a column-0 line ends the block; deeper (4+ space) keys are service sub-config.
    """
    text = (compose_path or _COMPOSE).read_text(encoding="utf-8")
    services: set[str] = set()
    in_services = False
    for line in text.splitlines():
        if re.match(r"^services:\s*(?:#.*)?$", line):
            in_services = True
            continue
        if in_services:
            if re.match(r"^\S", line):  # a new top-level key ends the services block
                in_services = False
                continue
            m = re.match(r"^  ([A-Za-z0-9][A-Za-z0-9_.-]*):\s*(?:#.*)?$", line)
            if m:
                services.add(m.group(1))
    return services


def profiles_services() -> set[str]:
    mod = _load("profiles", "profiles.py")
    svcs: set[str] = set()
    for spec in mod.PROFILES.values():
        svcs.update(spec.get("services", []))
    return svcs


def registry_services() -> set[str]:
    mod = _load("check_versions", "check-versions.py")
    return set(mod.REGISTRY.keys())


def check() -> int:
    compose = compose_services()
    profiles = profiles_services()
    registry = registry_services()

    missing = sorted(profiles - compose)   # BLOCKING — a profile points at a non-existent service
    ghost = sorted(registry - compose)     # WARN — monitoring a service compose does not define

    if missing:
        print("  DRIFT (blocking): profiles.toml service(s) not defined in docker-compose.yml:")
        for s in missing:
            print(f"    - {s}")
    if ghost:
        print("  WARN: check-versions REGISTRY entr(ies) with no matching compose service:")
        for s in ghost:
            print(f"    - {s}")

    print(f"  catalog: {len(compose)} compose / {len(profiles)} profile / {len(registry)} monitored "
          f"-> {len(missing)} blocking drift, {len(ghost)} ghost-monitored")
    return 1 if missing else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="Validate catalog consistency across profiles.toml / compose / REGISTRY")
    args = ap.parse_args()
    if args.check:
        return check()
    ap.print_usage(sys.stderr)
    print("\nNothing to do — pass --check (generation modes are a future phase).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
