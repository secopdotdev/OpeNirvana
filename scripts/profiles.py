#!/usr/bin/env python3
"""profiles.py — single source of truth for the stack's deployment profiles,
their coarse RBAC categories, and the cross-profile dependency map.

Data lives in profiles.toml (sibling file); this module loads it at import time
and exposes the Python API. Consumers don't read the TOML directly — they
import PROFILES / CATEGORIES / HARD_PROFILE_DEPS / SOFT_PROFILE_DEPS /
SERVICE_CATEGORY_OVERRIDE / rbac_category / resolve / category_of from here.

Two consumers:
  - run.sh: resolve enabled profiles + cherry-picked services into the effective
    service set + COMPOSE_PROFILES, and warn about dependency misconfigurations
    (HARD = won't start; SOFT = degraded) before `docker compose up`.
  - set-auth.py / utils_entra.py (Sub-project B): the service->category rollup
    drives the coarse RBAC group nesting.

Pure data + a pure resolve() (no docker calls), so it's unit-testable and usable
as a deploy-time "doctor". CLI: `profiles.py --check --profiles a,b --services x,y`.
"""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Any

_TOML_PATH = Path(__file__).resolve().parent / "profiles.toml"
with _TOML_PATH.open("rb") as _f:
    _data: dict[str, Any] = tomllib.load(_f)

# Coarse RBAC categories (Sub-project B groups access by these, NOT by fine profile).
CATEGORIES: tuple[str, ...] = tuple(_data["categories"])

# Fine deployment profiles. Each: category (coarse, for RBAC) + its services.
# `core` is infrastructure (no RBAC category) and is always required — its
# `category` key is absent in the TOML and normalized to None here.
PROFILES: dict[str, dict] = {
    name: {
        "category": spec.get("category"),
        "services": list(spec["services"]),
    }
    for name, spec in _data["profiles"].items()
}

# Cross-profile HARD dependencies — target CANNOT START without the dep
# (docker `network_mode: service:` or `depends_on` spanning profiles).
HARD_PROFILE_DEPS: dict[str, list[str]] = {
    k: list(v) for k, v in _data.get("hard_deps", {}).items()
}

# Cross-profile SOFT dependencies — starts, but degraded / no data.
SOFT_PROFILE_DEPS: dict[str, list[str]] = {
    k: list(v) for k, v in _data.get("soft_deps", {}).items()
}

_SERVICE_TO_PROFILE: dict[str, str] = {
    s: p for p, spec in PROFILES.items() for s in spec["services"]
}

# RBAC category overrides for services whose DEPLOYMENT profile differs from the
# coarse category that should govern their UI access. crowdsec deploys with core
# (caddy dependency) but its UI belongs to the netsec access category.
SERVICE_CATEGORY_OVERRIDE: dict[str, str] = dict(_data.get("overrides", {}))


def all_profiles() -> list[str]:
    return list(PROFILES.keys())


def category_of(profile: str) -> str | None:
    return PROFILES.get(profile, {}).get("category")


def rbac_category(service: str) -> str | None:
    """Coarse RBAC category for a service (Sub-project B): explicit override if
    any, else the service's deployment-profile category."""
    if service in SERVICE_CATEGORY_OVERRIDE:
        return SERVICE_CATEGORY_OVERRIDE[service]
    return category_of(_SERVICE_TO_PROFILE.get(service, ""))


def resolve(enabled_profiles: set[str], custom_services: set[str]) -> dict:
    """Resolve enabled profiles + cherry-picked services into the effective set
    and surface dependency issues. Pure (no docker)."""
    unknown = sorted(
        [p for p in enabled_profiles if p not in PROFILES]
        + [s for s in custom_services if s not in _SERVICE_TO_PROFILE]
    )
    valid_profiles = {p for p in enabled_profiles if p in PROFILES}
    valid_services = {s for s in custom_services if s in _SERVICE_TO_PROFILE}

    # A cherry-picked service activates its profile for dependency reasoning.
    active_profiles = set(valid_profiles)
    for s in valid_services:
        active_profiles.add(_SERVICE_TO_PROFILE[s])

    effective_services: set[str] = set(valid_services)
    for p in valid_profiles:
        effective_services.update(PROFILES[p]["services"])

    def _check(table: dict[str, list[str]]) -> list[tuple[str, str]]:
        out = []
        for prof in sorted(active_profiles):
            for dep in table.get(prof, []):
                if dep not in active_profiles:
                    out.append((prof, dep))
        return out

    return {
        "effective_services": sorted(effective_services),
        "active_profiles": sorted(active_profiles),
        "hard_violations": _check(HARD_PROFILE_DEPS),
        "soft_warnings": _check(SOFT_PROFILE_DEPS),
        "core_omitted": "core" not in enabled_profiles,
        "unknown": unknown,
    }


def _csv(s: str) -> set[str]:
    return {x.strip() for x in (s or "").split(",") if x.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description="Resolve + dependency-check stack profiles")
    ap.add_argument("--profiles", default="", help="comma-separated profile names")
    ap.add_argument("--services", default="", help="comma-separated individual service names")
    ap.add_argument("--check", action="store_true", help="exit non-zero on HARD violations / unknown")
    ap.add_argument("--list", action="store_true", help="list profiles by category")
    args = ap.parse_args()

    if args.list:
        for cat in (None,) + CATEGORIES:
            ps = [p for p in PROFILES if PROFILES[p]["category"] == cat]
            label = cat or "core/infra"
            print(f"[{label}] {', '.join(ps)}")
        return 0

    profs = _csv(args.profiles) | {"core"}   # core always implied
    r = resolve(profs, _csv(args.services))
    print(f"effective services ({len(r['effective_services'])}): {', '.join(r['effective_services'])}")
    if r["unknown"]:
        print(f"  UNKNOWN names: {', '.join(r['unknown'])}")
    if r["core_omitted"]:
        print("  WARNING: 'core' not explicitly enabled — core infra must run.")
    for prof, dep in r["hard_violations"]:
        print(f"  HARD: '{prof}' requires '{dep}' (won't start without it)")
    for prof, dep in r["soft_warnings"]:
        print(f"  soft: '{prof}' works better with '{dep}'")
    if args.check and (r["hard_violations"] or r["unknown"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
