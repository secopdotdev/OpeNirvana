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
import re
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

# Bundles — meta-groups expanding to fine profiles. STACK_PROFILES may list a
# bundle name OR a fine profile; expand_bundles() flattens bundles to profiles.
BUNDLES: dict[str, list[str]] = {k: list(v) for k, v in _data.get("bundles", {}).items()}

# Service-level HARD dependencies (compose depends_on / network_mode: service:).
# The resolver refuses a SERVICE_DISABLE that removes a service another ENABLED
# service hard-needs.
SERVICE_HARD_DEPS: dict[str, list[str]] = {
    k: list(v) for k, v in _data.get("service_deps", {}).items()
}

# core is always-on and irreducible — disabling a core service is refused.
CORE_SERVICES: frozenset[str] = frozenset(PROFILES["core"]["services"])

# Container↔host ownership exceptions (ADR-0014) layered on the 1010:1010 / mode-770
# baseline that docker-host-config.sh:create_dock_tree() establishes. Each entry
# names the /dock paths a service owns, the numeric UID:GID it runs as, the mode,
# and whether chown/chmod recurse. ownership_manifest() flattens this to a
# shell-parsable table that create_dock_tree applies in one idempotent loop —
# replacing ~60 lines of reactively-added ad-hoc chown special cases.
OWNERSHIP: list[dict[str, Any]] = [dict(e) for e in _data.get("ownership", [])]


def _validate_ownership(entries: list[dict[str, Any]]) -> None:
    """Fail loud (ADR-0014) on a malformed ownership entry — at import time, so a
    bad edit aborts host prep rather than silently emitting a wrong/empty manifest."""
    for e in entries:
        svc = e.get("service", "<unnamed>")
        paths = e.get("paths")
        if not paths or not isinstance(paths, list):
            raise ValueError(f"ownership[{svc}]: 'paths' is required and must be a non-empty list")
        if ("uid" in e) != ("gid" in e):
            raise ValueError(f"ownership[{svc}]: 'uid' and 'gid' must be set together (or both omitted)")
        if "uid" not in e and "mode" not in e:
            raise ValueError(f"ownership[{svc}]: entry sets neither owner nor mode — it is a no-op")
        if "mode" in e and not re.fullmatch(r"[0-7]{3,4}", str(e["mode"])):
            raise ValueError(f"ownership[{svc}]: 'mode' must be an octal string, got {e['mode']!r}")
        for p in paths:
            if not isinstance(p, str) or not p.startswith("/dock/"):
                raise ValueError(f"ownership[{svc}]: path {p!r} must be a string under /dock/")
            if any(c.isspace() for c in p):
                raise ValueError(f"ownership[{svc}]: path {p!r} has whitespace (manifest is tab-separated)")


_validate_ownership(OWNERSHIP)


def ownership_manifest() -> list[tuple[str, str, str, str, str, str]]:
    """Flatten OWNERSHIP to one row per path for create_dock_tree's apply loop.

    Each row is (path, uid, gid, mode, chown_recursive, chmod_recursive) as
    strings; uid/gid/mode are "-" when the entry omits them (a mode-only entry
    keeps the 1010 baseline owner; a chown-only entry keeps the baseline mode),
    and the recursion flags are "1"/"0". The values reproduce the exact
    owner/group/mode the pre-refactor create_dock_tree applied (ADR-0014,
    regression-safe), so the refactor preserves green rather than re-deriving it.
    """
    rows: list[tuple[str, str, str, str, str, str]] = []
    for e in OWNERSHIP:
        uid = str(e["uid"]) if "uid" in e else "-"
        gid = str(e["gid"]) if "gid" in e else "-"
        mode = str(e["mode"]) if "mode" in e else "-"
        crec = "1" if e.get("chown_recursive", False) else "0"
        mrec = "1" if e.get("chmod_recursive", False) else "0"
        for path in e["paths"]:
            rows.append((path, uid, gid, mode, crec, mrec))
    return rows


def expand_bundles(names: set[str]) -> set[str]:
    """Flatten any bundle names in `names` to their member profiles; pass other
    names (fine profiles, or unknowns for the caller to flag) through."""
    out: set[str] = set()
    for n in names:
        if n in BUNDLES:
            out.update(BUNDLES[n])
        else:
            out.add(n)
    return out


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


def resolve(
    enabled_profiles: set[str],
    custom_services: set[str],
    disabled_services: set[str] | frozenset[str] = frozenset(),
) -> dict:
    """Resolve enabled profiles (+ bundles) and cherry-picked SERVICE_ENABLE into
    the effective service set, apply SERVICE_DISABLE, and surface dependency
    issues. Pure (no docker).

    - bundles in `enabled_profiles` are expanded to fine profiles first.
    - `custom_services` (SERVICE_ENABLE) force individual services on.
    - `disabled_services` (SERVICE_DISABLE) force services off, EXCEPT core
      services (refused, reported in `illegal_core_disable`) and EXCEPT a service
      another enabled service hard-needs (refused, reported in
      `disable_hard_violations`).
    """
    enabled_profiles = expand_bundles(set(enabled_profiles))

    unknown = sorted(
        [p for p in enabled_profiles if p not in PROFILES]
        + [s for s in (custom_services | set(disabled_services))
           if s not in _SERVICE_TO_PROFILE]
    )
    valid_profiles = {p for p in enabled_profiles if p in PROFILES}
    valid_services = {s for s in custom_services if s in _SERVICE_TO_PROFILE}
    valid_disable = {s for s in disabled_services if s in _SERVICE_TO_PROFILE}

    # A cherry-picked service activates its profile for dependency reasoning.
    active_profiles = set(valid_profiles)
    for s in valid_services:
        active_profiles.add(_SERVICE_TO_PROFILE[s])

    effective_services: set[str] = set(valid_services)
    for p in valid_profiles:
        effective_services.update(PROFILES[p]["services"])

    # core is irreducible: a disable targeting a core service is refused (and
    # reported), never applied. Non-core disables are applied.
    illegal_core_disable = sorted(valid_disable & CORE_SERVICES)
    effective_services -= (valid_disable - CORE_SERVICES)

    # Service-level HARD-dep check: an enabled service whose hard-needed peer is
    # now absent (disabled, or never selected) would make the compose project
    # invalid / crashloop. Fail closed.
    disable_hard_violations: list[tuple[str, str]] = []
    for svc in sorted(effective_services):
        for dep in SERVICE_HARD_DEPS.get(svc, []):
            if dep not in effective_services:
                disable_hard_violations.append((svc, dep))

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
        "disable_hard_violations": disable_hard_violations,
        "illegal_core_disable": illegal_core_disable,
        "core_omitted": "core" not in enabled_profiles,
        "unknown": unknown,
    }


def _csv(s: str) -> set[str]:
    return {x.strip() for x in (s or "").split(",") if x.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description="Resolve + dependency-check stack profiles")
    ap.add_argument("--profiles", default="", help="comma-separated profile or bundle names")
    ap.add_argument("--enable", "--services", dest="enable", default="",
                    help="comma-separated services to force ON (SERVICE_ENABLE)")
    ap.add_argument("--disable", default="",
                    help="comma-separated services to force OFF (SERVICE_DISABLE)")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero on HARD/disable/core violations or unknown names")
    ap.add_argument("--list", action="store_true", help="list profiles by category + bundles")
    ap.add_argument("--resolve", action="store_true",
                    help="print only the resolved service list (space-separated) for run.sh")
    ap.add_argument("--ownership-manifest", dest="ownership_manifest", action="store_true",
                    help="emit the tab-separated /dock ownership manifest for create_dock_tree (ADR-0014)")
    args = ap.parse_args()

    if args.ownership_manifest:
        # path<TAB>uid<TAB>gid<TAB>mode<TAB>chown_recursive<TAB>chmod_recursive
        for row in ownership_manifest():
            print("\t".join(row))
        return 0

    if args.list:
        for cat in (None,) + CATEGORIES:
            ps = [p for p in PROFILES if PROFILES[p]["category"] == cat]
            label = cat or "core/infra"
            print(f"[{label}] {', '.join(ps)}")
        if BUNDLES:
            for b, members in BUNDLES.items():
                print(f"[bundle:{b}] {', '.join(members)}")
        return 0

    profs = _csv(args.profiles) | {"core"}   # core always implied
    r = resolve(profs, _csv(args.enable), _csv(args.disable))

    if args.resolve:
        # machine-readable: just the explicit service list run.sh passes to
        # `docker compose up`. Still fail closed on blocking violations.
        if r["unknown"] or r["hard_violations"] or r["disable_hard_violations"] or r["illegal_core_disable"]:
            for name in r["unknown"]:
                print(f"unknown name: {name}", file=sys.stderr)
            for prof, dep in r["hard_violations"]:
                print(f"HARD: '{prof}' requires '{dep}'", file=sys.stderr)
            for svc, dep in r["disable_hard_violations"]:
                print(f"DISABLE-HARD: '{svc}' needs '{dep}' (re-enable it or don't disable it)", file=sys.stderr)
            for svc in r["illegal_core_disable"]:
                print(f"CORE: '{svc}' is core infrastructure and cannot be disabled", file=sys.stderr)
            return 1
        print(" ".join(r["effective_services"]))
        return 0

    print(f"effective services ({len(r['effective_services'])}): {', '.join(r['effective_services'])}")
    if r["unknown"]:
        print(f"  UNKNOWN names: {', '.join(r['unknown'])}")
    if r["core_omitted"]:
        print("  WARNING: 'core' not explicitly enabled — core infra must run.")
    for svc in r["illegal_core_disable"]:
        print(f"  CORE: '{svc}' is core infrastructure - cannot be disabled")
    for prof, dep in r["hard_violations"]:
        print(f"  HARD: '{prof}' requires '{dep}' (won't start without it)")
    for svc, dep in r["disable_hard_violations"]:
        print(f"  DISABLE-HARD: '{svc}' needs '{dep}' (disabled/absent — would crashloop)")
    for prof, dep in r["soft_warnings"]:
        print(f"  soft: '{prof}' works better with '{dep}'")
    blocking = (r["hard_violations"] or r["unknown"]
                or r["disable_hard_violations"] or r["illegal_core_disable"])
    if args.check and blocking:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
