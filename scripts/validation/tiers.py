"""Blast-radius tier registry — single source of truth for per-script rigor.

Mirrors the tier lists in the design spec. Adding a script here is how you opt it
into the correct validation intensity.
"""

from __future__ import annotations

from pathlib import Path

from validation.model import Tier

TIER_MAP: dict[str, Tier] = {
    # -- Tier 0 -- crown jewels (identity & secrets) --
    "utils_entra.py": Tier.T0,
    "utils_authentik_oidc.py": Tier.T0,
    "utils_authentik_proxy.py": Tier.T0,
    "gen-secrets.py": Tier.T0,
    "bao_client.py": Tier.T0,
    "bao-bootstrap.py": Tier.T0,
    "bao-sync.py": Tier.T0,
    "bao-unseal.py": Tier.T0,
    "set-auth.py": Tier.T0,
    "audit-user-access.py": Tier.T0,
    "undo-entra.py": Tier.T0,
    "utils_nextcloud.py": Tier.T0,
    # -- Tier 1 -- deployment integrity --
    "docker-host-config.sh": Tier.T1,
    "run.sh": Tier.T1,
    "add-service.py": Tier.T1,
    "sync-env.py": Tier.T1,
    "profiles.py": Tier.T1,
    "profiles.toml": Tier.T1,
    "utils.py": Tier.T1,
    "utils_discovery.py": Tier.T1,
    "setup-sso-lockdown.py": Tier.T1,
    "fix-permissions.sh": Tier.T1,
    # -- Tier 2 -- operational / generators --
    "check-stack.py": Tier.T2,
    "maintain.py": Tier.T2,
    "check-versions.py": Tier.T2,
    "gen-grafana-dashboards.py": Tier.T2,
    "gen-dashy-config.py": Tier.T2,
    "grafana_panels.py": Tier.T2,
}


def tier_for(path: str | Path) -> Tier:
    """Return the tier for a file by basename; unknown files default to T2."""
    return TIER_MAP.get(Path(path).name, Tier.T2)
