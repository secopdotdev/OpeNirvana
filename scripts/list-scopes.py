#!/usr/bin/env python3
"""List Authentik scope mappings and a provider's property_mappings.

Resolves credentials via the project-canonical resolve_admin_token() helper
(prefers AUTHENTIK_API_TOKEN over AUTHENTIK_BOOTSTRAP_TOKEN) so this script
keeps working after bootstrap-token revocation (ADR-0017).

Usage:
    python3 scripts/list-scopes.py [--env PATH] [--provider-id N]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ── Ensure scripts/ is on the path so sibling modules are importable ──────────
_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from utils import AuthentikClient, EnvFile, red, resolve_admin_token

# Default Authentik OAuth2 provider ID to inspect (Nextcloud is provisioned
# first, so pk 1 on a clean install); override with --provider-id.
_DEFAULT_PROVIDER_ID: int = 1


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns an exit code."""
    parser = argparse.ArgumentParser(
        description="List Authentik scope mappings and a provider's property_mappings."
    )
    _stack_env = Path(__file__).resolve().parent.parent / ".env"
    parser.add_argument(
        "--env",
        default=str(_stack_env),
        metavar="PATH",
        help="Path to the .env file (default: <unified-stack>/.env)",
    )
    parser.add_argument(
        "--provider-id",
        type=int,
        default=_DEFAULT_PROVIDER_ID,
        metavar="N",
        help=f"Authentik OAuth2 provider ID to inspect (default: {_DEFAULT_PROVIDER_ID})",
    )
    args = parser.parse_args(argv)

    env_path = Path(args.env)
    if not env_path.exists():
        red(f".env not found: {env_path}")
        return 1

    env = EnvFile(env_path)

    # ── Resolve admin token (ADR-0017: prefers AUTHENTIK_API_TOKEN) ───────────
    token = resolve_admin_token(env)
    if not token:
        red(
            "No Authentik admin token found. "
            "Set AUTHENTIK_API_TOKEN (preferred) or AUTHENTIK_BOOTSTRAP_TOKEN in .env."
        )
        return 1

    # ── Build base URL from .env ───────────────────────────────────────────────
    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    if not public_fqdn:
        red("PUBLIC_FQDN not set in .env")
        return 1

    base_url = f"https://{auth_sub}.{public_fqdn}"
    ak = AuthentikClient(base_url, token)

    # ── List all scope mappings ────────────────────────────────────────────────
    mappings = ak.get("propertymappings/scope/")
    print("All scope mappings:")
    for m in mappings.get("results", []):
        print(
            "  pk=%s  scope=%s  name=%s"
            % (m["pk"], m.get("scope_name", ""), m["name"])
        )

    # ── Provider property_mappings ─────────────────────────────────────────────
    provider = ak.get(f"providers/oauth2/{args.provider_id}/")
    print(
        f"\nProvider {args.provider_id} property_mappings:",
        provider.get("property_mappings", []),
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
