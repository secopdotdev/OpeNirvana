#!/usr/bin/env python3
"""cf-token-broker.py — Store and verify Cloudflare API credentials.

Stores CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in the chosen credential store.
Optionally verifies the stored token is accepted by the Cloudflare API.

Run contexts
------------
Windows workstation (default): --store auto → KeyringStore("cloudflare")
Linux (no keyring):            --store env --env-path /path/.env
Dry-run (preview):             --dry-run

Usage
-----
    # Store credentials
    python3 scripts/cf-token-broker.py --token <TOKEN> --zone-id <ZONE_ID>

    # Store and verify against the Cloudflare API
    python3 scripts/cf-token-broker.py --token <TOKEN> --zone-id <ZONE_ID> --verify

    # Verify stored credentials (no --token / --zone-id)
    python3 scripts/cf-token-broker.py --verify

    # Linux: store in .env file
    python3 scripts/cf-token-broker.py --store env --env-path /path/.env \\
        --token <TOKEN> --zone-id <ZONE_ID>

    # Dry-run
    python3 scripts/cf-token-broker.py --dry-run --token <TOKEN> --zone-id <ZONE_ID>

Credential keys stored
----------------------
    CLOUDFLARE_API_TOKEN  — Cloudflare API token (scoped to the target zone)
    CLOUDFLARE_ZONE_ID    — Cloudflare zone ID
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ── Path bootstrap ──────────────────────────────────────────────────────────────
_SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS_DIR))

from cred_store import CredBroker, CredStore  # noqa: E402

_SERVICE_NAME = "cloudflare"
_CF_VERIFY_URL = "https://api.cloudflare.com/client/v4/user/tokens/verify"


# ── HTTP helpers ────────────────────────────────────────────────────────────────

def _http_get(url: str, token: str) -> dict:
    """GET *url* with Bearer token auth; returns parsed JSON dict."""
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        import json
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            body = {}
        return {"success": False, "errors": body.get("errors", [str(exc)])}


# ── Store helpers ───────────────────────────────────────────────────────────────

def _store_credentials(
    store: CredStore, token: str, zone_id: str
) -> None:
    store.store("CLOUDFLARE_API_TOKEN", token)
    store.store("CLOUDFLARE_ZONE_ID", zone_id)
    print("  CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID stored in credential store")


def _verify_token(token: str) -> bool:
    """Return True if the Cloudflare API accepts *token*."""
    result = _http_get(_CF_VERIFY_URL, token)
    if result.get("success"):
        status = (result.get("result") or {}).get("status", "unknown")
        print(f"  CF token verification: OK (status={status})")
        return True
    errors = result.get("errors", [])
    print(f"  CF token verification: FAILED — {errors}", file=sys.stderr)
    return False


# ── CLI ─────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cf-token-broker.py",
        description="Store and verify Cloudflare API credentials.",
    )
    CredBroker.add_store_args(p)
    p.add_argument("--token", default=None, metavar="TOKEN",
                   help="CLOUDFLARE_API_TOKEN value to store (omit to use already-stored value).")
    p.add_argument("--zone-id", default=None, metavar="ZONE_ID",
                   help="CLOUDFLARE_ZONE_ID value to store.")
    p.add_argument("--verify", action="store_true",
                   help="Verify the stored/provided token against the Cloudflare API.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    dry_run: bool = args.dry_run

    store: CredStore | None = None
    if not dry_run:
        try:
            store = CredBroker.build_store(args, _SERVICE_NAME)
        except (ValueError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    # Store credentials if provided.
    if args.token or args.zone_id:
        if not args.token or not args.zone_id:
            print("ERROR: --token and --zone-id must both be provided together.",
                  file=sys.stderr)
            return 1
        if dry_run:
            print("  [dry-run] would store CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID")
        else:
            assert store is not None
            _store_credentials(store, args.token, args.zone_id)

    # Verify if requested.
    if args.verify:
        token = args.token
        if token is None and store is not None:
            token = store.retrieve("CLOUDFLARE_API_TOKEN")
        if token is None:
            print("ERROR: No token available — provide --token or store credentials first.",
                  file=sys.stderr)
            return 1
        if dry_run:
            print("  [dry-run] would verify CLOUDFLARE_API_TOKEN against Cloudflare API")
        else:
            if not _verify_token(token):
                return 1

    if not args.token and not args.verify:
        print("Nothing to do — provide --token/--zone-id to store, --verify to check.",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
