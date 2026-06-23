#!/usr/bin/env python3
"""ts-key-broker.py — Generate and store an ephemeral Tailscale auth key.

Calls the Tailscale API to create an ephemeral auth key scoped to the configured
tailnet, then stores it in the chosen credential store for subsequent use by
provisioning scripts.

Run contexts
------------
Windows workstation (default): --store auto → KeyringStore("tailscale")
Linux (no keyring):            --store env --env-path /path/.env
Dry-run (preview):             --dry-run

Usage
-----
    # Generate and store an ephemeral auth key
    python3 scripts/ts-key-broker.py --tailnet example.com --api-key <TS_API_KEY>

    # Longer-lived key (default: 300 seconds)
    python3 scripts/ts-key-broker.py --tailnet example.com --api-key <TS_API_KEY> \\
        --expiry-seconds 3600

    # Linux: store in .env file
    python3 scripts/ts-key-broker.py --tailnet example.com --api-key <TS_API_KEY> \\
        --store env --env-path /path/.env

    # Dry-run
    python3 scripts/ts-key-broker.py --tailnet example.com --api-key <TS_API_KEY> \\
        --dry-run

Credential keys stored
----------------------
    TAILSCALE_AUTH_KEY  — ephemeral Tailscale auth key (reusable=False, preauthorized=True)
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ── Path bootstrap ──────────────────────────────────────────────────────────────
_SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS_DIR))

from cred_store import CredBroker, CredStore  # noqa: E402

_SERVICE_NAME = "tailscale"
_TS_KEYS_URL = "https://api.tailscale.com/api/v2/tailnet/{tailnet}/keys"
_DEFAULT_EXPIRY = 300  # seconds


# ── HTTP helpers ────────────────────────────────────────────────────────────────

def _http_post(url: str, api_key: str, body: dict) -> dict:
    """POST *body* as JSON to *url* with Bearer auth; returns parsed JSON dict."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            err_body = json.loads(exc.read().decode())
        except Exception:
            err_body = {}
        return {"error": err_body.get("message", str(exc)), "status": exc.code}


# ── Key generation ──────────────────────────────────────────────────────────────

def _generate_auth_key(tailnet: str, api_key: str, expiry_seconds: int) -> str | None:
    """Create an ephemeral, preauthorized auth key; return the key string or None on error."""
    url = _TS_KEYS_URL.format(tailnet=tailnet)
    payload = {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": True,
                    "preauthorized": True,
                    "tags": [],
                }
            }
        },
        "expirySeconds": expiry_seconds,
    }
    result = _http_post(url, api_key, payload)
    if "error" in result:
        print(f"  Tailscale API error: {result['error']}", file=sys.stderr)
        return None
    key = result.get("key")
    if not key:
        print(f"  Tailscale API: unexpected response — {result}", file=sys.stderr)
        return None
    key_id = result.get("id", "unknown")
    print(f"  Generated ephemeral auth key id={key_id} (expires in {expiry_seconds}s)")
    return key


# ── CLI ─────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ts-key-broker.py",
        description="Generate and store an ephemeral Tailscale auth key.",
    )
    CredBroker.add_store_args(p)
    p.add_argument("--tailnet", required=True, metavar="TAILNET",
                   help="Tailscale tailnet domain (e.g. example.com).")
    p.add_argument("--api-key", required=True, metavar="API_KEY",
                   help="Tailscale API key (used only for key generation, not stored).")
    p.add_argument("--expiry-seconds", type=int, default=_DEFAULT_EXPIRY,
                   metavar="SECS",
                   help=f"Key expiry in seconds (default: {_DEFAULT_EXPIRY}).")
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

    print("Generating Tailscale ephemeral auth key...")

    if dry_run:
        print(f"  [dry-run] would POST to Tailscale API for tailnet={args.tailnet}")
        print(f"  [dry-run] would store TAILSCALE_AUTH_KEY in credential store")
        return 0

    auth_key = _generate_auth_key(args.tailnet, args.api_key, args.expiry_seconds)
    if auth_key is None:
        return 1

    assert store is not None
    store.store("TAILSCALE_AUTH_KEY", auth_key)
    print("  TAILSCALE_AUTH_KEY stored in credential store")
    return 0


if __name__ == "__main__":
    sys.exit(main())
