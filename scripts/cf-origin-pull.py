#!/usr/bin/env python3
"""cf-origin-pull.py — Provision Cloudflare zone-level Authenticated Origin Pulls (AOP).

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here EXCEPT the documented fall-through token
resolution (operator direction 2026-06-16); update the canonical and re-copy.
Vendored so a live openirvana deploy (and the sanitized public OpeNirvana mirror)
provisions AOP standalone from .env with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001.

Upload the origin-pull client cert to the zone and enable AOP, or report status.
Token resolution (first match wins): --token, else each --token-key in order from the
credential store (DPAPI keyring on Windows / .env via --store env on the deploy host /
OpenBao). The default key order is fall-through: a dedicated least-privilege SSL:Edit
token (CLOUDFLARE_ORIGIN_TLS_RW_TOKEN), then the monolithic CLOUDFLARE_API_TOKEN — so both a
least-privilege split and a single all-scopes key work.

Examples:
  # Live deploy (Linux host) — read the token from .env:
  python3 scripts/cf-origin-pull.py --store env --env-path ../.env --fqdn example.com \
      --cert-file cf-client.pem --key-file cf-client.key --enable
  python3 scripts/cf-origin-pull.py --store env --env-path ../.env --fqdn example.com --status
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Sibling-module imports (standalone vendored layout — no cloudflare_toolkit package).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _http import api_get, resolve_zone_id  # noqa: E402
    from cred_store import CredBroker, CredStore  # noqa: E402
    from origin_tls import ensure_origin_pull, list_client_certs  # noqa: E402
except ImportError as e:
    print(f"ERROR: vendored cloudflare modules not found: {e}", file=sys.stderr)
    sys.exit(2)

_SERVICE_NAME = "cloudflare"
# Fall-through order: dedicated least-privilege SSL:Edit token first, then the
# monolithic all-scopes token. Overridable with one or more --token-key flags.
_DEFAULT_TOKEN_KEYS = ["CLOUDFLARE_ORIGIN_TLS_RW_TOKEN", "CLOUDFLARE_API_TOKEN"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cf-origin-pull.py", description=__doc__)
    CredBroker.add_store_args(p)
    p.add_argument("--fqdn", required=True, help="Any hostname in the target zone (apex resolved)")
    p.add_argument("--cert-file", help="PEM client certificate to upload")
    p.add_argument("--key-file", help="PEM private key for the client certificate")
    p.add_argument(
        "--enable",
        action="store_true",
        help="Enable zone-level AOP after upload",
    )
    p.add_argument(
        "--status",
        action="store_true",
        help="Report certs + AOP state, do not mutate",
    )
    p.add_argument(
        "--token",
        help="Override: CF API token (else read each --token-key from the credential store)",
    )
    p.add_argument(
        "--token-key",
        action="append",
        metavar="KEY",
        help=(
            "Credential key to try, in order (repeatable). Default fall-through: "
            "CLOUDFLARE_ORIGIN_TLS_RW_TOKEN then CLOUDFLARE_API_TOKEN."
        ),
    )
    return p


def _build_store(args: argparse.Namespace) -> CredStore | None:
    return CredBroker.build_store(args, _SERVICE_NAME)


def _token(args: argparse.Namespace) -> str | None:
    """Resolve the CF token: --token, else the first non-empty --token-key from the store."""
    if args.token:
        return str(args.token)
    store = _build_store(args)
    if store is None:
        return None
    for key in (args.token_key or _DEFAULT_TOKEN_KEYS):
        val = store.retrieve(key)
        if val:
            return val
    return None


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    token = _token(args)
    if not token:
        tried = " or ".join(args.token_key or _DEFAULT_TOKEN_KEYS)
        print(
            f"ERROR: no CF token available (--token, or {tried} in the store)",
            file=sys.stderr,
        )
        return 1

    if args.status:
        # README elevates --status to the capability-probe verify command, so
        # surface a clean message on a scope miss / bad token rather than a
        # urllib traceback. (Divergence from canonical — backport on PR #3.)
        try:
            zone_id = resolve_zone_id(token, args.fqdn)
            certs: list[dict[str, Any]] = list_client_certs(token, zone_id)
            settings: dict[str, Any] = api_get(
                token, f"/zones/{zone_id}/origin_tls_client_auth/settings"
            )
        except (RuntimeError, OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        result_section: dict[str, Any] = settings.get("result") or {}
        print(
            json.dumps(
                {
                    "zone_id": zone_id,
                    "cert_ids": [c.get("id") for c in certs],
                    "aop_enabled": result_section.get("enabled"),
                }
            )
        )
        return 0

    if not (args.cert_file and args.key_file):
        print(
            "ERROR: --cert-file and --key-file are required unless --status",
            file=sys.stderr,
        )
        return 1

    cert_pem = Path(args.cert_file).read_text(encoding="utf-8")
    key_pem = Path(args.key_file).read_text(encoding="utf-8")
    try:
        result: dict[str, Any] = ensure_origin_pull(
            token, args.fqdn, cert_pem, key_pem, enable=args.enable
        )
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
