"""hsts.py — Cloudflare HSTS policy automation.

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Vendored so HSTS enforcement runs standalone on the deploy host (and in the
sanitized public OpeNirvana mirror) with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001. The only deviation from
canonical is the import line below: `from _http` (sibling vendored module) instead
of `from cloudflare_toolkit._http` (installed package).

Cloudflare rewrites the origin's Strict-Transport-Security header at edge,
overriding whatever the origin (Caddy, nginx, etc.) sends. The API control
lives under SSL/TLS → Edge Certificates → HSTS; this module automates that
setting so new zones get a 1-year policy without manual dashboard clicks.

The target values mirror Caddy's security-headers snippet so the observable
header is consistent whether a request goes via CF or origin-direct.

CF caps max_age at 31536000s (1 year); this still exceeds Nextcloud's
setupcheck threshold of 15552000s (6 months).
"""
from __future__ import annotations

import sys
import urllib.error
from typing import Any

from _http import api_get, api_patch, resolve_zone_id

_HSTS_TARGET = {
    "enabled":            True,
    "max_age":            31536000,
    "include_subdomains": True,
    "preload":            True,
}


def apply_hsts(token: str, fqdn: str) -> bool:
    """Ensure the HSTS policy for *fqdn*'s zone matches ``_HSTS_TARGET``.

    Returns ``True`` if a PATCH was issued, ``False`` if already at target.
    Raises on unrecoverable API errors.

    The token (``CLOUDFLARE_API_TOKEN``) must have ``Zone.Zone Settings:Edit``
    permission scope — the API returns 403 without it.
    """
    zone_id = resolve_zone_id(token, fqdn)

    try:
        current = api_get(token, f"/zones/{zone_id}/settings/security_header")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            print(
                "CF API 403 on /zones/.../settings/security_header.\n"
                "The token is missing Zone.Zone Settings:Edit permission.\n"
                "Add it via dashboard → My Profile → API Tokens → edit.",
                file=sys.stderr,
            )
            raise
        raise

    result_val: dict[str, Any] = current.get("result") or {}
    value_val: dict[str, Any] = result_val.get("value") or {}
    sts: dict[str, Any] = value_val.get("strict_transport_security") or {}

    if all(sts.get(k) == v for k, v in _HSTS_TARGET.items()):
        print(
            f"HSTS already at target: max_age={sts.get('max_age')} "
            f"include_subdomains={sts.get('include_subdomains')} "
            f"preload={sts.get('preload')}"
        )
        return False

    resp = api_patch(
        token,
        f"/zones/{zone_id}/settings/security_header",
        {"value": {"strict_transport_security": _HSTS_TARGET}},
    )
    if not resp.get("success"):
        errors = resp.get("errors") or resp
        raise RuntimeError(f"CF HSTS PATCH failed: {errors}")

    new_result: dict[str, Any] = resp.get("result") or {}
    new_value: dict[str, Any] = new_result.get("value") or {}
    new_sts: dict[str, Any] = new_value.get("strict_transport_security") or {}
    print(
        f"HSTS updated: max_age={new_sts.get('max_age')} "
        f"include_subdomains={new_sts.get('include_subdomains')} "
        f"preload={new_sts.get('preload')}"
    )
    return True
