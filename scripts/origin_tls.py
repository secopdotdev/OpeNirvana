"""Cloudflare zone-level Authenticated Origin Pulls (AOP) provisioning.

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Vendored so the AOP origin-pull tool runs standalone on the deploy host (and in the
sanitized public OpeNirvana mirror) with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001.

Uploads an origin-pull client certificate to a zone and enables per-zone AOP so
Cloudflare's edge presents OUR client cert to the origin (Caddy), which is
configured to require_and_verify it. Defeats the orange-cloud bypass: only our
zone's edge holds the cert.

API contract (api.cloudflare.com/client/v4):
  GET  /zones/{zone_id}/origin_tls_client_auth            -> list certs
  POST /zones/{zone_id}/origin_tls_client_auth            -> upload {certificate, private_key}
  PUT  /zones/{zone_id}/origin_tls_client_auth/settings   -> {enabled: bool}

Token permission: Zone -> SSL and Certificates -> Edit.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

# Sibling-module import (standalone vendored layout — no cloudflare_toolkit package).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _http import api_get, api_post, api_put, resolve_zone_id  # noqa: E402


def _check(resp: dict[str, Any], what: str) -> dict[str, Any]:
    if not resp.get("success", False):
        errs = "; ".join(e.get("message", "?") for e in resp.get("errors", [])) or "unknown error"
        raise RuntimeError(f"Cloudflare AOP {what} failed: {errs}")
    return resp


def _norm_pem(pem: str) -> str:
    """Whitespace-normalized PEM body for identity comparison (stdlib-only)."""
    return "".join(pem.split())


def list_client_certs(token: str, zone_id: str) -> list[dict[str, Any]]:
    resp = _check(api_get(token, f"/zones/{zone_id}/origin_tls_client_auth"), "list")
    return cast(list[dict[str, Any]], resp.get("result") or [])


def upload_client_cert(token: str, zone_id: str, cert_pem: str, key_pem: str) -> str:
    resp = _check(
        api_post(
            token,
            f"/zones/{zone_id}/origin_tls_client_auth",
            {"certificate": cert_pem, "private_key": key_pem},
        ),
        "upload",
    )
    return resp["result"]["id"]


def set_aop_enabled(token: str, zone_id: str, enabled: bool) -> bool:
    resp = _check(
        api_put(token, f"/zones/{zone_id}/origin_tls_client_auth/settings", {"enabled": enabled}),
        "settings",
    )
    return bool(resp["result"]["enabled"])


def ensure_origin_pull(
    token: str,
    fqdn: str,
    cert_pem: str,
    key_pem: str,
    *,
    enable: bool = True,
) -> dict[str, Any]:
    """Idempotently ensure the cert is uploaded to fqdn's zone and AOP is enabled."""
    zone_id = resolve_zone_id(token, fqdn)
    target = _norm_pem(cert_pem)
    existing = next(
        (
            c for c in list_client_certs(token, zone_id)
            if _norm_pem(c.get("certificate", "")) == target
        ),
        None,
    )
    if existing is not None:
        cert_id, uploaded = existing["id"], False
    else:
        cert_id, uploaded = upload_client_cert(token, zone_id, cert_pem, key_pem), True
    enabled = set_aop_enabled(token, zone_id, True) if enable else False
    return {"zone_id": zone_id, "cert_id": cert_id, "uploaded": uploaded, "enabled": enabled}
