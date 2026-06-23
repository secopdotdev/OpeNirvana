"""_http.py — Shared Cloudflare HTTP helpers (stdlib-only, one retry on 429/5xx).

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Vendored so the AOP origin-pull tool runs standalone on the deploy host (and in the
sanitized public OpeNirvana mirror) with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

_CF_API_BASE = "https://api.cloudflare.com/client/v4"

_RETRY_CODES = frozenset({429, 500, 502, 503, 504})


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def api_get(token: str, path: str) -> dict[str, Any]:
    """GET from the CF REST API with one retry on transient errors."""
    url = f"{_CF_API_BASE}{path}"
    for attempt in range(2):
        req = urllib.request.Request(url, headers=_headers(token))  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in _RETRY_CODES:
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")  # pragma: no cover


def api_post(token: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST to the CF REST API with one retry on transient errors."""
    url = f"{_CF_API_BASE}{path}"
    payload = json.dumps(body).encode()
    for attempt in range(2):
        req = urllib.request.Request(  # noqa: S310
            url, data=payload, method="POST", headers=_headers(token)
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in _RETRY_CODES:
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")  # pragma: no cover


def api_patch(token: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    """PATCH to the CF REST API with one retry on transient errors."""
    url = f"{_CF_API_BASE}{path}"
    payload = json.dumps(body).encode()
    for attempt in range(2):
        req = urllib.request.Request(  # noqa: S310
            url, data=payload, method="PATCH", headers=_headers(token)
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in _RETRY_CODES:
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")  # pragma: no cover


def api_put(token: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    """PUT to the CF REST API with one retry on transient errors."""
    url = f"{_CF_API_BASE}{path}"
    payload = json.dumps(body).encode()
    for attempt in range(2):
        req = urllib.request.Request(  # noqa: S310
            url, data=payload, method="PUT", headers=_headers(token)
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in _RETRY_CODES:
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")  # pragma: no cover


def api_delete(token: str, path: str) -> dict[str, Any]:
    """DELETE from the CF REST API (no retry — deletes are not idempotent-safe to retry blindly)."""
    url = f"{_CF_API_BASE}{path}"
    req = urllib.request.Request(  # noqa: S310
        url, method="DELETE", headers=_headers(token)
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read())  # type: ignore[no-any-return]


def api_graphql(token: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    """POST to the CF GraphQL API with one retry on transient errors."""
    url = f"{_CF_API_BASE}/graphql"
    payload = json.dumps({"query": query, "variables": variables}).encode()
    for attempt in range(2):
        req = urllib.request.Request(url, data=payload, headers=_headers(token))  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in _RETRY_CODES:
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")  # pragma: no cover


def resolve_zone_id(token: str, domain: str) -> str:
    """Return the zone ID for *domain*'s apex (e.g. 'sub.example.com' → zone for 'example.com')."""
    apex = ".".join(domain.split(".")[-2:])
    data = api_get(token, f"/zones?name={apex}")
    zones: list[dict[str, Any]] = data.get("result", [])
    if not zones:
        raise ValueError(f"No Cloudflare zone found for {apex!r}")
    return str(zones[0]["id"])
