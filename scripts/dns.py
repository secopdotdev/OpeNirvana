"""dns.py — Minimal Cloudflare DNS API client (stdlib-only).

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Vendored so the DNS client runs standalone on the deploy host (and in the
sanitized public OpeNirvana mirror) with no private-package dependency — the
standalone-script pattern blessed by toolkit ADR-0001.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareClient:
    """Minimal Cloudflare DNS API client (stdlib-only, no third-party deps)."""

    def __init__(self, token: str) -> None:
        self.token = token

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        url = f"{_BASE}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(  # noqa: S310  # URL is always the hardcoded CF API base
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc

    def get_zone_id(self, domain: str) -> str:
        """Return the Cloudflare zone ID for *domain*."""
        resp = self._request("GET", f"/zones?name={domain}&status=active")
        if not resp.get("success") or not resp.get("result"):
            raise RuntimeError(f"Zone not found for domain: {domain}")
        return resp["result"][0]["id"]

    def get_dns_records(self, zone_id: str, domain: str) -> dict[str, list[str]]:
        """Return ``{subdomain: [record_types]}`` for all DNS records in the zone."""
        records: dict[str, list[str]] = {}
        page = 1
        while True:
            data = self._request(
                "GET", f"/zones/{zone_id}/dns_records?per_page=100&page={page}"
            )
            if not data.get("success"):
                break
            for r in data.get("result", []):
                name: str = r["name"]
                rtype: str = r["type"]
                if name == domain:
                    sub: str = "@"
                elif name.endswith(f".{domain}"):
                    sub = name[: -(len(domain) + 1)]
                else:
                    sub = name
                records.setdefault(sub, []).append(rtype)
            info_page: dict[str, Any] = data.get("result_info") or {}
            if page >= info_page.get("total_pages", 1):
                break
            page += 1
        return records

    def get_cname_target(self, zone_id: str, fqdn: str) -> str | None:
        """Return the CNAME content for *fqdn*, or ``None`` if not found."""
        data = self._request(
            "GET", f"/zones/{zone_id}/dns_records?type=CNAME&name={fqdn}"
        )
        if data.get("success") and data.get("result"):
            return str(data["result"][0]["content"])
        return None

    def create_cname(
        self, zone_id: str, fqdn: str, target: str, proxied: bool = True
    ) -> dict[str, Any]:
        """Create a CNAME record. *fqdn* is the full record name (e.g. ``'svc.example.com'``)."""
        return self._request("POST", f"/zones/{zone_id}/dns_records", {
            "type":    "CNAME",
            "name":    fqdn,
            "content": target,
            "proxied": proxied,
            "ttl":     1,
        })

    def delete_dns_record(self, zone_id: str, record_id: str) -> dict[str, Any]:
        """Delete a DNS record by its Cloudflare record ID."""
        return self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
