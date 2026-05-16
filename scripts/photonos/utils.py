"""
utils.py — Shared utilities for unified-stack scripts.

Provides: EnvFile, AuthentikClient, ANSI output helpers, container_state().
Import with: from utils import EnvFile, AuthentikClient, red, green, yellow, step, container_state
"""

import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


# ── ANSI output ────────────────────────────────────────────────────────────────

def _c(code: str, msg: str) -> str:
    return f"\033[{code}m{msg}\033[0m"

def red(msg: str)    -> None: print(_c("31", msg), file=sys.stderr)
def green(msg: str)  -> None: print(_c("32", msg))
def yellow(msg: str) -> None: print(_c("33", msg))
def step(msg: str)   -> None: print(_c("36", f"\n==> {msg}"))


# ── .env reader / writer ───────────────────────────────────────────────────────

class EnvFile:
    """Read and selectively update a bash-style .env file."""

    _INLINE_COMMENT = re.compile(r"\s*#.*$")

    def __init__(self, path: Path) -> None:
        self.path = path
        self._text = path.read_text()

    def get(self, key: str) -> str:
        """Return the value for KEY, stripping inline comments and whitespace."""
        for line in self._text.splitlines():
            if line.startswith(f"{key}="):
                val = line[len(key) + 1:]
                return self._INLINE_COMMENT.sub("", val).strip()
        return ""

    def force_set(self, key: str, value: str) -> None:
        """Write KEY=value unconditionally, replacing any existing value or appending."""
        pattern = rf"^({re.escape(key)}=).*$"
        new, count = re.subn(
            pattern,
            lambda m: f"{m.group(1)}{value}",
            self._text,
            flags=re.MULTILINE,
        )
        if count:
            self._text = new
            self.path.write_text(new)
            print(f"  updated {key}")
        else:
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self.path.write_text(self._text)
            print(f"  wrote  {key} (appended)")

    def set_if_blank(self, key: str, value: str) -> None:
        """Write KEY=value only if the key is absent or currently blank."""
        key_prefix = f"{key}="
        for line in self._text.splitlines():
            if line.startswith(key_prefix):
                existing = self._INLINE_COMMENT.sub("", line[len(key_prefix):]).strip()
                if existing:
                    print(f"  skip   {key} (already set)")
                    return
                break

        pattern = rf"^({re.escape(key)}=)\s*(#[^\n]*)?\s*$"
        new, count = re.subn(
            pattern,
            lambda m: f"{m.group(1)}{value}",
            self._text,
            flags=re.MULTILINE,
        )
        if count:
            self._text = new
            self.path.write_text(new)
            print(f"  wrote  {key}")
        else:
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self.path.write_text(self._text)
            print(f"  wrote  {key} (appended)")


# ── Authentik API client ───────────────────────────────────────────────────────

class AuthentikClient:
    """Minimal Authentik REST API client (stdlib only)."""

    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self.base_url}/api/v3/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc

    def get(self, path: str, **params: str) -> dict:
        if params:
            path = f"{path}?{urllib.parse.urlencode(params)}"
        return self._request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body)

    def patch(self, path: str, body: dict) -> dict:
        return self._request("PATCH", path, body)

    def delete(self, path: str) -> None:
        self._request("DELETE", path)


# ── Cloudflare DNS API client ──────────────────────────────────────────────────

class CloudflareClient:
    """Minimal Cloudflare DNS API client (stdlib only)."""

    _BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str) -> None:
        self.token = token

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self._BASE}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc

    def get_zone_id(self, domain: str) -> str:
        """Return the Cloudflare zone ID for the given domain."""
        resp = self._request("GET", f"/zones?name={domain}&status=active")
        if not resp.get("success") or not resp.get("result"):
            raise RuntimeError(f"Zone not found for domain: {domain}")
        return resp["result"][0]["id"]

    def get_dns_records(self, zone_id: str, domain: str) -> dict[str, list[str]]:
        """Return {subdomain: [types]} for all DNS records in the zone."""
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
                    sub = "@"
                elif name.endswith(f".{domain}"):
                    sub = name[: -(len(domain) + 1)]
                else:
                    sub = name
                records.setdefault(sub, []).append(rtype)
            info_page = data.get("result_info", {})
            if page >= info_page.get("total_pages", 1):
                break
            page += 1
        return records

    def get_cname_target(self, zone_id: str, fqdn: str) -> Optional[str]:
        """Return the CNAME content for a record name, or None if not found."""
        data = self._request(
            "GET", f"/zones/{zone_id}/dns_records?type=CNAME&name={fqdn}"
        )
        if data.get("success") and data.get("result"):
            return data["result"][0]["content"]
        return None

    def create_cname(self, zone_id: str, fqdn: str, target: str, proxied: bool = True) -> dict:
        """Create a CNAME record. fqdn = full record name (e.g. 'kafka.secop.dev')."""
        return self._request("POST", f"/zones/{zone_id}/dns_records", {
            "type":    "CNAME",
            "name":    fqdn,
            "content": target,
            "proxied": proxied,
            "ttl":     1,
        })


# ── Docker helpers ─────────────────────────────────────────────────────────────

def container_state(name: str) -> Optional[str]:
    """Return container state string (e.g. 'running'), or None if not found."""
    try:
        r = subprocess.run(
            ["docker", "inspect", name, "--format", "{{.State.Status}}"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
