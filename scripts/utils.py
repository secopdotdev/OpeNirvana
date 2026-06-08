"""
utils.py — Shared utilities for unified-stack scripts.

Provides: EnvFile, AuthentikClient, ANSI output helpers, container_state().
Import with: from utils import EnvFile, AuthentikClient, red, green, yellow, step, container_state
"""

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
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
        self._text = path.read_text(encoding="utf-8")

    def get(self, key: str) -> str:
        """Return the value for KEY, stripping inline comments and whitespace.

        Single- or double-quoted values (written by set_if_blank/force_set when the
        value contains shell-special chars such as '#') are decoded via shlex.split
        so the quoting is removed and the raw value is returned without the comment
        regex ever touching the interior of the string.
        """
        for line in self._text.splitlines():
            if line.startswith(f"{key}="):
                val = line[len(key) + 1:]
                stripped = val.strip()
                if stripped[:1] in ("'", '"'):
                    # Quoted value — shlex.split is the correct inverse of shlex.quote
                    # and handles all escape forms including embedded single-quotes.
                    parts = shlex.split(stripped)
                    return parts[0] if parts else ""
                return self._INLINE_COMMENT.sub("", val).strip()
        return ""

    def _atomic_write(self, text: str) -> None:
        d = self.path.parent
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".env.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)     # atomic swap
        except BaseException:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
            raise

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
            self._atomic_write(new)
            print(f"  updated {key}")
        else:
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self._atomic_write(self._text)
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
            self._atomic_write(new)
            print(f"  wrote  {key}")
        else:
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self._atomic_write(self._text)
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
            with urllib.request.urlopen(req, timeout=60) as resp:
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

    def put(self, path: str, body: dict) -> dict:
        return self._request("PUT", path, body)

    def delete(self, path: str) -> None:
        self._request("DELETE", path)


# ── Authentik access-policy discovery ──────────────────────────────────────────

def discover_app_access_groups(ak: "AuthentikClient", apps: list[dict]) -> dict[str, list[str]]:
    """Return {str(app pk): [group names that grant access]} for the given apps.

    Uses three bulk-paginated calls (all groups, all bindings, expression policies
    for matched bindings only) then attributes in Python. Avoids the N+1
    per-group query that hit Authentik's slow bindings endpoint, and sidesteps
    the GenericFK bug (target= filter omits GROUP-type bindings) by fetching
    all bindings without a filter.
    """
    app_pks = {str(a["pk"]) for a in apps}
    required: dict[str, list[str]] = {str(a["pk"]): [] for a in apps}

    # 1. Fetch all groups once (pk → name lookup table).
    groups_by_pk: dict[str, str] = {}
    page = 1
    while True:
        resp = ak.get("core/groups/", page=str(page), page_size="100")
        for g in resp.get("results", []):
            groups_by_pk[str(g["pk"])] = g["name"]
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    # 2. Fetch ALL policy bindings in bulk (avoids one request per group).
    all_bindings: list[dict] = []
    page = 1
    while True:
        resp = ak.get("policies/bindings/", page=str(page), page_size="100")
        all_bindings.extend(resp.get("results", []))
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    # 3. Fetch expression policies only for policy-type bindings targeting our apps.
    expr_pks = {
        str(b["policy"])
        for b in all_bindings
        if str(b.get("target", "")) in app_pks
        and b.get("policy")
        and not b.get("group")
    }
    policy_group_map: dict[str, str] = {}
    for pk in expr_pks:
        try:
            pol = ak.get(f"policies/expression/{pk}/")
            m = re.search(r'ak_groups\.filter\(name="([^"]+)"\)', pol.get("expression", ""))
            if m:
                policy_group_map[pk] = m.group(1)
        except RuntimeError:
            pass

    # 4. Attribute bindings to apps (local, no additional HTTP calls).
    for b in all_bindings:
        tgt = str(b.get("target", ""))
        if tgt not in app_pks:
            continue
        group_pk = str(b.get("group") or "")
        policy_pk = str(b.get("policy") or "")
        if group_pk:
            name = groups_by_pk.get(group_pk)
            if name and name not in required[tgt]:
                required[tgt].append(name)
        elif policy_pk and policy_pk in policy_group_map:
            name = policy_group_map[policy_pk]
            if name not in required[tgt]:
                required[tgt].append(name)

    return required


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
        """Create a CNAME record. fqdn = full record name (e.g. 'example.com')."""
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
