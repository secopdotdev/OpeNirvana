#!/usr/bin/env python3
"""
undo-entra.py  —  Restore local Authentik logins after Entra ID federation.

Reverses the Authentik-side changes made by setup-entra.py --setup:
  1. Disables the entra-id OAuth2 source (stops new Entra logins)
  2. Removes the access-group policy binding from the authorization flow
  3. Restores the password login stage to the authentication flow

Does NOT delete the App Registration, synced users, or .env credentials.
Runnable any time. No Graph API calls — works even when Entra ID is unavailable.

Usage:
    python3 scripts/undo-entra.py [path/to/.env]
"""

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


def _c(code: str, msg: str) -> str:
    return f"\033[{code}m{msg}\033[0m"

def red(msg: str)    -> None: print(_c("31", msg), file=sys.stderr)
def green(msg: str)  -> None: print(_c("32", msg))
def yellow(msg: str) -> None: print(_c("33", msg))
def step(msg: str)   -> None: print(_c("36", f"\n==> {msg}"))


class EnvFile:
    _INLINE_COMMENT = re.compile(r"\s*#.*$")

    def __init__(self, path: Path) -> None:
        self.path = path
        self._text = path.read_text()

    def get(self, key: str) -> str:
        for line in self._text.splitlines():
            if line.startswith(f"{key}="):
                val = line[len(key) + 1:]
                return self._INLINE_COMMENT.sub("", val).strip()
        return ""

    def force_set(self, key: str, value: str) -> None:
        pattern = rf"^({re.escape(key)}=).*$"
        new, count = re.subn(
            pattern, lambda m: f"{m.group(1)}{value}", self._text, flags=re.MULTILINE,
        )
        if count:
            self._text = new
            self.path.write_text(new)
        else:
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self.path.write_text(self._text)


class AuthentikClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self.base_url}/api/v3/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
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
            path += "?" + urllib.parse.urlencode(params)
        return self._request("GET", path)

    def patch(self, path: str, body: dict) -> dict:
        return self._request("PATCH", path, body)

    def delete(self, path: str) -> None:
        self._request("DELETE", path)


def main() -> int:
    env_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        red(f".env not found: {env_path}")
        return 1

    env = EnvFile(env_path)
    token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN")
    if not token:
        red("AUTHENTIK_BOOTSTRAP_TOKEN not set in .env")
        return 1

    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    if not public_fqdn:
        red("PUBLIC_FQDN not set in .env")
        return 1

    base_url = f"https://{auth_sub}.{public_fqdn}"
    ak = AuthentikClient(base_url, token)

    step(f"Verifying Authentik at {base_url}")
    try:
        ak.get("core/users/", page_size="1")
        green("  Authentik reachable")
    except Exception as exc:
        red(f"Cannot reach Authentik: {exc}")
        return 1

    # Step 1: Disable entra-id source
    step("Step 1 — Disabling entra-id OAuth2 source")
    sources = ak.get("sources/oauth/", slug="entra-id").get("results", [])
    if sources:
        source_pk = sources[0]["pk"]
        ak.patch(f"sources/oauth/{source_pk}/", {"enabled": False})
        green("  entra-id source disabled (config preserved)")
    else:
        yellow("  entra-id source not found — nothing to disable")

    # Step 2: Remove access-group policy binding from authorization flow
    step("Step 2 — Removing access-group policy binding from authorization flow")
    access_group = env.get("ENTRA_ACCESS_GROUP")
    if access_group:
        policy_name = f"entra-access-{access_group}"
        policies = ak.get("policies/expression/", name=policy_name).get("results", [])
        if policies:
            policy_pk = policies[0]["pk"]
            bindings = ak.get("policies/bindings/", policy=policy_pk).get("results", [])
            for binding in bindings:
                ak.delete(f"policies/bindings/{binding['pk']}/")
                green(f"  Removed policy binding (pk={binding['pk']})")
        else:
            yellow(f"  Policy '{policy_name}' not found — nothing to unbind")
    else:
        yellow("  ENTRA_ACCESS_GROUP not set — skipping policy unbind")

    # Step 3: Restore password login stage in authentication flow
    step("Step 3 — Restoring password login stage to authentication flow")
    auth_flows = ak.get("flows/instances/", designation="authentication").get("results", [])
    if auth_flows:
        flow_pk = auth_flows[0]["pk"]
        bindings = ak.get("flows/bindings/", target=flow_pk).get("results", [])
        restored = False
        for binding in bindings:
            stage_pk = binding.get("stage")
            if not stage_pk:
                continue
            try:
                stage = ak.get(f"stages/identification/{stage_pk}/")
                if stage.get("pk") and stage.get("password_stage") is None:
                    pw_stages = ak.get("stages/password/").get("results", [])
                    if pw_stages:
                        ak.patch(f"stages/identification/{stage_pk}/", {
                            "password_stage": pw_stages[0]["pk"],
                        })
                        green(f"  Restored password stage '{pw_stages[0]['name']}' to identification stage")
                    else:
                        yellow("  No password stage found to restore")
                    restored = True
                    break
            except RuntimeError:
                continue
        if not restored:
            yellow("  Identification stage not found or password_stage already set — no change")
    else:
        yellow("  No authentication flow found — skipping")

    # Step 4: Write restoration flag
    env.force_set("ENTRA_LOCAL_LOGIN_RESTORED", "true")
    green("  ENTRA_LOCAL_LOGIN_RESTORED=true written to .env")

    # Step 5: Print break-glass reminder
    admins_resp = ak.get("core/users/", is_superuser="true", is_active="true")
    admin_names = [u["username"] for u in admins_resp.get("results", [])]
    green(f"\nLocal logins restored.")
    green(f"Break-glass admin account(s): {', '.join(admin_names) if admin_names else '(none found!)'}")
    yellow("IMPORTANT: Verify you can log in with a local admin account before closing this terminal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
