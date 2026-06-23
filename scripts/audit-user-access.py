#!/usr/bin/env python3
"""
audit-user-access.py — Audit one Authentik user's access to every stack service.

Authenticates to the Authentik API *as* AUTHENTIK_USER_NAME using that user's
AUTHENTIK_USER_ACCESS_TOKEN to determine which applications they can reach, uses
the admin AUTHENTIK_BOOTSTRAP_TOKEN to enumerate all services and discover the
Authentik/Entra groups gating each one, and — when ENTRA_CLIENT_ID/SECRET/TENANT_ID
are set — cross-checks the user's effective Microsoft Entra group membership.

Usage:
  python3 scripts/audit-user-access.py [--env PATH] [--no-probe] [--no-color] [--no-log]
"""

import argparse
import datetime
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from utils import (
    EnvFile, AuthentikClient, discover_app_access_groups,
    red, green, yellow, step, resolve_admin_token,
)
import utils_nextcloud

_STACK_DIR = Path(__file__).resolve().parent.parent
_LOG_PATH  = _STACK_DIR / "audit-user-access.log"

_USE_COLOR = True
def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s
def _ok(s: str) -> str:   return _c("32", s)
def _bad(s: str) -> str:  return _c("31", s)
def _dim(s: str) -> str:  return _c("90", s)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture the raw 3xx code instead of following it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_opener = urllib.request.build_opener(_NoRedirect())


def _validate_nextcloud_oidc(env: EnvFile) -> tuple[bool, str]:
    """Verify Nextcloud's user_oidc app is configured to point at Authentik.

    Primary check: `docker exec nextcloud occ user_oidc:provider` lists a
    provider whose discoveryEndpoint matches NEXTCLOUD_OIDC_DISCOVERY_URL.

    Secondary (optional) check: if NEXTCLOUD_API_USERNAME + NEXTCLOUD_API_KEY
    are set, also probe the OCS API for reachability. Missing API creds are
    not an error — they just skip the OCS round-trip.

    Returns (ok, detail). detail is the failure reason when ok is False, or
    the matched provider identifier when ok is True.
    """
    expected_disco = env.get("NEXTCLOUD_OIDC_DISCOVERY_URL") or ""
    if not expected_disco:
        return False, "NEXTCLOUD_OIDC_DISCOVERY_URL not set in .env"

    # Optional: OCS API reachability probe. Skipped silently if API creds absent.
    if env.get("NEXTCLOUD_API_USERNAME") and env.get("NEXTCLOUD_API_KEY"):
        try:
            utils_nextcloud.ocs_get(env, "/ocs/v2.php/cloud/capabilities")
        except RuntimeError as exc:
            return False, f"OCS API unreachable: {exc}"

    # Primary: query user_oidc providers via occ (docker exec — no API creds needed).
    try:
        providers = utils_nextcloud.user_oidc_list_providers()
    except Exception as exc:
        return False, f"user_oidc query failed: {exc}"
    if not providers:
        return False, "user_oidc has no providers registered (or app not installed)"

    matches = [p for p in providers if p.get("discoveryEndpoint") == expected_disco]
    if not matches:
        seen = ", ".join(p.get("discoveryEndpoint", "?") for p in providers) or "<none>"
        return False, f"no user_oidc provider matches NEXTCLOUD_OIDC_DISCOVERY_URL (seen: {seen})"
    return True, matches[0].get("identifier") or "Authentik"


def _probe(url: str, token: str, timeout: int = 10) -> int:
    """GET url with the user's bearer token; return HTTP status (0 on network error)."""
    req = urllib.request.Request(
        url, method="GET", headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


class GraphClient:
    """Minimal Microsoft Graph client — app-only client-credentials flow, stdlib only."""

    def __init__(self, token: str) -> None:
        self._token = token

    @classmethod
    def from_client_credentials(cls, tenant_id: str, client_id: str,
                                client_secret: str) -> "GraphClient":
        data = urllib.parse.urlencode({
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         "https://graph.microsoft.com/.default",
            "grant_type":    "client_credentials",
        }).encode()
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                tok = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"Entra token request failed (HTTP {exc.code}): {detail}") from exc
        return cls(tok["access_token"])

    def _get_url(self, url: str) -> dict:
        req = urllib.request.Request(
            url, method="GET",
            headers={"Authorization": f"Bearer {self._token}",
                     "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} GET {url}: {detail}") from exc
        return json.loads(raw) if raw else {}

    def get(self, path: str, **params: str) -> dict:
        url = f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._get_url(url)

    def list_all(self, path: str, **params: str) -> list[dict]:
        """GET following @odata.nextLink; return the concatenated `value` arrays."""
        out: list[dict] = []
        url = f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        while url:
            page = self._get_url(url)
            out += page.get("value", [])
            url = page.get("@odata.nextLink", "")
        return out


def _render(rows: list[dict], username: str, email: str) -> None:
    cols = [
        ("SERVICE",           "service", 14),
        ("URL",               "url",     28),
        ("MODE",              "mode",    12),
        ("ACCESS",            "access",   9),
        ("HTTP",              "http",     5),
        ("ENTRA",             "entra",   10),
        ("GROUPS / REQUIRES", "groups",  40),
    ]
    bar = "─" * (sum(w + 3 for _, _, w in cols) + 1)
    print()
    print(f"User access audit — {username}" + (f" ({email})" if email else ""))
    print(bar)
    print("│ " + " │ ".join(h.ljust(w) for h, _, w in cols) + " │")
    print(bar)
    access_color = {"GRANTED": _ok, "DENIED": _bad, "OPEN": _dim}
    entra_color  = {"MEMBER": _ok, "NON-MEMBER": _bad}
    for r in rows:
        cells = []
        for h, k, w in cols:
            disp = str(r.get(k, ""))[:w].ljust(w)
            if k == "access":
                disp = access_color.get(r["access"], str)(disp)
            elif k == "entra":
                disp = entra_color.get(r.get("entra", ""), _dim)(disp)
            cells.append(disp)
        print("│ " + " │ ".join(cells) + " │")
    print(bar)
    g = sum(1 for r in rows if r["access"] == "GRANTED")
    d = sum(1 for r in rows if r["access"] == "DENIED")
    o = sum(1 for r in rows if r["access"] == "OPEN")
    print(f"{_ok(f'{g} granted')} · {_bad(f'{d} denied')} · {_dim(f'{o} open')}")


def _write_log(rows: list[dict], username: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    g = sum(1 for r in rows if r["access"] == "GRANTED")
    d = sum(1 for r in rows if r["access"] == "DENIED")
    o = sum(1 for r in rows if r["access"] == "OPEN")
    with _LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] audit user={username} granted={g} denied={d} open={o}\n")
        for r in rows:
            f.write(f"    {r['access']:<8} entra={r.get('entra', 'n/a'):<11} "
                    f"{r['service']:<16} {r['groups']}\n")
    green(f"  appended audit record to {_LOG_PATH}")


def _entra_member_groups(env: EnvFile, user_detail: dict, email: str) -> tuple:
    """Return (groups_set_or_None, skip_reason).

    groups_set is the audited user's effective (transitive) Entra group display
    names. None means the Entra check was skipped — skip_reason explains why.
    """
    tenant = env.get("ENTRA_TENANT_ID")
    cid    = env.get("ENTRA_READ_CLIENT_ID") or env.get("ENTRA_WRITE_CLIENT_ID")
    secret = env.get("ENTRA_READ_CLIENT_SECRET") or env.get("ENTRA_WRITE_CLIENT_SECRET")
    if not (tenant and cid and secret):
        return None, "ENTRA_READ_CLIENT_ID / ENTRA_READ_CLIENT_SECRET / ENTRA_TENANT_ID not all set"
    step("Cross-checking Entra group membership")
    try:
        gc = GraphClient.from_client_credentials(tenant, cid, secret)
        oid = (user_detail.get("attributes") or {}).get("entra_id")
        if not oid and email:
            hits = gc.get("users", **{"$filter": f"mail eq '{email}'",
                                      "$select": "id"}).get("value", [])
            oid = hits[0]["id"] if hits else None
        if not oid:
            return None, "audited user has no entra_id attribute and no matching Entra user"
        groups = gc.list_all(
            f"users/{oid}/transitiveMemberOf/microsoft.graph.group",
            **{"$select": "displayName", "$top": "999"})
        names = {g["displayName"] for g in groups if g.get("displayName")}
        green(f"  user is in {len(names)} Entra group(s)")
        return names, ""
    except (RuntimeError, KeyError, urllib.error.URLError) as exc:
        return None, f"Entra query failed: {exc}"


def main() -> int:
    global _USE_COLOR
    parser = argparse.ArgumentParser(
        description="Audit one Authentik user's access to every stack service.")
    parser.add_argument("--env", default=str(_STACK_DIR / ".env"), metavar="PATH",
                        help="Live .env file (default: <unified-stack>/.env)")
    parser.add_argument("--no-probe", action="store_true", help="Skip live HTTP probes")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colour")
    parser.add_argument("--no-log", action="store_true", help="Do not append to audit log")
    args = parser.parse_args()
    _USE_COLOR = not args.no_color and sys.stdout.isatty()

    env_path = Path(args.env)
    if not env_path.exists():
        red(f".env not found: {env_path}")
        return 1
    env = EnvFile(env_path)

    username    = env.get("AUTHENTIK_USER_NAME")
    user_token  = env.get("AUTHENTIK_USER_ACCESS_TOKEN")
    admin_token = resolve_admin_token(env)
    auth_sub    = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    for label, val in [("AUTHENTIK_USER_NAME", username),
                        ("AUTHENTIK_USER_ACCESS_TOKEN", user_token),
                        ("AUTHENTIK_BOOTSTRAP_TOKEN", admin_token),
                        ("PUBLIC_FQDN", public_fqdn)]:
        if not val:
            red(f"{label} not set in .env")
            return 1

    base_url = f"https://{auth_sub}.{public_fqdn}"
    user_ak  = AuthentikClient(base_url, user_token)
    admin_ak = AuthentikClient(base_url, admin_token)

    # 1. Verify the access token's identity matches AUTHENTIK_USER_NAME.
    step(f"Verifying access token for {username!r}")
    try:
        me = user_ak.get("core/users/me/")
    except Exception as exc:
        red(f"User access token rejected by Authentik: {exc}")
        return 1
    me_user = me.get("user", me)          # /core/users/me/ wraps the user in {"user": {...}}
    if me_user.get("username") != username:
        red(f"Token belongs to {me_user.get('username')!r}, not "
            f"AUTHENTIK_USER_NAME={username!r}")
        return 1
    user_pk = str(me_user.get("pk"))
    email   = me_user.get("email") or ""
    green(f"  token OK — {username} ({email or 'no-email'})")

    # 2. Admin: enumerate every application (minus the forward-auth carrier app).
    step("Enumerating applications (admin token)")
    apps: list[dict] = []
    page = 1
    while True:
        resp = admin_ak.get("core/applications/", page=str(page),
                            page_size="100", superuser_full_list="true")
        apps += [a for a in resp.get("results", []) if a["slug"] != "forward-auth"]
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    apps.sort(key=lambda a: a["slug"])
    green(f"  {len(apps)} applications")

    # 3. Map provider pk → auth mode (proxy = forward-auth, oauth2 = native-OIDC).
    provider_mode: dict[int, str] = {}
    page = 1
    while True:
        resp = admin_ak.get("providers/all/", page=str(page), page_size="100")
        for p in resp.get("results", []):
            comp = p.get("component", "")
            if "proxy" in comp:
                provider_mode[p["pk"]] = "forward-auth"
            elif "oauth2" in comp:
                provider_mode[p["pk"]] = "native-OIDC"
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    # 4. User: applications this user can actually reach (Authentik policy engine).
    step(f"Querying accessible applications as {username}")
    granted: set[str] = set()
    page = 1
    while True:
        resp = user_ak.get("core/applications/", page=str(page), page_size="100")
        granted |= {a["slug"] for a in resp.get("results", [])}
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    green(f"  {len(granted)} accessible")

    # 5. Admin: gating groups per app + the audited user's own group memberships.
    step("Resolving access-control groups (admin token)")
    required = discover_app_access_groups(admin_ak, apps)
    user_detail = admin_ak.get(f"core/users/{user_pk}/")
    user_groups = {g["name"] for g in user_detail.get("groups_obj", [])}

    # 6. Optional: cross-check the user's effective Entra group membership.
    entra_groups, entra_skip = _entra_member_groups(env, user_detail, email)
    if entra_skip:
        yellow(f"  Entra check skipped — {entra_skip}")

    # 7. Entra-side group-name resolution: Authentik "entra-<slug>" ⇄ Entra
    #    "authentik-<slug>"; global/access groups share one name across systems.
    entra_prefix = env.get("ENTRA_GROUP_PREFIX") or "authentik"
    ak_prefix    = env.get("AUTHENTIK_GROUP_PREFIX") or "entra"
    def entra_name(ak_group: str) -> str:
        if ak_group.startswith(f"{ak_prefix}-"):
            return f"{entra_prefix}-{ak_group[len(ak_prefix) + 1:]}"
        return ak_group

    # 8. Build rows.
    rows: list[dict] = []
    for a in apps:
        reqd = required.get(str(a["pk"]), [])
        if not reqd:
            verdict = "OPEN"
        elif a["slug"] in granted:
            verdict = "GRANTED"
        else:
            verdict = "DENIED"

        if entra_groups is None:
            entra_cell = "n/a"
        elif not reqd:
            entra_cell = "—"
        else:
            wanted = {entra_name(g) for g in reqd}
            entra_cell = "MEMBER" if (entra_groups & wanted) else "NON-MEMBER"

        url = a.get("meta_launch_url") or ""
        http = str(_probe(url, user_token)) if url and not args.no_probe else ""
        if verdict == "OPEN":
            groups_cell = "(no policy — any authenticated user)"
        elif verdict == "GRANTED":
            via = sorted(user_groups & set(reqd))
            groups_cell = "via " + ", ".join(via) if via else "via superuser"
        else:
            groups_cell = ", ".join(
                f"{g} ⇄ {entra_name(g)}" if entra_name(g) != g else g
                for g in sorted(reqd)
            )
        _prov_pk = a.get("provider")
        rows.append({
            "service": a["slug"], "url": url,
            "mode":    provider_mode.get(_prov_pk, "unknown") if isinstance(_prov_pk, int) else "unknown",
            "access":  verdict, "http": http, "entra": entra_cell,
            "groups":  groups_cell,
        })

    # Nextcloud-specific Authentik<->Nextcloud OIDC validation.
    nc_sub = env.get("NEXTCLOUD_SUBDOMAIN") or "cloud"
    for r in rows:
        if r["service"] != nc_sub:
            continue
        ok, detail = _validate_nextcloud_oidc(env)
        if ok:
            r["mode"] = "native-OIDC ✓"
        else:
            r["mode"]   = _bad("OIDC BROKEN")
            r["groups"] = _bad(detail)
        break

    _render(rows, username, email)
    if not args.no_log:
        _write_log(rows, username)
    return 0


if __name__ == "__main__":
    sys.exit(main())
