#!/usr/bin/env python3
"""utils_authentik_oidc - Authentik OAuth2 / native-OIDC provider provisioning.

Behavior preserved from setup-oidc.py (deleted in Task 8). The previous
top-level main() is now run(args, env, sync_only); argparse is owned by
set-auth.py.

Provisions Authentik OAuth2/OIDC providers + applications for Nextcloud,
Tandoor, AFFiNE, Jellyfin, Immich, Vikunja and writes the generated
credentials back into .env. Creates oidc-setup-output.txt with any
remaining manual steps.
"""


import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from utils import EnvFile, AuthentikClient, red, green, yellow, step, container_state


def get_token_from_container() -> Optional[str]:
    """Pull a valid API token from the live authentik-server container.

    Search order:
      1. identifier starts with 'ak-bootstrap'  (gen-secrets.sh installs)
      2. Any non-expiring, non-outpost token     (manually created API tokens)
    """
    script = (
        "from authentik.core.models import Token; "
        "t = (Token.objects.filter(identifier__startswith='ak-bootstrap').first()"
        " or Token.objects.filter(expiring=False)"
        ".exclude(identifier__startswith='ak-outpost')"
        ".order_by('pk').first()); "
        "print(t.key if t else '', end='')"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", "authentik-server", "ak", "shell", "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_container_env_var(container: str, var: str) -> Optional[str]:
    """Read a single env var from a running container via docker inspect."""
    try:
        result = subprocess.run(
            ["docker", "inspect", container,
             "--format", f"{{{{range .Config.Env}}}}{{{{println .}}}}{{{{end}}}}"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.startswith(f"{var}="):
                return line[len(var) + 1:]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def restart_service(env_path: Path, svc: str) -> None:
    try:
        subprocess.run(
            ["docker", "compose", "--env-file", str(env_path),
             "up", "-d", "--no-deps", "--force-recreate", svc],
            cwd=str(env_path.parent),
            check=True, timeout=120,
        )
        green(f"  restarted {svc}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        yellow(f"  {svc} restart failed — restart manually")


# ── Application pk lookup ──────────────────────────────────────────────────────

def _get_app_pk(ak: AuthentikClient, slug: str) -> Optional[str]:
    """Return the Authentik application pk for the given slug, or None if absent."""
    apps = ak.get("core/applications/", slug=slug).get("results", [])
    return apps[0]["pk"] if apps else None


# ── Microsoft Graph API client ─────────────────────────────────────────────────

class GraphClient:
    """Stdlib-only Microsoft Graph API client using client-credentials flow."""

    _GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    _TOKEN_URL  = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id     = tenant_id
        self._client_id     = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None

    def _acquire_token(self) -> str:
        url  = self._TOKEN_URL.format(tenant_id=self._tenant_id)
        body = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     self._client_id,
            "client_secret": self._client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }).encode()
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, data=body, method="POST"), timeout=20
            ) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"Graph token HTTP {exc.code}: {detail}") from exc
        if "access_token" not in data:
            raise RuntimeError(
                f"Graph token error: {data.get('error_description', data)}"
            )
        return data["access_token"]

    def _auth_headers(self) -> dict:
        if self._token is None:
            self._token = self._acquire_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
        }

    def _request(self, method: str, url: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(2):
            req = urllib.request.Request(url, data=data, method=method,
                                         headers=self._auth_headers())
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt == 0:
                    try:
                        retry_after = int(exc.headers.get("Retry-After", "10"))
                    except ValueError:
                        retry_after = 10
                    time.sleep(retry_after)
                    continue
                detail = exc.read().decode(errors="replace")
                raise RuntimeError(
                    f"Graph HTTP {exc.code} {method} {url}: {detail}"
                ) from exc
        raise RuntimeError(f"Graph HTTP {method} {url}: max retries exceeded")

    def get(self, path: str, **params: str) -> dict:
        url = f"{self._GRAPH_BASE}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._request("GET", url)

    def get_url(self, url: str) -> dict:
        """Call a full URL directly (used for @odata.nextLink pagination)."""
        return self._request("GET", url)

    def post(self, path: str, body: dict) -> dict:
        url = f"{self._GRAPH_BASE}/{path.lstrip('/')}"
        return self._request("POST", url, body)


def _load_graph_client(env: EnvFile) -> Optional[GraphClient]:
    """Return a GraphClient using ENTRA_WRITE_CLIENT_* credentials, else warn and return None."""
    tenant_id     = env.get("ENTRA_TENANT_ID")
    client_id     = env.get("ENTRA_WRITE_CLIENT_ID")
    client_secret = env.get("ENTRA_WRITE_CLIENT_SECRET")
    if not all([tenant_id, client_id, client_secret]):
        yellow(
            "ENTRA_TENANT_ID / ENTRA_WRITE_CLIENT_ID / ENTRA_WRITE_CLIENT_SECRET "
            "not set — skipping Entra group provisioning"
        )
        return None
    return GraphClient(tenant_id, client_id, client_secret)


# ── Entra + Authentik group lifecycle ─────────────────────────────────────────

# Maps Docker container name → Authentik application slug for the six OIDC services.
# Used to look up the correct app pk when binding the Authentik group as an access policy.
_OIDC_CONTAINER_SLUGS: dict[str, str] = {
    "nextcloud":     "nextcloud",
    "tandoor":       "tandoor",
    "affine":        "affine",
    "jellyfin":      "jellyfin",
    "immich-server": "immich",
    "vikunja":       "vikunja",
}


def _discover_running_services() -> list[str]:
    """Return the names of all currently-running Docker containers."""
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            yellow(f"  docker ps failed (exit {r.returncode}) — skipping group discovery")
            return []
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _ensure_entra_group(gc: GraphClient, name: str) -> str:
    """Find or create an Entra security group by displayName. Returns group ID."""
    existing = gc.get(
        "groups",
        **{"$filter": f"displayName eq '{name}'", "$select": "id,displayName"},
    ).get("value", [])
    if existing:
        return existing[0]["id"]
    group = gc.post("groups", {
        "displayName":     name,
        "mailNickname":    name,
        "securityEnabled": True,
        "mailEnabled":     False,
        "groupTypes":      [],
    })
    green(f"  created Entra group: {name}")
    return group["id"]


def _ensure_authentik_group(ak: AuthentikClient, name: str) -> str:
    """Find or create an Authentik group by name. Returns group pk."""
    existing = ak.get("core/groups/", name=name).get("results", [])
    if existing:
        return existing[0]["pk"]
    group = ak.post("core/groups/", {"name": name})
    green(f"  created Authentik group: {name}")
    return group["pk"]


def _ensure_policy_binding(ak: AuthentikClient, app_pk: str, group_pk: str) -> None:
    """Bind an Authentik group to an application as an access policy (idempotent)."""
    existing = ak.get("policies/bindings/", target=app_pk).get("results", [])
    if any(b.get("group") == group_pk for b in existing):
        return
    ak.post("policies/bindings/", {
        "target":  app_pk,
        "group":   group_pk,
        "enabled": True,
        "order":   0,
    })
    green(f"  bound group {group_pk} → app {app_pk}")


def _sync_group_membership(
    gc: GraphClient,
    ak: AuthentikClient,
    entra_group_id: str,
    authentik_group_pk: str,
) -> None:
    """Sync all Entra group members to the matching Authentik group."""
    # Collect all Entra group members, paging through @odata.nextLink.
    members: list[dict] = []
    page = gc.get(
        f"groups/{entra_group_id}/members",
        **{"$select": "id,displayName,mail,userPrincipalName"},
    )
    while True:
        members.extend(page.get("value", []))
        next_link = page.get("@odata.nextLink")
        if not next_link:
            break
        page = gc.get_url(next_link)

    # Drop nested service-principal / group objects; keep only real users.
    members = [m for m in members if m.get("@odata.type") == "#microsoft.graph.user"]

    # Current Authentik group member PKs.
    group_data = ak.get(f"core/groups/{authentik_group_pk}/")
    current_pks = {str(pk) for pk in group_data.get("users", [])}

    for member in members:
        mail = (member.get("mail") or "").strip()
        if not mail:
            yellow(f"  SKIPPED (no email): {member.get('displayName', '?')}")
            continue

        results = ak.get("core/users/", email=mail).get("results", [])
        if results:
            user_pk = results[0]["pk"]
            if str(user_pk) in current_pks:
                green(f"  ALREADY MEMBER: {mail}")
                continue
            ak.post(f"core/groups/{authentik_group_pk}/add_user/", {"pk": user_pk})
            green(f"  ADDED: {mail}")
        else:
            new_user = ak.post("core/users/", {
                "username":  member.get("userPrincipalName") or mail,
                "name":      member.get("displayName") or mail,
                "email":     mail,
                "type":      "external",
                "is_active": True,
            })
            ak.post(
                f"core/groups/{authentik_group_pk}/add_user/", {"pk": new_user["pk"]}
            )
            green(f"  CREATED+ADDED: {mail}")


# ── Preflight API key check ────────────────────────────────────────────────────

def check_api_keys(env: EnvFile) -> bool:
    """
    Verify all API keys required for auto-config are set.
    Returns True to proceed, False to abort.
    Skips the interactive prompt entirely if no keys are missing.
    """
    missing = []
    if not env.get("JELLYFIN_API_KEY"):
        missing.append((
            "JELLYFIN_API_KEY",
            "Jellyfin SSO plugin auto-config",
            "Jellyfin → Dashboard → API Keys → New Key",
        ))
    if not env.get("IMMICH_API_KEY"):
        missing.append((
            "IMMICH_API_KEY",
            "Immich OAuth auto-config",
            "Immich → Account Settings → API Keys → New Key",
        ))

    if not missing:
        return True

    yellow("\nWARNING: The following API keys are not set in .env:")
    for key, purpose, location in missing:
        yellow(f"  {key}  ({purpose})")
        yellow(f"    How to get it: {location}")
    yellow("\nAuto-config will be skipped for the affected services.")
    yellow("Set the keys in .env and re-run this script at any time.\n")
    if not sys.stdin.isatty():
        yellow("Non-interactive mode — proceeding without missing keys.")
        return True
    try:
        answer = input("Proceed without the missing keys? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    return answer in ("y", "yes")


# ── Provider + application factory ────────────────────────────────────────────

def provision_service(
    ak: AuthentikClient,
    env: EnvFile,
    *,
    slug: str,
    name: str,
    redirect_uris: list[dict],
    auth_flow_pk: str,
    invalidation_flow_pk: str,
    signing_key_pk: str,
    property_mappings: list[str],
    id_var: str,
    secret_var: str,
) -> tuple[str, str, Optional[str]]:
    """
    Idempotently create an Authentik OAuth2/OIDC provider + application.
    Always syncs redirect_uris even when credentials are already in .env,
    so subdomain renames self-heal without a full teardown.
    Returns (client_id, client_secret, app_pk).
    """
    # Check whether the provider already exists in Authentik regardless of
    # whether credentials are in .env — so we can always sync redirect_uris.
    # A subdomain rename leaves stale URIs in Authentik and causes login
    # failures even when CLIENT_ID/.env look correct.
    app_pk: Optional[str] = None
    existing = ak.get("providers/oauth2/", name=name).get("results", [])

    existing_id = env.get(id_var)
    if existing_id and not existing:
        # Credentials in .env but provider missing from Authentik — unusual;
        # warn and return so the caller can surface it rather than silently
        # creating a duplicate with a different client_id.
        yellow(f"{name}: {id_var} set in .env but provider not found in Authentik — skipping")
        return existing_id, env.get(secret_var), _get_app_pk(ak, slug)

    if existing:
        provider      = existing[0]
        pk            = provider["pk"]
        client_id     = provider["client_id"]
        client_secret = provider["client_secret"]
        app_pk        = _get_app_pk(ak, slug)
        if existing_id:
            yellow(f"{name}: {id_var} already set — skipping creation")
        else:
            green(f"  {name}: provider already exists (pk={pk}) — reusing credentials")
        # Always sync redirect_uris so subdomain changes take effect without
        # a full teardown. Authentik ignores PATCH fields not in the body.
        current_uris = [u["url"] for u in provider.get("redirect_uris", [])]
        wanted_uris  = [u["url"] for u in redirect_uris]
        if sorted(current_uris) != sorted(wanted_uris):
            ak.patch(f"providers/oauth2/{pk}/", {"redirect_uris": redirect_uris})
            green(f"  {name}: updated redirect_uris → {wanted_uris}")
        if existing_id:
            return existing_id, env.get(secret_var), app_pk
    else:
        step(f"{name}: creating OAuth2/OIDC provider")
        provider = ak.post("providers/oauth2/", {
            "name": name,
            "authorization_flow": auth_flow_pk,
            "invalidation_flow": invalidation_flow_pk,
            "client_type": "confidential",
            "redirect_uris": redirect_uris,
            "signing_key": signing_key_pk,
            "property_mappings": property_mappings,
            "sub_mode": "hashed_user_id",
            "include_claims_in_id_token": True,
        })
        pk            = provider["pk"]
        client_id     = provider["client_id"]
        client_secret = provider["client_secret"]
        green(f"  provider pk={pk}  client_id={client_id}")

        step(f"{name}: creating application (slug={slug})")
        try:
            app_result = ak.post("core/applications/", {"name": name, "slug": slug, "provider": pk})
            app_pk = app_result.get("pk")
            green("  application created")
        except RuntimeError as exc:
            if "already exists" in str(exc):
                green("  application already exists — skipping")
                app_pk = _get_app_pk(ak, slug)
            else:
                raise

    env.set_if_blank(id_var,     client_id)
    env.set_if_blank(secret_var, client_secret)
    return client_id, client_secret, app_pk


# ── OIDC scope mapping guard ──────────────────────────────────────────────────

def ensure_email_verified_claim(ak: AuthentikClient, email_scope_pk: str) -> None:
    """Ensure the OIDC 'email' scope mapping asserts email_verified: True.

    Some OIDC clients (notably AFFiNE) reject the entire OAuth response when the
    email_verified claim is false. Authentik's default email scope asserts True;
    this corrects the mapping in place if it has drifted to False. Idempotent —
    a no-op once the expression is correct.
    """
    mapping = ak.get(f"propertymappings/provider/scope/{email_scope_pk}/")
    expr = mapping.get("expression", "")
    if not re.search(r"""["']email_verified["']""", expr):
        yellow("  email scope: no email_verified claim found — leaving expression as-is")
        return
    fixed = re.sub(r"""(["']email_verified["']\s*:\s*)False\b""", r"\1True", expr)
    if fixed != expr:
        ak.patch(f"propertymappings/provider/scope/{email_scope_pk}/", {"expression": fixed})
        green("  email scope: corrected email_verified False -> True")
    else:
        green("  email scope: email_verified OK")


# ── Jellyfin SSO plugin configurator ──────────────────────────────────────────

def configure_jellyfin_sso(
    jellyfin_url: str,
    api_key: str,
    provider_name: str,
    client_id: str,
    client_secret: str,
    discovery_url: str,
) -> bool:
    """
    Configure OIDC in the Jellyfin SSO plugin via the standard Jellyfin
    plugin configuration API (GET+POST /Plugins/{id}/Configuration).

    Compatible with jellyfin-plugin-sso v4+ (github.com/9p4/jellyfin-plugin-sso).
    The plugin must be installed and Jellyfin restarted at least once after
    installation before this function is called.

    Returns True on success, False on failure (prints a warning — never raises).
    """
    base = jellyfin_url.rstrip("/")
    headers = {
        "X-MediaBrowser-Token": api_key,
        "Content-Type":         "application/json",
        "Accept":               "application/json",
    }

    # Discover the SSO plugin ID dynamically so we're not hardcoding a GUID.
    try:
        req = urllib.request.Request(f"{base}/Plugins", headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            plugins = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        yellow(f"  Could not list Jellyfin plugins (HTTP {exc.code}) — check JELLYFIN_API_KEY")
        return False
    except OSError as exc:
        yellow(f"  Jellyfin unreachable: {exc}")
        return False

    plugin_id = next(
        (p["Id"] for p in plugins if "sso" in p.get("Name", "").lower()),
        None,
    )
    if not plugin_id:
        yellow("  Jellyfin SSO plugin not found — install it:")
        yellow("  Jellyfin admin → Plugins → Catalog → SSO Authentication → Install, then restart Jellyfin")
        return False

    plugin_status = next(
        (p.get("Status", "") for p in plugins if p["Id"] == plugin_id), ""
    )
    if plugin_status == "Restart":
        yellow("  Jellyfin SSO plugin installed but Jellyfin needs a restart to activate it")
        yellow("  Run: docker restart jellyfin   then re-run setup-oidc.py")
        return False

    cfg_url = f"{base}/Plugins/{plugin_id}/Configuration"

    # Fetch current config so we don't wipe other providers.
    try:
        req = urllib.request.Request(cfg_url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            config = json.loads(resp.read())
    except (urllib.error.HTTPError, OSError, json.JSONDecodeError) as exc:
        yellow(f"  Could not fetch Jellyfin SSO config: {exc}")
        return False

    # Merge the provider into OidConfigs (v4 field names from PluginConfiguration.cs).
    config.setdefault("OidConfigs", {})[provider_name] = {
        "OidEndpoint":               discovery_url,
        "OidClientId":               client_id,
        "OidSecret":                 client_secret,
        "OidScopes":                 ["openid", "profile", "email"],
        "Enabled":                   True,
        "EnableAuthorization":       False,
        "EnableAllFolders":          False,
        "EnabledFolders":            [],
        "AdminRoles":                [],
        "Roles":                     [],
        "EnableFolderRoles":         False,
        "EnableLiveTvRoles":         False,
        "EnableLiveTv":              False,
        "EnableLiveTvManagement":    False,
        "LiveTvRoles":               [],
        "LiveTvManagementRoles":     [],
        "FolderRoleMapping":         [],
        "RoleClaim":                 "",
        "SchemeOverride":            "",
        "DoNotValidateEndpoints":    False,
        "DoNotValidateIssuerName":   False,
        "DisableHttps":              False,
        "DisablePushedAuthorization": False,
    }

    post_req = urllib.request.Request(
        cfg_url,
        data=json.dumps(config).encode(),
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(post_req, timeout=20) as resp:
            resp.read()
        green(f"  Jellyfin SSO plugin configured (provider={provider_name})")
        return True
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        yellow(f"  Jellyfin SSO config failed (HTTP {exc.code}): {detail[:120]}")
        return False
    except OSError as exc:
        yellow(f"  Jellyfin unreachable: {exc}")
        yellow("  Run setup-oidc.py again once Jellyfin is up")
        return False


# ── Immich OAuth configurator ─────────────────────────────────────────────────

def _immich_exec_api(
    method: str, path: str, api_key: str, body: Optional[dict] = None
) -> tuple[int, dict]:
    """
    Call the Immich API via docker inside the running container at localhost:2283.

    Bypasses Caddy entirely — avoids any forward-auth or Cloudflare interference.
    The immich-server container ships with curl (confirmed by its own healthcheck).
    Returns (http_status_code, response_dict).
    """
    args = [
        "docker", "exec", "immich-server",
        "curl", "-s", "-w", "\n%{http_code}",
        "-X", method,
        "-H", "x-api-key: " + api_key,
        "-H", "Accept: application/json",
    ]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    args.append("http://localhost:2283" + path)

    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise RuntimeError("docker exec immich-server timed out after 30 s")
    except FileNotFoundError:
        raise RuntimeError("docker not found on PATH")

    # curl -w appends the status code on its own line after the body
    parts = r.stdout.rsplit("\n", 1)
    try:
        status = int(parts[-1].strip())
    except (ValueError, IndexError) as exc:
        raise RuntimeError(f"Unexpected curl output: {r.stdout[:200]}") from exc
    body_text = parts[0] if len(parts) > 1 else ""
    try:
        return status, (json.loads(body_text) if body_text.strip() else {})
    except json.JSONDecodeError:
        return status, {"raw": body_text[:200]}


def configure_immich_oidc(
    immich_url: str,
    api_key: str,
    client_id: str,
    client_secret: str,
    issuer_url: str,
) -> bool:
    """
    Configure Immich OAuth2/OIDC via the system-config API.

    Calls the API through the immich-server container at localhost:2283 to
    bypass Caddy and avoid any network-layer issues. Fetches the current
    config, merges the OAuth block, and PUTs the full object back — Immich
    requires a complete config, partial PATCH is not supported.
    Returns True on success, False on failure (prints a warning — never raises).
    """
    try:
        status, config = _immich_exec_api("GET", "/api/system-config", api_key)
    except RuntimeError as exc:
        yellow(f"  Immich API unreachable via container: {exc}")
        return False

    if status == 401:
        yellow("  Immich returned 401 — IMMICH_API_KEY is invalid or expired")
        yellow("  Create a new key: Immich → Account Settings → API Keys → New Key")
        return False
    if status == 403:
        yellow("  Immich returned 403 — IMMICH_API_KEY must belong to an admin user")
        yellow("  Create the key while logged in as an Immich admin account")
        return False
    if status != 200:
        detail = config.get("raw") or config.get("message") or str(config)
        yellow(f"  Could not fetch Immich system config (HTTP {status}): {detail[:120]}")
        return False

    config.setdefault("oauth", {}).update({
        "enabled":           True,
        "issuerUrl":         issuer_url,
        "clientId":          client_id,
        "clientSecret":      client_secret,
        "scope":             "openid profile email",
        "buttonText":        "Login with Authentik",
        "autoRegister":      True,
        "autoLaunch":        False,
        "signingAlgorithm":  "RS256",
        "storageLabelClaim": "preferred_username",
    })

    try:
        put_status, put_resp = _immich_exec_api("PUT", "/api/system-config", api_key, body=config)
    except RuntimeError as exc:
        yellow(f"  Immich API PUT failed: {exc}")
        return False

    if put_status not in (200, 201):
        detail = put_resp.get("raw") or put_resp.get("message") or str(put_resp)
        yellow(f"  Immich OAuth config PUT failed (HTTP {put_status}): {detail[:120]}")
        return False

    green(f"  Immich OAuth configured (issuer={issuer_url})")
    return True


# ── Output file ────────────────────────────────────────────────────────────────

def write_output(path: Path, nc: dict, td: dict, af: dict, jf: dict, im: dict, vk: dict) -> None:
    affine_json = json.dumps({
        "args": {},
        "issuer":       af["issuer"],
        "clientId":     af["client_id"],
        "clientSecret": af["client_secret"],
    }, indent=2)

    text = f"""\
OIDC Setup Output
Generated by setup-oidc.py
================================================================

All credentials have been written to .env. The sections below
describe any remaining in-application steps that cannot be
automated via the API.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEXTCLOUD  (two manual steps required)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: Install the "OpenID Connect user backend" app
  → Nextcloud admin panel → Apps → search "user_oidc"

Step 2: Register the provider via occ (run after stack is healthy):

  docker exec --user www-data nextcloud sh -c '
    php occ user_oidc:provider "{nc["provider_name"]}" \\
      --clientid="{nc["client_id"]}" \\
      --clientsecret="{nc["client_secret"]}" \\
      --discoveryuri="{nc["discovery_url"]}" \\
      --check-bearer'

Credentials:
  Provider Name: {nc["provider_name"]}
  Client ID:     {nc["client_id"]}
  Client Secret: {nc["client_secret"]}
  Discovery URL: {nc["discovery_url"]}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TANDOOR  (no manual steps — restart-and-done)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Django allauth reads SOCIALACCOUNT_PROVIDERS from the environment
at startup. Credentials were written to .env and Tandoor was
restarted automatically. No further steps are needed.

If a manual restart is required:
  docker compose up -d --no-deps --force-recreate tandoor

Credentials:
  Client ID:     {td["client_id"]}
  Client Secret: {td["client_secret"]}
  Discovery URL: {td["discovery_url"]}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFFINE  (one manual step — admin panel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: Open  AFFiNE Admin Panel → Settings → OAuth
Step 2: Click "OIDC OAuth provider config" and paste this JSON:

{affine_json}

Credentials:
  Client ID:     {af["client_id"]}
  Client Secret: {af["client_secret"]}
  Issuer URL:    {af["issuer"]}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JELLYFIN  (SSO plugin required — github.com/9p4/jellyfin-plugin-sso)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{"Auto-configured via API." if jf.get("auto_configured") else "Auto-config was skipped (container not running or JELLYFIN_API_KEY not set)."}

Step 1: Install the SSO plugin
  Jellyfin admin → Plugins → Catalog → search "SSO Authentication" → Install
  Restart Jellyfin after installing.

Step 2: (if auto-config was skipped) Push config via the plugin config API.
  First, get the plugin ID:

  PLUGIN_ID=$(curl -s -H "X-MediaBrowser-Token: $JELLYFIN_API_KEY" \\
    {jf["jellyfin_url"]}/Plugins | python3 -c \\
    "import json,sys; print(next(p['Id'] for p in json.load(sys.stdin) if 'sso' in p.get('Name','').lower()))")

  Then POST the merged config:

  CURRENT=$(curl -s -H "X-MediaBrowser-Token: $JELLYFIN_API_KEY" \\
    {jf["jellyfin_url"]}/Plugins/$PLUGIN_ID/Configuration)
  echo $CURRENT | python3 -c "
import json,sys
c=json.load(sys.stdin)
c.setdefault('OidConfigs',{{}})['Authentik']={{
  'OidEndpoint':'{jf["discovery_url"]}',
  'OidClientId':'{jf["client_id"]}',
  'OidSecret':'{jf["client_secret"]}',
  'OidScopes':['openid','profile','email'],
  'Enabled':True,'EnableAuthorization':False,
  'EnableAllFolders':False,'EnabledFolders':[],
  'AdminRoles':[],'Roles':[],'EnableFolderRoles':False,
  'DisableHttps':False,'DisablePushedAuthorization':False,
  'DoNotValidateEndpoints':False,'DoNotValidateIssuerName':False,
  'RoleClaim':'','SchemeOverride':''
}}
print(json.dumps(c))" | \\
  curl -s -X POST \\
    -H "X-MediaBrowser-Token: $JELLYFIN_API_KEY" \\
    -H "Content-Type: application/json" \\
    -d @- {jf["jellyfin_url"]}/Plugins/$PLUGIN_ID/Configuration

Step 3: Confirm the "Sign in with Authentik" button appears at:
  {jf["jellyfin_url"]}/web/index.html#!/login.html

Note — Caddy / Authentik forward-auth:
  Jellyfin's API clients (mobile apps) and the SSO redirect callback must
  NOT pass through Authentik forward-auth. If example.com is behind
  @requires-auth in the Caddyfile, either exempt these paths:
    /sso/*  /Users/AuthenticateByName  /web/*  /Items/*  /Videos/*
  or remove forward-auth from the Jellyfin route and rely on Jellyfin's
  own authentication.

Credentials:
  Client ID:      {jf["client_id"]}
  Client Secret:  {jf["client_secret"]}
  Discovery URL:  {jf["discovery_url"]}
  Redirect URI:   {jf["redirect_uri"]}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMMICH  (OAuth via system-config API)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{"Auto-configured via API." if im.get("auto_configured") else "Auto-config was skipped (container not running or IMMICH_API_KEY not set)."}

Step 1: (if auto-config was skipped) Get an admin API key
  Immich → Account Settings → API Keys → New API Key → copy key
  Set IMMICH_API_KEY in unified-stack/.env, then re-run setup-oidc.py.

  Or apply manually via docker exec (bypasses Caddy):

  CURRENT=$(docker exec immich-server curl -s -H "x-api-key: $IMMICH_API_KEY" \\
    http://localhost:2283/api/system-config)
  echo $CURRENT | python3 -c "
import json,sys
c=json.load(sys.stdin)
c.setdefault('oauth',{{}}).update({{
  'enabled':True,
  'issuerUrl':'{im["issuer"]}',
  'clientId':'{im["client_id"]}',
  'clientSecret':'{im["client_secret"]}',
  'scope':'openid profile email',
  'buttonText':'Login with Authentik',
  'autoRegister':True,'autoLaunch':False,
  'signingAlgorithm':'RS256',
  'storageLabelClaim':'preferred_username'
}})
print(json.dumps(c))" | \\
  docker exec -i immich-server curl -s -X PUT \\
    -H "x-api-key: $IMMICH_API_KEY" -H "Content-Type: application/json" \\
    -d @- http://localhost:2283/api/system-config

Step 2: Verify the "Login with Authentik" button appears at:
  {im["immich_url"]}

Note — Caddy / Authentik forward-auth:
  Immich's mobile app and API clients authenticate directly and must NOT
  pass through Authentik forward-auth. The Immich route in the Caddyfile
  should NOT have forward_auth applied (the comment in docker-compose.yml
  already reflects this).

Credentials:
  Client ID:      {im["client_id"]}
  Client Secret:  {im["client_secret"]}
  Issuer URL:     {im["issuer"]}
  Redirect URI:   {im["redirect_uri"]}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VIKUNJA  (no manual steps — restart-and-done)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Vikunja reads OIDC config from environment variables at startup.
Credentials were written to .env and Vikunja was restarted
automatically. No further steps are needed.

If a manual restart is required:
  docker compose up -d --no-deps --force-recreate vikunja

Credentials:
  Client ID:     {vk["client_id"]}
  Client Secret: {vk["client_secret"]}
  Auth URL:      {vk["auth_url"]}
  Redirect URI:  {vk["redirect_uri"]}
"""
    path.write_text(text)
    step(f"Output file written to {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(args, env, sync_only: bool = False) -> int:
    """Provision Authentik OIDC providers for native-OIDC services.

    args is the argparse Namespace from set-auth.py; env is an EnvFile.
    sync_only mirrors the legacy --sync flag.
    """
    do_sync  = sync_only
    env_path = env.path


    # ── Preflight: verify API keys for auto-config ─────────────────────────────
    if not check_api_keys(env):
        red("Aborted.")
        return 1

    # ── Resolve Authentik token ────────────────────────────────────────────────
    token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN")
    if not token:
        step("AUTHENTIK_BOOTSTRAP_TOKEN not in .env — trying container fallback")
        token = get_token_from_container()
        if token:
            green("  retrieved token from authentik-server container")
        else:
            red(
                "ERROR: AUTHENTIK_BOOTSTRAP_TOKEN is not set in .env and the "
                "authentik-server container is not running or accessible."
            )
            return 1

    # ── Resolve required domain vars ───────────────────────────────────────────
    # Fall back to container env vars if .env values are missing
    def resolve(env_key: str, container: str, default: str = "") -> str:
        val = env.get(env_key)
        if not val and container_state(container) == "running":
            val = get_container_env_var(container, env_key) or ""
        return val or default

    public_fqdn  = resolve("PUBLIC_FQDN",  "caddy")
    tailnet_fqdn = resolve("TAILNET_FQDN", "caddy")
    auth_sub     = env.get("AUTHENTIK_SUBDOMAIN")  or "auth"
    nc_sub       = env.get("NEXTCLOUD_SUBDOMAIN")  or "cloud"
    td_sub       = env.get("TANDOOR_SUBDOMAIN")    or "food"
    af_sub       = env.get("AFFINE_SUBDOMAIN")     or "note"
    jf_sub       = env.get("JELLYFIN_SUBDOMAIN")   or "stream"
    im_sub       = env.get("IMMICH_SUBDOMAIN")     or "pic"
    vk_sub       = env.get("VIKUNJA_SUBDOMAIN")    or "todo"

    if not public_fqdn:
        red("ERROR: PUBLIC_FQDN is not set in .env and could not be read from the caddy container.")
        return 1

    authentik_url = f"https://{auth_sub}.{public_fqdn}"

    # ── Verify Authentik is reachable ──────────────────────────────────────────
    step(f"Verifying Authentik API at {authentik_url}")
    ak = AuthentikClient(authentik_url, token)
    try:
        ak.get("core/users/", page_size="1")
    except RuntimeError as exc:
        if "401" in str(exc) or "403" in str(exc):
            yellow(f"  Token rejected ({exc.args[0][:60]}…) — trying container fallback")
            container_token = get_token_from_container()
            if not container_token:
                red("ERROR: Token invalid and container fallback unavailable.")
                return 1
            token = container_token
            ak = AuthentikClient(authentik_url, token)
            try:
                ak.get("core/users/", page_size="1")
            except RuntimeError as exc2:
                red(f"Cannot reach Authentik API even with container token: {exc2}")
                return 1
            green("  Authentik API OK (using container token)")
            # Overwrite the stale token so future runs don't need the fallback.
            env.force_set("AUTHENTIK_BOOTSTRAP_TOKEN", token)
        else:
            red(f"Cannot reach Authentik API: {exc}")
            return 1
    else:
        green("  Authentik API OK")

    # ── Fetch shared prerequisites ─────────────────────────────────────────────
    step("Fetching authorization flow, invalidation flow, and signing key")

    flows = ak.get(
        "flows/instances/", designation="authorization", ordering="slug"
    ).get("results", [])
    auth_flow = next(
        (f["pk"] for f in flows if "implicit" in f.get("slug", "")),
        flows[0]["pk"] if flows else None,
    )
    if not auth_flow:
        red("No authorization flow found in Authentik — check the admin panel.")
        return 1
    green(f"  authorization flow: {auth_flow}")

    inv_flows = ak.get(
        "flows/instances/", designation="invalidation", ordering="slug"
    ).get("results", [])
    # Prefer provider-specific invalidation flow; fall back to the generic one.
    invalidation_flow = next(
        (f["pk"] for f in inv_flows if "provider" in f.get("slug", "")),
        inv_flows[0]["pk"] if inv_flows else None,
    )
    if not invalidation_flow:
        red("No invalidation flow found in Authentik — check the admin panel.")
        return 1
    green(f"  invalidation flow: {invalidation_flow}")

    keys = ak.get(
        "crypto/certificatekeypairs/", has_key="true", ordering="name"
    ).get("results", [])
    if not keys:
        red("No signing key found — generate one in Authentik admin → System → Certificates.")
        return 1
    signing_key = keys[0]["pk"]
    green(f"  signing key: {signing_key}")

    all_pm = ak.get("propertymappings/all/", page_size="100").get("results", [])
    scope_pk: dict[str, str] = {}
    for m in all_pm:
        lname = m["name"].lower()
        pk    = m["pk"]
        if "openid 'openid'" in lname:
            scope_pk["openid"] = pk
        elif "openid 'profile'" in lname:
            scope_pk["profile"] = pk
        elif "openid 'email'" in lname:
            scope_pk["email"] = pk
    if len(scope_pk) < 3:
        red("Could not find openid/profile/email scope property mappings — check Authentik.")
        return 1
    oidc_scope_mappings = [scope_pk["openid"], scope_pk["profile"], scope_pk["email"]]
    green(f"  scope mappings: openid={scope_pk['openid'][:8]}…")
    ensure_email_verified_claim(ak, scope_pk["email"])

    # Track which services have credentials before provisioning so we only
    # restart containers that actually received new credentials this run.
    _restart_cred_vars = {
        "nextcloud": "NEXTCLOUD_OIDC_CLIENT_ID",
        "tandoor":   "TANDOOR_OIDC_CLIENT_ID",
        "affine":    "AFFINE_OIDC_CLIENT_ID",
        "vikunja":   "VIKUNJA_OIDC_CLIENT_ID",
    }
    _creds_blank_before = {svc: not env.get(var) for svc, var in _restart_cred_vars.items()}

    # ── Nextcloud ──────────────────────────────────────────────────────────────
    step("Provisioning Nextcloud")
    redirect_uris_nc = [
        {"matching_mode": "strict",
         "url": f"https://{nc_sub}.{public_fqdn}/apps/user_oidc/code"},
    ]
    if tailnet_fqdn:
        redirect_uris_nc.append({
            "matching_mode": "strict",
            "url": f"https://{nc_sub}.{tailnet_fqdn}/apps/user_oidc/code",
        })

    nc_id, nc_secret, nc_app_pk = provision_service(
        ak, env,
        slug="nextcloud", name="Nextcloud",
        redirect_uris=redirect_uris_nc,
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow, signing_key_pk=signing_key,
        property_mappings=oidc_scope_mappings,
        id_var="NEXTCLOUD_OIDC_CLIENT_ID", secret_var="NEXTCLOUD_OIDC_CLIENT_SECRET",
    )
    nc_discovery = (
        f"https://{auth_sub}.{public_fqdn}"
        "/application/o/nextcloud/.well-known/openid-configuration"
    )
    env.set_if_blank("NEXTCLOUD_OIDC_DISCOVERY_URL", nc_discovery)
    nc_info = {
        "provider_name": env.get("NEXTCLOUD_OIDC_PROVIDER_NAME") or "Authentik",
        "client_id":     nc_id,
        "client_secret": nc_secret,
        "discovery_url": env.get("NEXTCLOUD_OIDC_DISCOVERY_URL") or nc_discovery,
    }

    # ── Tandoor ────────────────────────────────────────────────────────────────
    step("Provisioning Tandoor")
    _td_redirect_uris = [{
        "matching_mode": "strict",
        "url": f"https://{td_sub}.{public_fqdn}/accounts/oidc/authentik/login/callback/",
    }]
    if tailnet_fqdn:
        _td_redirect_uris.append({
            "matching_mode": "strict",
            "url": f"https://{td_sub}.{tailnet_fqdn}/accounts/oidc/authentik/login/callback/",
        })
    td_id, td_secret, td_app_pk = provision_service(
        ak, env,
        slug="tandoor", name="Tandoor",
        redirect_uris=_td_redirect_uris,
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow, signing_key_pk=signing_key,
        property_mappings=oidc_scope_mappings,
        id_var="TANDOOR_OIDC_CLIENT_ID", secret_var="TANDOOR_OIDC_CLIENT_SECRET",
    )
    td_discovery = (
        f"https://{auth_sub}.{public_fqdn}"
        "/application/o/tandoor/.well-known/openid-configuration"
    )
    env.set_if_blank("TANDOOR_OIDC_DISCOVERY_URL", td_discovery)
    td_info = {
        "client_id":     td_id,
        "client_secret": td_secret,
        "discovery_url": env.get("TANDOOR_OIDC_DISCOVERY_URL") or td_discovery,
    }

    # ── AFFiNE ─────────────────────────────────────────────────────────────────
    step("Provisioning AFFiNE")
    af_id, af_secret, af_app_pk = provision_service(
        ak, env,
        slug="affine", name="AFFiNE",
        redirect_uris=[{
            "matching_mode": "strict",
            "url": f"https://{af_sub}.{public_fqdn}/oauth/callback",
        }],
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow, signing_key_pk=signing_key,
        property_mappings=oidc_scope_mappings,
        id_var="AFFINE_OIDC_CLIENT_ID", secret_var="AFFINE_OIDC_CLIENT_SECRET",
    )
    af_issuer = f"https://{auth_sub}.{public_fqdn}/application/o/affine/"
    env.set_if_blank("AFFINE_OIDC_ISSUER", af_issuer)
    af_info = {
        "client_id":     af_id,
        "client_secret": af_secret,
        "issuer":        env.get("AFFINE_OIDC_ISSUER") or af_issuer,
    }

    # ── Jellyfin ───────────────────────────────────────────────────────────────
    step("Provisioning Jellyfin")
    jellyfin_url   = f"https://{jf_sub}.{public_fqdn}"
    jf_redirect    = f"{jellyfin_url}/sso/OID/redirect/Authentik"
    jf_discovery   = (
        f"https://{auth_sub}.{public_fqdn}"
        "/application/o/jellyfin/.well-known/openid-configuration"
    )
    jf_id, jf_secret, jf_app_pk = provision_service(
        ak, env,
        slug="jellyfin", name="Jellyfin",
        redirect_uris=[{"matching_mode": "strict", "url": jf_redirect}],
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow,
        signing_key_pk=signing_key, property_mappings=oidc_scope_mappings,
        id_var="JELLYFIN_OIDC_CLIENT_ID", secret_var="JELLYFIN_OIDC_CLIENT_SECRET",
    )
    env.set_if_blank("JELLYFIN_OIDC_DISCOVERY_URL", jf_discovery)

    jf_api_key      = env.get("JELLYFIN_API_KEY")
    jf_auto_ok      = False
    if jf_api_key and container_state("jellyfin") == "running":
        step("Configuring Jellyfin SSO plugin")
        jf_auto_ok = configure_jellyfin_sso(
            jellyfin_url  = jellyfin_url,
            api_key       = jf_api_key,
            provider_name = "Authentik",
            client_id     = jf_id,
            client_secret = jf_secret,
            discovery_url = env.get("JELLYFIN_OIDC_DISCOVERY_URL") or jf_discovery,
        )
    elif not jf_api_key:
        yellow("  JELLYFIN_API_KEY not set — skipping SSO plugin auto-config")
    else:
        yellow("  jellyfin container not running — skipping SSO plugin auto-config")

    jf_info = {
        "client_id":      jf_id,
        "client_secret":  jf_secret,
        "discovery_url":  env.get("JELLYFIN_OIDC_DISCOVERY_URL") or jf_discovery,
        "redirect_uri":   jf_redirect,
        "jellyfin_url":   jellyfin_url,
        "auto_configured": jf_auto_ok,
    }

    # ── Immich ─────────────────────────────────────────────────────────────────
    step("Provisioning Immich")
    immich_url  = f"https://{im_sub}.{public_fqdn}"
    im_redirect = f"{immich_url}/auth/login"
    im_issuer   = f"https://{auth_sub}.{public_fqdn}/application/o/immich/"
    im_id, im_secret, im_app_pk = provision_service(
        ak, env,
        slug="immich", name="Immich",
        redirect_uris=[
            {"matching_mode": "strict", "url": im_redirect},
            # Mobile app callback scheme
            {"matching_mode": "strict", "url": "app.immich:///oauth-callback"},
        ],
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow,
        signing_key_pk=signing_key, property_mappings=oidc_scope_mappings,
        id_var="IMMICH_OIDC_CLIENT_ID", secret_var="IMMICH_OIDC_CLIENT_SECRET",
    )
    env.set_if_blank("IMMICH_OIDC_ISSUER", im_issuer)

    im_api_key  = env.get("IMMICH_API_KEY")
    im_auto_ok  = False
    if im_api_key and container_state("immich-server") == "running":
        step("Configuring Immich OAuth")
        im_auto_ok = configure_immich_oidc(
            immich_url=immich_url,
            api_key=im_api_key,
            client_id=im_id,
            client_secret=im_secret,
            issuer_url=im_issuer,
        )
    elif not im_api_key:
        yellow("  IMMICH_API_KEY not set — skipping OAuth auto-config")
    else:
        yellow("  immich-server container not running — skipping OAuth auto-config")

    im_info = {
        "client_id":       im_id,
        "client_secret":   im_secret,
        "issuer":          im_issuer,
        "redirect_uri":    im_redirect,
        "immich_url":      immich_url,
        "auto_configured": im_auto_ok,
    }

    # ── Vikunja ───────────────────────────────────────────────────────────────
    step("Provisioning Vikunja")
    # The provider key "AUTHENTIK" in the env var name fixes the redirect path
    # to /auth/openid/authentik — Authentik must have that exact URI registered.
    vk_redirect = f"https://{vk_sub}.{public_fqdn}/auth/openid/authentik"
    vk_issuer   = f"https://{auth_sub}.{public_fqdn}/application/o/vikunja/"
    vk_id, vk_secret, vk_app_pk = provision_service(
        ak, env,
        slug="vikunja", name="Vikunja",
        redirect_uris=[{"matching_mode": "strict", "url": vk_redirect}],
        auth_flow_pk=auth_flow, invalidation_flow_pk=invalidation_flow,
        signing_key_pk=signing_key, property_mappings=oidc_scope_mappings,
        id_var="VIKUNJA_OIDC_CLIENT_ID", secret_var="VIKUNJA_OIDC_CLIENT_SECRET",
    )
    env.set_if_blank("VIKUNJA_OIDC_AUTH_URL", vk_issuer)
    vk_info = {
        "client_id":     vk_id,
        "client_secret": vk_secret,
        "auth_url":      env.get("VIKUNJA_OIDC_AUTH_URL") or vk_issuer,
        "redirect_uri":  vk_redirect,
    }

    # ── Entra group lifecycle ──────────────────────────────────────────────────
    gc = _load_graph_client(env)
    entra_prefix = env.get("ENTRA_GROUP_PREFIX")     or "authentik"
    ak_prefix    = env.get("AUTHENTIK_GROUP_PREFIX") or "entra"

    # Keyed by Authentik slug — used for policy binding in the next task.
    oidc_app_pks: dict[str, Optional[str]] = {
        "nextcloud": nc_app_pk,
        "tandoor":   td_app_pk,
        "affine":    af_app_pk,
        "jellyfin":  jf_app_pk,
        "immich":    im_app_pk,
        "vikunja":   vk_app_pk,
    }

    # Per-service Entra and Authentik group ids — collected for --sync use.
    service_group_ids: list[tuple[str, str, str]] = []  # (svc, entra_id, ak_pk)

    if gc is not None:
        step("Provisioning Entra + Authentik security groups")
        all_services = _discover_running_services()
        services = [s for s in all_services if s in _OIDC_CONTAINER_SLUGS]
        if not services:
            yellow("  No OIDC-managed containers found — skipping group provisioning")
        for svc in services:
            slug_name  = _OIDC_CONTAINER_SLUGS[svc]
            entra_name = f"{entra_prefix}-{slug_name}"
            ak_name    = f"{ak_prefix}-{slug_name}"
            entra_id   = _ensure_entra_group(gc, entra_name)
            ak_pk      = _ensure_authentik_group(ak, ak_name)
            service_group_ids.append((svc, entra_id, ak_pk))
            # Policy binding for the six OIDC services only.
            slug = _OIDC_CONTAINER_SLUGS.get(svc)
            if slug:
                app_pk = oidc_app_pks.get(slug)
                if app_pk:
                    _ensure_policy_binding(ak, app_pk, ak_pk)
            green(f"  {svc}: Entra group={entra_name}, Authentik group={ak_name}")

        # --sync: mirror Entra group membership into Authentik.
        if do_sync:
            step("Syncing Entra group membership into Authentik")
            for svc, entra_id, ak_pk in service_group_ids:
                step(f"  Syncing {svc}")
                _sync_group_membership(gc, ak, entra_id, ak_pk)

    # ── Global access group bindings ───────────────────────────────────────────
    # Members of ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME (default: ENTRA_ACCESS_GROUP)
    # get a GROUP binding on EVERY Authentik application so they can access all
    # services without being added to each per-service entra-{slug} group.
    # policy_engine_mode is "any" on all apps, so this binding alone is sufficient.
    #
    # Covers all apps (including forward-auth outpost and non-OIDC apps like kafka)
    # by querying Authentik directly rather than iterating only oidc_app_pks.
    # Filters existing bindings by group (not target) to avoid the Authentik GenericFK
    # 400 bug that occurs when querying target= for apps with no prior bindings.
    global_group_name = (
        env.get("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME")
        or "Global Access"
    )
    step(f"Binding global access group '{global_group_name}' to all apps")
    global_group_pk = _ensure_authentik_group(ak, global_group_name)

    if do_sync and gc is not None:
        step(f"Syncing global group '{global_group_name}' membership from Entra")
        global_entra_id = _ensure_entra_group(gc, global_group_name)
        _sync_group_membership(gc, ak, global_entra_id, global_group_pk)

    all_ak_apps: list[dict] = []
    page = 1
    while True:
        resp = ak.get(
            "core/applications/",
            page=str(page), page_size="100", superuser_full_list="true",
        )
        all_ak_apps.extend(resp.get("results", []))
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    # Fetch all existing bindings for the global group in one pass to avoid
    # N+1 calls and the GenericFK target= filter 400 on apps with no bindings.
    already_bound: set[str] = set()
    page = 1
    while True:
        resp = ak.get("policies/bindings/", group=global_group_pk, page=str(page), page_size="100")
        for b in resp.get("results", []):
            already_bound.add(str(b.get("target")))
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    for app in all_ak_apps:
        app_pk = str(app["pk"])
        if app_pk in already_bound:
            green(f"  {app['slug']}: global group binding already exists")
            continue
        ak.post("policies/bindings/", {
            "target":  app_pk,
            "group":   global_group_pk,
            "enabled": True,
            "order":   0,
        })
        green(f"  {app['slug']}: added global group binding")

    # ── Restart services that received new credentials this run ───────────────
    step("Restarting services with newly provisioned credentials")
    for svc in ("nextcloud", "tandoor", "affine", "vikunja"):
        if container_state(svc) != "running":
            yellow(f"  {svc} not running — start it after configuring credentials")
            continue
        if _creds_blank_before.get(svc, False):
            restart_service(env_path, svc)
        else:
            green(f"  {svc} already configured — no restart needed")

    # ── Write output file ──────────────────────────────────────────────────────
    output_path = env_path.parent / "oidc-setup-output.txt"
    write_output(output_path, nc_info, td_info, af_info, jf_info, im_info, vk_info)

    green(f"\nsetup-oidc.py complete.")
    green(f"Manual steps: {output_path}")
    return 0


