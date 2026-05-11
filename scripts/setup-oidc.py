#!/usr/bin/env python3
"""
setup-oidc.py  —  Provisions Authentik OAuth2/OIDC providers and applications
for Nextcloud, Tandoor, AFFiNE, Jellyfin, Immich, and Vikunja, then writes the
generated credentials back into .env and creates oidc-setup-output.txt with any
remaining manual steps.

Usage:
    python3 scripts/setup-oidc.py [path/to/.env]
    (defaults to <script-dir>/../.env)

Prerequisites:
    - Authentik must be running and healthy
    - AUTHENTIK_BOOTSTRAP_TOKEN must be in .env
      (or the authentik-server container must be running as a fallback)
    - JELLYFIN_API_KEY — optional; enables Jellyfin SSO plugin auto-config
    - IMMICH_API_KEY   — optional; enables Immich OAuth auto-config
    - Python 3.10+  (no third-party packages required — stdlib only)

Idempotent: any service whose CLIENT_ID var is already non-empty is skipped.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


# ── ANSI output helpers ────────────────────────────────────────────────────────

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
        """
        Write KEY=value when:
          - the key exists with a blank value (or blank + inline comment) → replace in-place
          - the key is absent entirely → append to end of file
        Skip when the key exists and already has a non-blank value.
        """
        # Check whether the key exists at all and whether it has a value.
        key_prefix = f"{key}="
        for line in self._text.splitlines():
            if line.startswith(key_prefix):
                existing_val = self._INLINE_COMMENT.sub("", line[len(key_prefix):]).strip()
                if existing_val:
                    print(f"  skip   {key} (already set)")
                    return
                break  # key present but blank — fall through to in-place replace

        # Try in-place replacement of blank key line.
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
            # Key is absent — append it.
            self._text = self._text.rstrip("\n") + f"\n{key}={value}\n"
            self.path.write_text(self._text)
            print(f"  wrote  {key} (appended)")


# ── Authentik API client ───────────────────────────────────────────────────────

class AuthentikClient:
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
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc

    def get(self, path: str, **params: str) -> dict:
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            path = f"{path}?{qs}"
        return self._request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body)


# ── Docker helpers ─────────────────────────────────────────────────────────────

def container_running(name: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", name, "--format", "{{.State.Status}}"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() == "running"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


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
) -> tuple[str, str]:
    """
    Create an Authentik OAuth2/OIDC provider + application if CLIENT_ID is blank.
    Returns (client_id, client_secret).
    """
    existing_id = env.get(id_var)
    if existing_id:
        yellow(f"{name}: {id_var} already set — skipping")
        return existing_id, env.get(secret_var)

    # Check whether the provider already exists in Authentik (e.g. from a
    # prior partial run where credentials weren't written back to .env).
    existing = ak.get("providers/oauth2/", name=name).get("results", [])
    if existing:
        provider      = existing[0]
        pk            = provider["pk"]
        client_id     = provider["client_id"]
        client_secret = provider["client_secret"]
        green(f"  {name}: provider already exists (pk={pk}) — reusing credentials")
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
            ak.post("core/applications/", {"name": name, "slug": slug, "provider": pk})
            green("  application created")
        except RuntimeError as exc:
            if "already exists" in str(exc):
                green("  application already exists — skipping")
            else:
                raise

    env.set_if_blank(id_var,     client_id)
    env.set_if_blank(secret_var, client_secret)
    return client_id, client_secret


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

def configure_immich_oidc(
    immich_url: str,
    api_key: str,
    client_id: str,
    client_secret: str,
    issuer_url: str,
) -> bool:
    """
    Configure Immich OAuth2/OIDC via the system-config API.

    Fetches the current system config, merges in the OAuth block, and PUTs
    the full config back (Immich requires a complete object — partial PATCH is
    not supported). Returns True on success, False on failure.
    """
    base = immich_url.rstrip("/")
    headers = {
        "x-api-key":     api_key,
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }

    # Fetch current config so we don't wipe unrelated settings.
    get_req = urllib.request.Request(f"{base}/api/system-config", headers=headers)
    try:
        with urllib.request.urlopen(get_req, timeout=20) as resp:
            config = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        yellow(f"  Could not fetch Immich system config (HTTP {exc.code}): {detail[:120]}")
        return False
    except OSError as exc:
        yellow(f"  Immich unreachable: {exc}")
        yellow("  Set IMMICH_API_KEY and re-run setup-oidc.py once Immich is up")
        return False

    config.setdefault("oauth", {}).update({
        "enabled":          True,
        "issuerUrl":        issuer_url,
        "clientId":         client_id,
        "clientSecret":     client_secret,
        "scope":            "openid profile email",
        "buttonText":       "Login with Authentik",
        "autoRegister":     True,
        "autoLaunch":       False,
        "signingAlgorithm": "RS256",
        "storageLabelClaim": "preferred_username",
    })

    put_req = urllib.request.Request(
        f"{base}/api/system-config",
        data=json.dumps(config).encode(),
        method="PUT",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(put_req, timeout=20) as resp:
            resp.read()
        green(f"  Immich OAuth configured (issuer={issuer_url})")
        return True
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        yellow(f"  Immich OAuth config failed (HTTP {exc.code}): {detail[:120]}")
        return False
    except OSError as exc:
        yellow(f"  Immich unreachable: {exc}")
        return False


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
  NOT pass through Authentik forward-auth. If stream.secop.dev is behind
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
  Set IMMICH_API_KEY in /dock/conf/.env, then re-run setup-oidc.py.

  Or apply manually with curl:

  CURRENT=$(curl -s -H "x-api-key: $IMMICH_API_KEY" {im["immich_url"]}/api/system-config)
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
  curl -s -X PUT -H "x-api-key: $IMMICH_API_KEY" -H "Content-Type: application/json" \\
    -d @- {im["immich_url"]}/api/system-config

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

def main(argv: list[str]) -> int:
    script_dir = Path(__file__).resolve().parent
    env_path   = (
        Path(argv[1]).resolve() if len(argv) > 1
        else (script_dir / ".." / ".env").resolve()
    )

    if not env_path.exists():
        red(f"ERROR: .env not found at {env_path}")
        return 1

    env = EnvFile(env_path)

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
        if not val and container_running(container):
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

    nc_id, nc_secret = provision_service(
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
    td_id, td_secret = provision_service(
        ak, env,
        slug="tandoor", name="Tandoor",
        redirect_uris=[{
            "matching_mode": "strict",
            "url": f"https://{td_sub}.{public_fqdn}/accounts/oidc/authentik/login/callback/",
        }],
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
    af_id, af_secret = provision_service(
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
    jf_id, jf_secret = provision_service(
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
    if jf_api_key and container_running("jellyfin"):
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
    im_id, im_secret = provision_service(
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
    if im_api_key and container_running("immich-server"):
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
    vk_id, vk_secret = provision_service(
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

    # ── Restart running containers ─────────────────────────────────────────────
    step("Restarting running services")
    for svc in ("nextcloud", "tandoor", "affine", "vikunja"):
        if container_running(svc):
            restart_service(env_path, svc)
        else:
            yellow(f"  {svc} not running — start it after configuring credentials")

    # ── Write output file ──────────────────────────────────────────────────────
    output_path = env_path.parent / "oidc-setup-output.txt"
    write_output(output_path, nc_info, td_info, af_info, jf_info, im_info, vk_info)

    green(f"\nsetup-oidc.py complete.")
    green(f"Manual steps: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
