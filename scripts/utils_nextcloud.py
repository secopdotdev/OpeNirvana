"""utils_nextcloud - Nextcloud occ + OCS helpers and user_oidc auto-config.

The setup side uses `docker exec --user www-data nextcloud php occ ...` because
the script runs on the docker host where it has docker access. The OCS API
helper is used for read-side validation (audit-user-access.py).
"""

import base64
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from utils import EnvFile, red, green, yellow, step


_NEXTCLOUD_CONTAINER = "nextcloud"


def _occ(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Run `php occ <args>` inside the nextcloud container as www-data."""
    cmd = ["docker", "exec", "--user", "www-data", _NEXTCLOUD_CONTAINER,
           "php", "occ", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def app_is_enabled(app: str) -> bool:
    """True iff `occ app:list --output=json` lists the named app under 'enabled'."""
    r = _occ(["app:list", "--output=json"])
    if r.returncode != 0:
        return False
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return False
    return app in (data.get("enabled") or {})


def app_install(app: str) -> bool:
    """Ensure `app` is installed and enabled. Idempotent. Returns True on success."""
    if app_is_enabled(app):
        green(f"  Nextcloud app '{app}' already enabled")
        return True
    step(f"Installing Nextcloud app '{app}'")
    r = _occ(["app:install", app])
    if r.returncode != 0 and "already installed" not in (r.stderr + r.stdout).lower():
        red(f"  occ app:install {app} failed: {r.stderr.strip() or r.stdout.strip()}")
        return False
    # `app:install` enables automatically on most builds; explicit enable for safety.
    r2 = _occ(["app:enable", app])
    if r2.returncode != 0:
        red(f"  occ app:enable {app} failed: {r2.stderr.strip()}")
        return False
    green(f"  Nextcloud app '{app}' installed + enabled")
    return True


def user_oidc_list_providers() -> list[dict]:
    """Return the provider list from `occ user_oidc:provider --output=json`.

    Each entry has at least: id, identifier, clientId, discoveryEndpoint.
    Returns [] if user_oidc isn't enabled or the command fails.
    """
    if not app_is_enabled("user_oidc"):
        return []
    r = _occ(["user_oidc:provider", "--output=json"])
    if r.returncode != 0:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def user_oidc_register_provider(name: str, client_id: str, client_secret: str,
                                discovery_url: str) -> bool:
    """Register or update a user_oidc provider named `name`. Idempotent.

    Returns True on success.
    """
    if not app_install("user_oidc"):
        return False
    existing = next((p for p in user_oidc_list_providers() if p["identifier"] == name), None)
    verb = "updat" if existing else "register"
    step(f"{verb}ing Nextcloud user_oidc provider {name!r}")
    cmd = [
        "user_oidc:provider", name,
        f"--clientid={client_id}",
        f"--clientsecret={client_secret}",
        f"--discoveryuri={discovery_url}",
        "--check-bearer=1",
        "--unique-uid=0",
        "--mapping-uid=preferred_username",
    ]
    r = _occ(cmd, timeout=90)
    if r.returncode != 0:
        red(f"  occ user_oidc:provider failed: {r.stderr.strip() or r.stdout.strip()}")
        return False
    green(f"  user_oidc provider {name!r} {verb}ed")
    return True


def talk_signaling_list() -> list[dict]:
    """Return the configured Talk HPB signaling servers as a list of dicts.

    `occ talk:signaling:list --output=json` returns either:
      - {"servers": [{"server": "...", "verify": bool}, ...], "secret": "..."}
      - [] when none are configured
      - a bare list on some older versions
    Each entry has at least: server, verify. Returns [] if Talk isn't enabled
    or the command fails. The id/index is the position in the list (0-based).
    """
    if not app_is_enabled("spreed"):
        return []
    r = _occ(["talk:signaling:list", "--output=json"])
    if r.returncode != 0:
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("servers", [])
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict)]


def talk_signaling_setup(server_url: str, shared_secret: str) -> bool:
    """Configure Nextcloud Talk's High-Performance Backend signaling server.

    Idempotent: if a server with the same URL is already registered, this is
    a no-op. If a different URL is registered, all entries are cleared and the
    target server is added (Talk supports multiple signaling servers but we
    only manage the single in-stack HPB here — the spreed-signaling container
    paired with nextcloud-spreed-signaling/server.conf).

    Returns True on success.
    """
    if not app_is_enabled("spreed"):
        yellow("  Talk (spreed) app not enabled — skipping HPB signaling setup")
        return True
    existing = talk_signaling_list()
    if any(e.get("server") == server_url for e in existing):
        green(f"  Talk HPB signaling already configured: {server_url}")
        return True
    if existing:
        step("clearing stale Talk HPB signaling entries")
        for idx in range(len(existing) - 1, -1, -1):
            rd = _occ(["talk:signaling:delete", str(idx)])
            if rd.returncode != 0:
                red(f"  occ talk:signaling:delete {idx} failed: "
                    f"{rd.stderr.strip() or rd.stdout.strip()}")
                return False
    step(f"registering Talk HPB signaling server {server_url}")
    r = _occ(["talk:signaling:add", server_url, shared_secret])
    if r.returncode != 0:
        red(f"  occ talk:signaling:add failed: {r.stderr.strip() or r.stdout.strip()}")
        return False
    green(f"  Talk HPB signaling configured: {server_url}")
    return True


def ocs_get(env: EnvFile, path: str, params: dict | None = None) -> dict:
    """Authenticated GET against the Nextcloud OCS API. Returns the parsed JSON body.

    Uses NEXTCLOUD_API_USERNAME + NEXTCLOUD_API_KEY (basic auth) and sets the
    mandatory OCS-APIRequest header. Raises RuntimeError on HTTP error.
    """
    user   = env.get("NEXTCLOUD_API_USERNAME") or env.get("NEXTCLOUD_ADMIN_USER")
    secret = env.get("NEXTCLOUD_API_KEY")
    sub    = env.get("NEXTCLOUD_SUBDOMAIN") or "cloud"
    fqdn   = env.get("PUBLIC_FQDN")
    if not (user and secret and fqdn):
        raise RuntimeError("NEXTCLOUD_API_USERNAME / NEXTCLOUD_API_KEY / PUBLIC_FQDN not set")
    url = f"https://{sub}.{fqdn}{path}?format=json"
    if params:
        url += "&" + urllib.parse.urlencode(params)
    auth = base64.b64encode(f"{user}:{secret}".encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization":  f"Basic {auth}",
        "OCS-APIRequest": "true",
        "Accept":         "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"OCS GET {url}: HTTP {e.code} {body}") from e


def _setup_talk_hpb(env: EnvFile) -> bool:
    """Register the in-stack spreed-signaling HPB with Talk. Idempotent.

    Reads TALK_SUBDOMAIN, PUBLIC_FQDN, NC_HPB_SHARED_SECRET. Skips with a
    warning if any are missing (HPB is optional — the stack still works for
    1-on-1 calls without it).
    """
    sub    = env.get("TALK_SUBDOMAIN")
    fqdn   = env.get("PUBLIC_FQDN")
    secret = env.get("NC_HPB_SHARED_SECRET")
    if not (sub and fqdn and secret):
        yellow("  skipping Talk HPB setup — TALK_SUBDOMAIN / PUBLIC_FQDN / "
               "NC_HPB_SHARED_SECRET not all set in .env")
        return True
    server_url = f"https://{sub}.{fqdn}/"
    return talk_signaling_setup(server_url, secret)


def run(args, env: EnvFile) -> int:
    """Subcommand entry point. Reads NEXTCLOUD_OIDC_* + Talk HPB vars from .env
    and configures user_oidc + Talk signaling. Idempotent."""
    name          = env.get("NEXTCLOUD_OIDC_PROVIDER_NAME") or "Authentik"
    client_id     = env.get("NEXTCLOUD_OIDC_CLIENT_ID")
    client_secret = env.get("NEXTCLOUD_OIDC_CLIENT_SECRET")
    discovery_url = env.get("NEXTCLOUD_OIDC_DISCOVERY_URL")
    missing = [k for k, v in {
        "NEXTCLOUD_OIDC_CLIENT_ID":     client_id,
        "NEXTCLOUD_OIDC_CLIENT_SECRET": client_secret,
        "NEXTCLOUD_OIDC_DISCOVERY_URL": discovery_url,
    }.items() if not v]
    if missing:
        red(f"  cannot configure user_oidc -- missing .env vars: {', '.join(missing)}")
        red("  run `set-auth.py oidc` first to provision the Authentik OAuth2 provider")
        return 1
    if not user_oidc_register_provider(name, client_id, client_secret, discovery_url):
        return 1
    if not _setup_talk_hpb(env):
        return 1
    return 0
