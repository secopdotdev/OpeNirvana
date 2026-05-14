#!/usr/bin/env python3
"""
setup-entra.py  —  Optional Authentik ↔ Microsoft Entra ID federation.

Usage:
    python3 scripts/setup-entra.py --setup [path/to/.env]
    python3 scripts/setup-entra.py --sync  [path/to/.env]

    --setup  One-time interactive setup (device-code login, App Registration,
             Authentik source + policy, Entra-only enforcement).
    --sync   Non-interactive sync of Entra group members → Authentik users/groups.
             Safe to run on cron. Reads all credentials from .env.

Prerequisites:
    pip install msal
    ENTRA_TENANT_ID set in .env before --setup
    Authentik running with AUTHENTIK_BOOTSTRAP_TOKEN in .env
    Break-glass local Authentik admin account active

Idempotent: each phase checks its .env output vars before executing.
"""

import sys

# Guard: must be first executable statement after docstring and stdlib imports
try:
    import msal  # noqa: F401
except ImportError:
    print("ERROR: msal is not installed. Run:  pip install msal", file=sys.stderr)
    sys.exit(1)

import argparse
import datetime
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from utils import EnvFile, AuthentikClient, red, green, yellow, step, container_state


# ── Microsoft Graph client ─────────────────────────────────────────────────────

# Well-known Azure CLI public client ID — supports device-code flow without
# registering a new app. Used only for --setup (delegated permissions).
_AZ_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


class GraphClient:
    """Microsoft Graph REST client. Call authenticate() or from_client_credentials() first."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._token: Optional[str] = None

    def authenticate(self) -> None:
        """Device-code flow — interactive, for --setup."""
        app = msal.PublicClientApplication(
            _AZ_CLI_CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
        if "error" in flow:
            red(f"Device flow error: {flow.get('error_description', flow['error'])}")
            sys.exit(1)
        print(f"\n{flow['message']}\n")
        result = app.acquire_token_by_device_flow(flow)
        if "error" in result:
            red(f"Authentication failed: {result.get('error_description', result['error'])}")
            sys.exit(1)
        self._token = result["access_token"]
        green("  Microsoft authentication complete")

    @classmethod
    def from_client_credentials(cls, tenant_id: str, client_id: str, client_secret: str) -> "GraphClient":
        """Client-credentials flow — non-interactive, for --sync."""
        gc = cls(tenant_id)
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "error" in result:
            red(f"Client credentials failed: {result.get('error_description', result['error'])}")
            sys.exit(1)
        gc._token = result["access_token"]
        return gc

    def _request(self, method: str, url: str, body: Optional[dict] = None, _retries: int = 0) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After")
            if exc.code == 429 and retry_after and _retries < 3:
                try:
                    delay = min(int(retry_after), 60)
                except ValueError:
                    delay = 30
                yellow(f"  Graph rate limit — sleeping {delay}s")
                time.sleep(delay)
                return self._request(method, url, body, _retries + 1)
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc

    def get(self, path: str, **params: str) -> dict:
        """GET a single page. Callers must follow @odata.nextLink for paginated results."""
        url = f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._request("GET", url)

    def post(self, path: str, body: dict) -> dict:
        return self._request("POST", f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}", body)

    def patch(self, path: str, body: dict) -> dict:
        return self._request("PATCH", f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}", body)


# ── Graph API constants ────────────────────────────────────────────────────────

# Microsoft Graph service principal app ID (constant across all tenants)
_GRAPH_SP_APP_ID = "00000003-0000-0000-c000-000000000000"

# Application permission role IDs on Microsoft Graph
_GRAPH_ROLES = {
    "User.Read.All":        "df021288-bdef-4463-88db-98f22de89214",
    "Group.Read.All":       "5b567255-7703-4780-807c-7be8301ae99b",
    "GroupMember.Read.All": "98830695-27a2-44f7-8c18-0c3ebc9698f6",
}


# ── Graph API helpers ──────────────────────────────────────────────────────────

def _find_or_create_app(gc: GraphClient, app_name: str, redirect_uris: list[str]) -> tuple[str, str]:
    """Return (object_id, app_id/client_id) — creates App Registration if absent.

    If app exists: ensures redirect_uris are present, returns (id, appId).
    If app absent: creates with displayName, signInAudience=AzureADMyOrg,
      web.redirectUris, and requiredResourceAccess for all _GRAPH_ROLES.
    """
    resp = gc.get("applications", **{"$filter": f"displayName eq '{app_name}'"})
    existing = resp.get("value", [])
    if existing:
        app = existing[0]
        green(f"  App Registration '{app_name}' already exists (appId={app['appId']})")
        current_uris = app.get("web", {}).get("redirectUris", [])
        missing = [u for u in redirect_uris if u not in current_uris]
        if missing:
            gc.patch(f"applications/{app['id']}", {
                "web": {"redirectUris": current_uris + missing}
            })
            green(f"  Added {len(missing)} redirect URI(s)")
        return app["id"], app["appId"]

    step(f"Creating App Registration '{app_name}'")
    app = gc.post("applications", {
        "displayName": app_name,
        "signInAudience": "AzureADMyOrg",
        "web": {"redirectUris": redirect_uris},
        "requiredResourceAccess": [{
            "resourceAppId": _GRAPH_SP_APP_ID,
            "resourceAccess": [
                {"id": role_id, "type": "Role"}
                for role_id in _GRAPH_ROLES.values()
            ],
        }],
    })
    green(f"  Created App Registration (appId={app['appId']})")
    return app["id"], app["appId"]


def _add_client_secret(gc: GraphClient, object_id: str) -> str:
    """Add a 2-year client secret and return the secret value."""
    expiry = (datetime.datetime.utcnow() + datetime.timedelta(days=730)).strftime("%Y-%m-%dT%H:%M:%SZ")
    resp = gc.post(f"applications/{object_id}/addPassword", {
        "passwordCredential": {
            "displayName": "authentik-sync",
            "endDateTime": expiry,
        }
    })
    return resp["secretText"]


def _get_or_create_service_principal(gc: GraphClient, client_id: str) -> str:
    """Return service principal object ID, creating it if absent."""
    resp = gc.get("servicePrincipals", **{"$filter": f"appId eq '{client_id}'"})
    existing = resp.get("value", [])
    if existing:
        return existing[0]["id"]
    sp = gc.post("servicePrincipals", {"appId": client_id})
    green(f"  Created service principal (id={sp['id']})")
    return sp["id"]


def _get_graph_sp_id(gc: GraphClient) -> str:
    """Return the object ID of the Microsoft Graph service principal in this tenant."""
    resp = gc.get("servicePrincipals", **{"$filter": f"appId eq '{_GRAPH_SP_APP_ID}'"})
    return resp["value"][0]["id"]


def _grant_app_roles(gc: GraphClient, sp_id: str, graph_sp_id: str) -> None:
    """Grant all _GRAPH_ROLES via appRoleAssignments. Skips existing. Exits 1 on 403.

    Requires Global Admin on the authenticated account — exits with portal URL on 403.
    """
    existing_resp = gc.get(f"servicePrincipals/{sp_id}/appRoleAssignments")
    existing_role_ids = {a["appRoleId"] for a in existing_resp.get("value", [])}

    for perm_name, role_id in _GRAPH_ROLES.items():
        if role_id in existing_role_ids:
            green(f"  Admin consent already granted: {perm_name}")
            continue
        try:
            gc.post(f"servicePrincipals/{sp_id}/appRoleAssignments", {
                "principalId": sp_id,
                "resourceId": graph_sp_id,
                "appRoleId": role_id,
            })
            green(f"  Granted: {perm_name}")
        except RuntimeError as exc:
            if "403" in str(exc):
                portal_url = (
                    "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade"
                    "/~/RegisteredApps"
                )
                red(f"  Admin consent 403 — account lacks Global Admin role.")
                red(f"  Grant permissions manually: {portal_url}")
                red(f"  Required: {', '.join(_GRAPH_ROLES.keys())}")
                sys.exit(1)
            raise


# ── Entra group helpers (Phase 2) ──────────────────────────────────────────────

def _find_or_create_group(gc: GraphClient, group_name: str) -> str:
    """Return Entra security group object ID, creating it if absent."""
    resp = gc.get("groups", **{"$filter": f"displayName eq '{group_name}'"})
    existing = resp.get("value", [])
    if existing:
        green(f"  Entra group '{group_name}' already exists (id={existing[0]['id']})")
        return existing[0]["id"]
    group = gc.post("groups", {
        "displayName": group_name,
        "mailEnabled": False,
        "mailNickname": group_name.replace(" ", "-").lower(),
        "securityEnabled": True,
        "groupTypes": [],
    })
    green(f"  Created Entra group '{group_name}' (id={group['id']})")
    return group["id"]


def _add_group_member(gc: GraphClient, group_id: str, user_id: str) -> None:
    """Add user to Entra group; silently ignore if already a member."""
    try:
        gc.post(f"groups/{group_id}/members/$ref", {
            "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
        })
        green("  Added authenticated user to access group")
    except RuntimeError as exc:
        if "already exist" in str(exc).lower() or "400" in str(exc):
            green("  User already a member of access group")
        else:
            raise


def _get_me(gc: GraphClient) -> dict:
    """Return the authenticated user's profile (/me)."""
    return gc.get("me")


# ── Phase 1 orchestrator ───────────────────────────────────────────────────────

def phase1_app_registration(
    gc: GraphClient,
    env: EnvFile,
    app_name: str,
    redirect_uris: list[str],
) -> tuple[str, str]:
    """Create or find App Registration, secret, SP, and grant admin consent.

    Returns (client_id, client_secret). Writes ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET to .env.
    Idempotent: if ENTRA_CLIENT_ID already set, skips Graph API calls and returns existing values.
    """
    existing_client_id = env.get("ENTRA_CLIENT_ID")
    if existing_client_id:
        green(f"  ENTRA_CLIENT_ID already set — skipping App Registration phase")
        return existing_client_id, env.get("ENTRA_CLIENT_SECRET")

    object_id, client_id = _find_or_create_app(gc, app_name, redirect_uris)
    client_secret = _add_client_secret(gc, object_id)
    env.force_set("ENTRA_CLIENT_ID", client_id)
    env.force_set("ENTRA_CLIENT_SECRET", client_secret)

    sp_id = _get_or_create_service_principal(gc, client_id)
    graph_sp_id = _get_graph_sp_id(gc)
    _grant_app_roles(gc, sp_id, graph_sp_id)

    return client_id, client_secret


# ── Phase 2 orchestrator ───────────────────────────────────────────────────────

def phase2_entra_group(gc: GraphClient, env: EnvFile, access_group_name: str) -> str:
    """Create Entra access group, add authenticated user as first member.

    Returns Entra group object_id.
    """
    step("Phase 2 — Create Entra access group")
    group_id = _find_or_create_group(gc, access_group_name)
    me = _get_me(gc)
    _add_group_member(gc, group_id, me["id"])
    green(f"  Access group ready: '{access_group_name}' ({me.get('userPrincipalName', me['id'])} is a member)")
    return group_id


# ── Phase 3 — Authentik OIDC source ───────────────────────────────────────────

def _find_or_create_authentik_source(
    ak: AuthentikClient,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> str:
    """Create (or find) Authentik OAuth2 source with slug 'entra-id'.

    Returns source PK.
    user_matching_mode='email_link': links sign-ins to pre-provisioned accounts by email.
    """
    existing = ak.get("sources/oauth/", slug="entra-id").get("results", [])
    if existing:
        green(f"  Authentik OIDC source 'entra-id' already exists (pk={existing[0]['pk']})")
        return existing[0]["pk"]

    step("Phase 3 — Creating Authentik OIDC source (entra-id)")
    source = ak.post("sources/oauth/", {
        "name": "Microsoft Entra ID",
        "slug": "entra-id",
        "enabled": True,
        "provider_type": "openidconnect",
        "consumer_key": client_id,
        "consumer_secret": client_secret,
        "authorization_url": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "access_token_url": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "profile_url": "https://graph.microsoft.com/oidc/userinfo",
        "oidc_jwks_url": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        "oidc_issuer_url": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "additional_scopes": "openid profile email",
        "user_matching_mode": "email_link",
    })
    green(f"  Created Authentik OIDC source (pk={source['pk']})")
    return source["pk"]


def phase3_authentik_source(
    ak: AuthentikClient,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> str:
    """Phase 3 orchestrator — creates the entra-id source. Returns source PK."""
    step("Phase 3 — Authentik OIDC source")
    return _find_or_create_authentik_source(ak, tenant_id, client_id, client_secret)


# ── Phase 4 — Access-group policy + flow binding ───────────────────────────────

def _find_or_create_authentik_group(ak: AuthentikClient, group_name: str) -> str:
    """Return Authentik group PK, creating if absent."""
    resp = ak.get("core/groups/", name=group_name)
    existing = resp.get("results", [])
    if existing:
        green(f"  Authentik group '{group_name}' already exists (pk={existing[0]['pk']})")
        return existing[0]["pk"]
    group = ak.post("core/groups/", {"name": group_name})
    green(f"  Created Authentik group '{group_name}' (pk={group['pk']})")
    return group["pk"]


def _find_or_create_expression_policy(ak: AuthentikClient, group_name: str) -> str:
    """Create expression policy that gates access to members of group_name.

    Policy name: 'entra-access-{group_name}'
    Expression: return request.user.ak_groups.filter(name="{group_name}").exists()
    """
    if not re.match(r'^[\w\-]+$', group_name):
        red(f"Group name '{group_name}' contains invalid characters (allowed: a-z A-Z 0-9 _ -)")
        sys.exit(1)
    policy_name = f"entra-access-{group_name}"
    resp = ak.get("policies/expression/", name=policy_name)
    existing = resp.get("results", [])
    if existing:
        green(f"  Expression policy '{policy_name}' already exists")
        return existing[0]["pk"]
    policy = ak.post("policies/expression/", {
        "name": policy_name,
        "expression": (
            f'return request.user.ak_groups.filter(name="{group_name}").exists()'
        ),
    })
    green(f"  Created expression policy '{policy_name}' (pk={policy['pk']})")
    return policy["pk"]


def _find_or_create_policy_binding(
    ak: AuthentikClient,
    policy_pk: str,
    flow_pk: str,
    order: int = 0,
) -> str:
    """Bind policy to flow. Returns binding PK."""
    resp = ak.get("policies/bindings/", policy=policy_pk, target=flow_pk)
    existing = resp.get("results", [])
    if existing:
        green(f"  Policy binding already exists (pk={existing[0]['pk']})")
        return existing[0]["pk"]
    binding = ak.post("policies/bindings/", {
        "policy": policy_pk,
        "target": flow_pk,
        "enabled": True,
        "order": order,
    })
    green(f"  Created policy binding (pk={binding['pk']})")
    return binding["pk"]


def _get_authorization_flow_pk(ak: AuthentikClient) -> str:
    """Return PK of the default authorization flow (designation='authorization')."""
    resp = ak.get("flows/instances/", designation="authorization")
    results = resp.get("results", [])
    if not results:
        red("No authorization flow found in Authentik. Is Authentik healthy?")
        sys.exit(1)
    return results[0]["pk"]


def phase4_access_policy(
    ak: AuthentikClient,
    access_group_name: str,
) -> tuple[str, str, str]:
    """Phase 4 orchestrator — Authentik group, expression policy, auth flow binding.

    Returns (group_pk, policy_pk, binding_pk).
    """
    step("Phase 4 — Authentik access-group policy")
    auth_flow_pk = _get_authorization_flow_pk(ak)
    group_pk = _find_or_create_authentik_group(ak, access_group_name)
    policy_pk = _find_or_create_expression_policy(ak, access_group_name)
    binding_pk = _find_or_create_policy_binding(ak, policy_pk, auth_flow_pk)
    return group_pk, policy_pk, binding_pk


# ── Phase 5 — Enforce Entra-only login ────────────────────────────────────────

def _verify_break_glass_account(ak: AuthentikClient) -> None:
    """Refuse to enforce Entra-only login if no active local superuser exists."""
    resp = ak.get("core/users/", is_superuser="true", is_active="true")
    admins = resp.get("results", [])
    if not admins:
        red("No active local superuser found in Authentik.")
        red("Create a break-glass admin account before enforcing Entra-only login:")
        red("  Authentik → Directory → Users → Create → Enable superuser")
        sys.exit(1)
    usernames = [u["username"] for u in admins]
    green(f"  Break-glass account(s) verified: {', '.join(usernames)}")


def _enforce_entra_only_login(ak: AuthentikClient, source_pk: str) -> None:
    """Modify identification stage: add entra-id source, set password_stage=None."""
    # Get the default authentication flow
    auth_flows = ak.get("flows/instances/", designation="authentication").get("results", [])
    if not auth_flows:
        red("No authentication flow found.")
        sys.exit(1)
    flow_pk = auth_flows[0]["pk"]

    # Find the identification stage bound to this flow
    bindings = ak.get("flows/bindings/", target=flow_pk).get("results", [])
    stage_pk = None
    for binding in bindings:
        bound_stage_pk = binding.get("stage")
        if not bound_stage_pk:
            continue
        try:
            stage = ak.get(f"stages/identification/{bound_stage_pk}/")
            if stage.get("pk"):
                stage_pk = bound_stage_pk
                break
        except RuntimeError:
            continue

    if not stage_pk:
        red("Could not find identification stage in authentication flow.")
        sys.exit(1)

    stage = ak.get(f"stages/identification/{stage_pk}/")
    current_sources = stage.get("sources", [])
    if source_pk not in current_sources:
        current_sources.append(source_pk)

    ak.patch(f"stages/identification/{stage_pk}/", {
        "sources": current_sources,
        "password_stage": None,
        "show_source_labels": True,
    })
    green("  Authentication flow updated: Entra ID source added, password stage removed")


def phase5_enforce_entra_only(ak: AuthentikClient, source_pk: str) -> None:
    """Phase 5 orchestrator."""
    step("Phase 5 — Enforce Entra-only login")
    _verify_break_glass_account(ak)
    _enforce_entra_only_login(ak, source_pk)
    green("  Entra-only login enforced. Break-glass admin can still use /if/admin/")


# ── Authentik connection helper ────────────────────────────────────────────────

def connect_authentik(env: EnvFile) -> AuthentikClient:
    """Build AuthentikClient from .env. Verifies connectivity. Exits on failure."""
    token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN")
    if not token:
        red("AUTHENTIK_BOOTSTRAP_TOKEN not set in .env")
        sys.exit(1)
    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    if not public_fqdn:
        red("PUBLIC_FQDN not set in .env")
        sys.exit(1)
    base_url = f"https://{auth_sub}.{public_fqdn}"
    ak = AuthentikClient(base_url, token)
    step(f"Verifying Authentik API at {base_url}")
    try:
        ak.get("core/users/", page_size="1")
        green("  Authentik API OK")
    except Exception as exc:
        red(f"Cannot reach Authentik: {exc}")
        sys.exit(1)
    return ak


# ── --sync implementation ──────────────────────────────────────────────────────

def _resolve_entra_group_ids(gc: GraphClient, group_names: list[str]) -> dict[str, str]:
    """Return {group_name: object_id} map. Warns and skips missing groups."""
    result = {}
    for name in group_names:
        resp = gc.get("groups", **{"$filter": f"displayName eq '{name}'"})
        items = resp.get("value", [])
        if not items:
            yellow(f"  WARNING: Entra group '{name}' not found — skipping")
            continue
        result[name] = items[0]["id"]
        green(f"  Resolved group '{name}' → {items[0]['id']}")
    return result


def _fetch_entra_group_members(gc: GraphClient, group_id: str) -> list[dict]:
    """Return all transitive members of an Entra group (handles pagination).

    Only returns users (filters out other directory objects like groups).
    """
    members = []
    url = f"groups/{group_id}/transitiveMembers"
    while url:
        resp = gc.get(url)
        members.extend(resp.get("value", []))
        next_link = resp.get("@odata.nextLink", "")
        if next_link:
            # nextLink is a full URL — strip the base for our get()
            url = next_link.replace("https://graph.microsoft.com/v1.0/", "")
        else:
            url = None
    # Filter to only user objects
    return [m for m in members if m.get("@odata.type") == "#microsoft.graph.user"]


def _upsert_authentik_user(ak: AuthentikClient, entra_user: dict) -> tuple[str, str]:
    """Create or update an Authentik user from Entra user data.

    Returns (action, pk) where action is 'created', 'updated', or 'unchanged'.
    """
    email = entra_user.get("mail") or entra_user.get("userPrincipalName", "")
    display_name = entra_user.get("displayName", "")
    entra_id = entra_user["id"]
    is_active = entra_user.get("accountEnabled", True)

    if not email:
        yellow(f"  User {entra_id} ({display_name!r}) has no email — creating with display_name as username")
        resp = {"results": []}
    else:
        resp = ak.get("core/users/", email=email)
    existing = resp.get("results", [])

    if existing:
        user = existing[0]
        pk = str(user["pk"])
        updates = {}
        if user.get("name") != display_name:
            updates["name"] = display_name
        if user.get("email") != email:
            updates["email"] = email
        if user.get("is_active") != is_active:
            updates["is_active"] = is_active
        attrs = user.get("attributes", {}) or {}
        if attrs.get("entra_id") != entra_id:
            updates["attributes"] = {**attrs, "entra_id": entra_id}
        if updates:
            ak.patch(f"core/users/{pk}/", updates)
            return "updated", pk
        return "unchanged", pk
    else:
        username = (email.split("@")[0] if email else display_name.replace(" ", ".").lower())
        user = ak.post("core/users/", {
            "username": username,
            "name": display_name,
            "email": email,
            "is_active": is_active,
            "type": "internal",
            "attributes": {"entra_id": entra_id},
        })
        return "created", str(user["pk"])


def _reconcile_group_memberships(
    ak: AuthentikClient,
    group_name: str,
    entra_user_pks: set[str],
) -> None:
    """Add/remove Authentik group members to match Entra group membership."""
    resp = ak.get("core/groups/", name=group_name)
    results = resp.get("results", [])
    if not results:
        yellow(f"  Authentik group '{group_name}' not found — skipping membership sync")
        return
    group_pk = results[0]["pk"]
    group_detail = ak.get(f"core/groups/{group_pk}/")
    current_member_pks = {str(m["pk"]) for m in group_detail.get("users_obj", [])}

    to_add = entra_user_pks - current_member_pks
    to_remove = current_member_pks - entra_user_pks

    for pk in to_add:
        try:
            ak.post(f"core/groups/{group_pk}/add_user/", {"pk": pk})
        except RuntimeError as exc:
            yellow(f"  Warning: could not add user pk={pk} to '{group_name}': {exc}")

    for pk in to_remove:
        try:
            ak.post(f"core/groups/{group_pk}/remove_user/", {"pk": pk})
        except RuntimeError as exc:
            yellow(f"  Warning: could not remove user pk={pk} from '{group_name}': {exc}")

    if to_add or to_remove:
        green(f"  '{group_name}': +{len(to_add)} added, -{len(to_remove)} removed")


def _deactivate_removed_users(
    ak: AuthentikClient,
    active_entra_ids: set[str],
) -> int:
    """Deactivate Authentik users with entra_id attribute not in active_entra_ids.

    Returns count of deactivated users.
    Does NOT delete users — preserves audit trail.
    """
    deactivated = 0
    page = 1
    while True:
        resp = ak.get("core/users/", page=str(page), page_size="100")
        users = resp.get("results", [])
        if not users:
            break
        for user in users:
            entra_id = (user.get("attributes") or {}).get("entra_id")
            if entra_id and entra_id not in active_entra_ids and user.get("is_active"):
                ak.patch(f"core/users/{user['pk']}/", {"is_active": False})
                deactivated += 1
        if not resp.get("next"):
            break
        page += 1
    return deactivated


def run_sync(env: EnvFile) -> None:
    tenant_id = env.get("ENTRA_TENANT_ID")
    client_id = env.get("ENTRA_CLIENT_ID")
    client_secret = env.get("ENTRA_CLIENT_SECRET")
    sync_groups_raw = env.get("ENTRA_SYNC_GROUPS")

    for var, val in [
        ("ENTRA_TENANT_ID", tenant_id),
        ("ENTRA_CLIENT_ID", client_id),
        ("ENTRA_CLIENT_SECRET", client_secret),
        ("ENTRA_SYNC_GROUPS", sync_groups_raw),
    ]:
        if not val:
            red(f"{var} not set — run --setup first")
            sys.exit(1)

    sync_group_names = [g.strip() for g in sync_groups_raw.split(",") if g.strip()]

    step("Connecting to Microsoft Graph (client credentials)")
    gc = GraphClient.from_client_credentials(tenant_id, client_id, client_secret)
    ak = connect_authentik(env)

    step("Pass 1 — Resolving Entra group IDs and members")
    group_ids = _resolve_entra_group_ids(gc, sync_group_names)

    # {entra_user_id: [group_names]}
    user_groups: dict[str, list[str]] = {}
    for group_name, group_id in group_ids.items():
        members = _fetch_entra_group_members(gc, group_id)
        for m in members:
            user_groups.setdefault(m["id"], []).append(group_name)
    green(f"  Found {len(user_groups)} unique Entra users across {len(group_ids)} groups")

    step("Pass 2 — Upserting Authentik users")
    counts: dict[str, int] = {"created": 0, "updated": 0, "unchanged": 0}
    # {entra_user_id: authentik_pk}
    user_pk_map: dict[str, str] = {}
    errors = 0

    for entra_user_id in user_groups:
        try:
            entra_user = gc.get(
                f"users/{entra_user_id}",
                **{"$select": "id,displayName,mail,userPrincipalName,accountEnabled"},
            )
        except RuntimeError as exc:
            yellow(f"  Error fetching user {entra_user_id}: {exc}")
            errors += 1
            continue
        try:
            action, pk = _upsert_authentik_user(ak, entra_user)
            counts[action] += 1
            user_pk_map[entra_user_id] = pk
        except RuntimeError as exc:
            upn = entra_user.get("userPrincipalName", entra_user_id)
            yellow(f"  Error upserting {upn}: {exc}")
            errors += 1

    step("Pass 3 — Reconciling group memberships")
    for group_name in sync_group_names:
        if group_name not in group_ids:
            continue
        group_entra_ids = {uid for uid, gnames in user_groups.items() if group_name in gnames}
        ak_pks = {user_pk_map[eid] for eid in group_entra_ids if eid in user_pk_map}
        _reconcile_group_memberships(ak, group_name, ak_pks)

    active_entra_ids = set(user_groups.keys())
    deactivated = _deactivate_removed_users(ak, active_entra_ids)

    green(
        f"\nSync complete: +{counts['created']} created  "
        f"~{counts['updated']} updated  "
        f"-{deactivated} deactivated  "
        f"{counts['unchanged']} unchanged"
    )
    if errors:
        yellow(f"  {errors} per-user error(s) occurred — check output above")
        sys.exit(1)


# ── --setup main ───────────────────────────────────────────────────────────────

def run_setup(env: EnvFile) -> None:
    tenant_id = env.get("ENTRA_TENANT_ID")
    if not tenant_id:
        red("ENTRA_TENANT_ID is not set in .env")
        red("Set it to your Azure Tenant ID (Entra ID → Overview → Tenant ID) and re-run.")
        sys.exit(1)

    app_name = env.get("ENTRA_APP_NAME") or "Authentik-Sync"

    # Prompt for group names
    default_group = "openirvana-homies"
    access_group_raw = input(f"Primary access group name [{default_group}]: ").strip()
    access_group = access_group_raw or default_group
    env.force_set("ENTRA_ACCESS_GROUP", access_group)

    extra_raw = input("Additional groups to sync (comma-separated, or Enter to skip): ").strip()
    sync_groups = [access_group]
    if extra_raw:
        sync_groups += [g.strip() for g in extra_raw.split(",") if g.strip()]
    env.force_set("ENTRA_SYNC_GROUPS", ",".join(sync_groups))

    # Connect to Authentik early — verify break-glass before doing any Graph work
    ak = connect_authentik(env)
    _verify_break_glass_account(ak)

    # Build redirect URIs
    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    tailnet_fqdn = env.get("TAILNET_FQDN") or ""
    redirect_uris = [f"https://{auth_sub}.{public_fqdn}/source/oauth/callback/entra-id/"]
    if tailnet_fqdn:
        redirect_uris.append(f"https://{auth_sub}.{tailnet_fqdn}/source/oauth/callback/entra-id/")

    # Device-code login
    step("Phase 1 — Azure device-code authentication")
    gc = GraphClient(tenant_id)
    gc.authenticate()

    client_id, client_secret = phase1_app_registration(gc, env, app_name, redirect_uris)
    phase2_entra_group(gc, env, access_group)
    source_pk = phase3_authentik_source(ak, tenant_id, client_id, client_secret)
    phase4_access_policy(ak, access_group)
    phase5_enforce_entra_only(ak, source_pk)

    # Clear local-login-restored flag if it was set by undo-entra.py
    env.force_set("ENTRA_LOCAL_LOGIN_RESTORED", "")

    green("\n==> setup-entra.py --setup complete.")
    green(f"    Access group: {access_group}")
    green(f"    Synced groups: {', '.join(sync_groups)}")
    green(f"    To restore local logins: python3 scripts/undo-entra.py {env.path}")
    green(f"    To sync group members:   python3 scripts/setup-entra.py --sync {env.path}")


# ── Argument parsing ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="setup-entra.py",
        description="Authentik ↔ Microsoft Entra ID optional federation",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--setup", action="store_true", help="One-time interactive setup")
    mode.add_argument("--sync", action="store_true", help="Sync Entra group members → Authentik")
    parser.add_argument(
        "env_path", nargs="?",
        default=str(Path(__file__).parent.parent / ".env"),
        help="Path to .env file (default: ../.env relative to script)",
    )
    return parser.parse_args()


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    env_path = Path(args.env_path)
    if not env_path.exists():
        red(f".env file not found: {env_path}")
        return 1
    env = EnvFile(env_path)

    if args.setup:
        run_setup(env)
    else:
        run_sync(env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
