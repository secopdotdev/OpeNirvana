#!/usr/bin/env python3
"""utils_entra - Authentik <-> Microsoft Entra federation.

Behavior preserved from setup-entra.py (deleted in Task 8). The previous
parse_args() and main() are removed; set-auth.py owns argparse and calls
run_setup/run_sync/run_report/run_update_policies directly.

msal is imported lazily inside GraphClient.authenticate /
from_client_credentials so that hosts without msal installed can still run
non-entra subcommands of set-auth.py.
"""


import sys

try:
    import yaml as _yaml  # pyright: ignore[reportMissingImports]  # optional dep; guarded by _HAS_YAML
    _HAS_YAML = True
except ImportError:
    _yaml = None  # type: ignore[assignment]
    _HAS_YAML = False

try:
    from profiles import rbac_category as _rbac_category
    _HAS_PROFILES = True
except ImportError:
    def _rbac_category(service: str) -> "Optional[str]":  # type: ignore[misc]
        return None
    _HAS_PROFILES = False

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

from utils import (
    EnvFile, AuthentikClient, red, green, yellow, step, container_state,
    discover_app_access_groups, resolve_admin_token,
)


# ── Manifest helpers ───────────────────────────────────────────────────────────
# Written to scripts/output/entra-setup-manifest.json after each entra-setup / entra-nesting run.
# Allows undo-entra.py to remove exactly the artifacts we created (was_created_by_us=true).
# Merge rule: first creation sets was_created_by_us=true; re-runs only update last_confirmed_at.

_MANIFEST_VERSION = 1


def _manifest_path(env: "EnvFile") -> Path:
    return Path(__file__).resolve().parent / "output" / "entra-setup-manifest.json"


def _now_iso() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_manifest(path: Path) -> dict:
    """Load existing manifest or return an empty-skeleton dict."""
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            yellow(f"  WARNING: manifest at {path} is corrupt — starting fresh")
    return {
        "schema_version": _MANIFEST_VERSION,
        "created_at": _now_iso(),
        "last_run_at": _now_iso(),
        "entra_app_registrations": [],
        "entra_groups": [],
        "authentik_sources": [],
        "authentik_groups": [],
        "authentik_expression_policies": [],
        "authentik_policy_bindings": [],
    }


def _save_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest["last_run_at"] = _now_iso()
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    green(f"  Manifest written → {path}")


def _merge_entra_group(manifest: dict, group_id: str, display_name: str, was_created: bool, group_type: str = "service") -> None:
    """Upsert an Entra group entry. Never overwrites was_created_by_us once set to true."""
    for entry in manifest["entra_groups"]:
        if entry.get("id") == group_id:
            entry["last_confirmed_at"] = _now_iso()
            entry["display_name"] = display_name
            if was_created:
                entry["was_created_by_us"] = True
            return
    manifest["entra_groups"].append({
        "id": group_id,
        "display_name": display_name,
        "type": group_type,
        "was_created_by_us": was_created,
        "created_at": _now_iso(),
        "last_confirmed_at": _now_iso(),
    })


def _merge_authentik_group(manifest: dict, pk: str, name: str, was_created: bool) -> None:
    for entry in manifest["authentik_groups"]:
        if entry.get("pk") == pk:
            entry["last_confirmed_at"] = _now_iso()
            if was_created:
                entry["was_created_by_us"] = True
            return
    manifest["authentik_groups"].append({
        "pk": pk, "name": name,
        "was_created_by_us": was_created,
        "created_at": _now_iso(), "last_confirmed_at": _now_iso(),
    })


def _merge_authentik_source(manifest: dict, pk: str, slug: str, was_created: bool) -> None:
    for entry in manifest["authentik_sources"]:
        if entry.get("pk") == pk:
            entry["last_confirmed_at"] = _now_iso()
            if was_created:
                entry["was_created_by_us"] = True
            return
    manifest["authentik_sources"].append({
        "pk": pk, "slug": slug,
        "was_created_by_us": was_created,
        "created_at": _now_iso(), "last_confirmed_at": _now_iso(),
    })


def _merge_authentik_policy(manifest: dict, pk: str, name: str, was_created: bool) -> None:
    for entry in manifest["authentik_expression_policies"]:
        if entry.get("pk") == pk:
            entry["last_confirmed_at"] = _now_iso()
            if was_created:
                entry["was_created_by_us"] = True
            return
    manifest["authentik_expression_policies"].append({
        "pk": pk, "name": name,
        "was_created_by_us": was_created,
        "created_at": _now_iso(), "last_confirmed_at": _now_iso(),
    })


def _merge_authentik_binding(manifest: dict, pk: str, policy_pk: str, target_pk: str, was_created: bool) -> None:
    for entry in manifest["authentik_policy_bindings"]:
        if entry.get("pk") == pk:
            entry["last_confirmed_at"] = _now_iso()
            if was_created:
                entry["was_created_by_us"] = True
            return
    manifest["authentik_policy_bindings"].append({
        "pk": pk, "policy_pk": policy_pk, "target_pk": target_pk,
        "was_created_by_us": was_created,
        "created_at": _now_iso(), "last_confirmed_at": _now_iso(),
    })


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
        import msal  # pyright: ignore[reportMissingImports]  # optional Entra-only dep (lazy import; see ADR-0001 exception)
        app = msal.PublicClientApplication(
            _AZ_CLI_CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
        if "error" in flow:
            red(f"Device flow error: {flow.get('error_description', flow['error'])}")
            sys.exit(1)
        print(f"\n{flow['message']}\n")
        expires_in = flow.get("expires_in")
        if expires_in:
            deadline = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
            yellow(
                f"  Device code valid for ~{expires_in // 60} min — "
                f"complete sign-in before {deadline:%H:%M:%S} local time, "
                f"or this step fails with 'authorization pending'."
            )
        result = app.acquire_token_by_device_flow(flow)
        if "error" in result:
            err = result.get("error", "")
            desc = result.get("error_description", err)
            red(f"Authentication failed: {desc}")
            if "authorization" in err or "70016" in desc or "expired" in err:
                yellow("  The device code expired before sign-in completed.")
                yellow("  Re-run --setup and authenticate immediately when the code appears.")
            sys.exit(1)
        self._token = result["access_token"]
        green("  Microsoft authentication complete")

    @classmethod
    def from_client_credentials(cls, tenant_id: str, client_id: str, client_secret: str) -> "GraphClient":
        """Client-credentials flow — non-interactive, for --sync."""
        import msal  # pyright: ignore[reportMissingImports]  # optional Entra-only dep (lazy import; see ADR-0001 exception)
        gc = cls(tenant_id)
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if result is None or "error" in result:
            err = (result or {})
            red(f"Client credentials failed: {err.get('error_description', err.get('error', 'unknown'))}")
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

# Application permission role IDs on Microsoft Graph.
# All are Application type (not Delegated) and require tenant admin consent.
# Grant via: Azure Portal → App registrations → [app] → API permissions → Grant admin consent
# OR: _grant_app_roles() in phase1 handles this automatically during --setup.
#
# Application.ReadWrite.OwnedBy requires the app's service principal to be listed
# as an owner of the App Registration itself (one-time manual step — see README).
_GRAPH_ROLES = {
    "User.Read.All":                "df021288-bdef-4463-88db-98f22de89214",  # --sync: read user profiles
    "Group.ReadWrite.All":          "62a82d76-70ea-41e2-9197-370581804d09",  # --setup: create/manage Entra groups
    "GroupMember.Read.All":         "98830695-27a2-44f7-8c18-0c3ebc9698f6",  # --sync: read group membership
    "Application.Read.All":         "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",  # --setup: read App Registration
    "Application.ReadWrite.OwnedBy":"18a4783c-866b-4cc7-a460-3d5e5662c884",  # --setup: patch redirect URIs
}

# Naming prefixes for per-service group provisioning (phase4b)
_DEFAULT_ENTRA_GROUP_PREFIX = "authentik"   # Entra security group: authentik-{slug}
_DEFAULT_AUTHENTIK_GROUP_PREFIX = "entra"   # Authentik group: entra-{slug}


def _graph_client_for(env: "EnvFile", role: str) -> "Optional[GraphClient]":
    """Return a non-interactive GraphClient for 'read' or 'write' Graph operations.

    read:  prefers ENTRA_READ_CLIENT_*; falls back to ENTRA_WRITE_CLIENT_* so a
           single-app deployment (READ == WRITE) works without duplicating creds.
    write: uses ENTRA_WRITE_CLIENT_* only — no fallback to READ, preserving the
           least-privilege intent of the split.
    Returns None when required credentials are absent (Entra integration is optional).
    """
    tenant_id = env.get("ENTRA_TENANT_ID")
    if not tenant_id:
        return None
    if role == "read":
        client_id = env.get("ENTRA_READ_CLIENT_ID") or env.get("ENTRA_WRITE_CLIENT_ID")
        client_secret = (env.get("ENTRA_READ_CLIENT_SECRET")
                         or env.get("ENTRA_WRITE_CLIENT_SECRET"))
    else:  # write
        client_id = env.get("ENTRA_WRITE_CLIENT_ID")
        client_secret = env.get("ENTRA_WRITE_CLIENT_SECRET")
    if not (client_id and client_secret):
        return None
    return GraphClient.from_client_credentials(tenant_id, client_id, client_secret)


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

def _find_or_create_group(gc: GraphClient, group_name: str, description: str = "") -> tuple[str, bool]:
    """Return (object_id, was_created) for Entra security group, creating it if absent.

    If description is provided and differs from the existing group's description, patches it.
    was_created=True only on the run where the group is first created.
    """
    resp = gc.get("groups", **{"$filter": f"displayName eq '{group_name}'"})
    existing = resp.get("value", [])
    if existing:
        green(f"  Entra group '{group_name}' already exists (id={existing[0]['id']})")
        if description and existing[0].get("description") != description:
            gc.patch(f"groups/{existing[0]['id']}", {"description": description})
            green(f"  Updated description for '{group_name}'")
        return existing[0]["id"], False
    body: dict = {
        "displayName": group_name,
        "mailEnabled": False,
        "mailNickname": group_name.replace(" ", "-").lower(),
        "securityEnabled": True,
        "groupTypes": [],
    }
    if description:
        body["description"] = description
    group = gc.post("groups", body)
    green(f"  Created Entra group '{group_name}' (id={group['id']})")
    return group["id"], True


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

    Returns (client_id, client_secret). Writes ENTRA_READ_CLIENT_ID and ENTRA_READ_CLIENT_SECRET to .env.
    When ENTRA_READ_CLIENT_ID is set (or legacy ENTRA_CLIENT_ID), looks up the App Registration
    by appId to reconcile redirect URIs — never by display name, which may have drifted from
    ENTRA_APP_NAME. Skips secret creation, SP setup, and admin consent when already set.
    """
    existing_client_id = (env.get("ENTRA_READ_CLIENT_ID")
                          or env.get("ENTRA_CLIENT_ID"))  # legacy fallback

    if existing_client_id:
        # Locate the App Registration by its stable appId, not by display name.
        # ENTRA_APP_NAME in .env may not match the actual registration display name;
        # searching by name would silently create a duplicate App Registration and
        # add the redirect URI to the wrong app.
        resp = gc.get("applications", **{"$filter": f"appId eq '{existing_client_id}'"})
        existing = resp.get("value", [])
        if existing:
            app = existing[0]
            current_uris = app.get("web", {}).get("redirectUris", [])
            missing = [u for u in redirect_uris if u not in current_uris]
            if missing:
                gc.patch(f"applications/{app['id']}", {
                    "web": {"redirectUris": current_uris + missing}
                })
                green(f"  Added {len(missing)} redirect URI(s) to App Registration (appId={existing_client_id})")
            else:
                green(f"  App Registration redirect URIs already up to date")
            green(f"  App Registration '{app['displayName']}' (appId={existing_client_id})")
        else:
            yellow(f"  WARNING: No App Registration found for appId={existing_client_id} — ENTRA_READ_CLIENT_ID may be stale")
        green("  ENTRA_READ_CLIENT_ID already set — skipping client secret + admin consent")
        return existing_client_id, (env.get("ENTRA_READ_CLIENT_SECRET")
                                    or env.get("ENTRA_CLIENT_SECRET"))  # legacy fallback

    object_id, client_id = _find_or_create_app(gc, app_name, redirect_uris)
    client_secret = _add_client_secret(gc, object_id)
    env.force_set("ENTRA_READ_CLIENT_ID", client_id)
    env.force_set("ENTRA_READ_CLIENT_SECRET", client_secret)

    sp_id = _get_or_create_service_principal(gc, client_id)
    graph_sp_id = _get_graph_sp_id(gc)
    _grant_app_roles(gc, sp_id, graph_sp_id)

    return client_id, client_secret


# ── Phase 2 orchestrator ───────────────────────────────────────────────────────

def phase2_entra_group(
    gc: GraphClient,
    env: EnvFile,
    access_group_name: str,
    add_self: bool = True,
) -> str:
    """Create Entra access group, optionally add the authenticated user as first member.

    Returns Entra group object_id.
    add_self=False when running with client credentials — /me is not available and
    there is no delegated user to add.
    """
    step("Phase 2 — Create Entra access group")
    group_id, _ = _find_or_create_group(
        gc, access_group_name,
        description="Members granted access to ALL OpenNirvana Authentik gated applications.",
    )
    if add_self:
        me = _get_me(gc)
        _add_group_member(gc, group_id, me["id"])
        green(f"  Access group ready: '{access_group_name}' ({me.get('userPrincipalName', me['id'])} is a member)")
    else:
        green(f"  Access group ready: '{access_group_name}' (self-add skipped — client credentials)")
    return group_id


# ── Phase 3 — Authentik OIDC source ───────────────────────────────────────────

def _get_source_flow_pks(ak: AuthentikClient) -> tuple[Optional[str], Optional[str]]:
    """Return (authentication_flow_pk, enrollment_flow_pk) for the default source flows.

    Authentik ships with 'default-source-authentication' and 'default-source-enrollment'.
    Both must be set on the OAuth source or the callback returns 'Configured flow does not exist'.

    Also patches default-source-authentication to authentication=none if needed.
    Authentik's factory default is 'require_unauthenticated', which blocks already-logged-in
    users from completing the Entra OAuth callback (they get "Flow does not apply to current
    user" when returning from Microsoft). Setting none lets the ak_is_sso_flow policy alone
    gate the flow, which is the correct guard.
    """
    auth_resp = ak.get("flows/instances/", slug="default-source-authentication")
    auth_results = auth_resp.get("results", [])
    auth_pk = auth_results[0]["pk"] if auth_results else None

    if auth_results and auth_results[0].get("authentication") == "require_unauthenticated":
        ak.patch("flows/instances/default-source-authentication/", {"authentication": "none"})
        green("  Patched default-source-authentication: authentication → none (allows session linking)")

    enroll_resp = ak.get("flows/instances/", slug="default-source-enrollment")
    enroll_results = enroll_resp.get("results", [])
    enroll_pk = enroll_results[0]["pk"] if enroll_results else None

    return auth_pk, enroll_pk


def _find_or_create_authentik_source(
    ak: AuthentikClient,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> tuple[str, bool]:
    """Return (pk, was_created) for Authentik OAuth2 source with slug 'entra-id'.

    user_matching_mode='email_link': links sign-ins to pre-provisioned accounts by email.
    authentication_flow and enrollment_flow must be set — if null, Authentik returns
    'Configured flow does not exist' on every OAuth callback.
    """
    auth_flow_pk, enroll_flow_pk = _get_source_flow_pks(ak)
    if not auth_flow_pk:
        yellow("  WARNING: 'default-source-authentication' flow not found — source callbacks may fail")
    if not enroll_flow_pk:
        yellow("  WARNING: 'default-source-enrollment' flow not found — new-user enrollment may fail")

    existing = ak.get("sources/oauth/", slug="entra-id").get("results", [])
    if existing:
        source = existing[0]
        pk = source["pk"]
        green(f"  Authentik OIDC source 'entra-id' already exists (pk={pk})")
        updates: dict = {}
        if auth_flow_pk and not source.get("authentication_flow"):
            updates["authentication_flow"] = auth_flow_pk
        if enroll_flow_pk and not source.get("enrollment_flow"):
            updates["enrollment_flow"] = enroll_flow_pk
        if updates:
            # sources/oauth/ does not support PATCH (405). GET the full detail
            # object, merge updates, then PUT the complete representation back.
            full = ak.get(f"sources/oauth/{source['slug']}/")
            full.update(updates)
            # GET omits write-only fields — consumer_secret is never echoed back,
            # so re-supply both consumer credentials or the PUT fails with
            # "This field is required."
            full["consumer_key"] = client_id
            full["consumer_secret"] = client_secret
            ak.put(f"sources/oauth/{source['slug']}/", full)
            green(f"  Updated flow(s) on existing source: {list(updates.keys())}")
        return pk, False

    step("Phase 3 — Creating Authentik OIDC source (entra-id)")
    body: dict = {
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
    }
    if auth_flow_pk:
        body["authentication_flow"] = auth_flow_pk
    if enroll_flow_pk:
        body["enrollment_flow"] = enroll_flow_pk
    source = ak.post("sources/oauth/", body)
    green(f"  Created Authentik OIDC source (pk={source['pk']})")
    return source["pk"], True


def phase3_authentik_source(
    ak: AuthentikClient,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> tuple[str, bool]:
    """Phase 3 orchestrator — creates the entra-id source. Returns (source_pk, was_created)."""
    step("Phase 3 — Authentik OIDC source")
    return _find_or_create_authentik_source(ak, tenant_id, client_id, client_secret)


# ── Phase 4 — Access-group policy + flow binding ───────────────────────────────

def _find_or_create_authentik_group(ak: AuthentikClient, group_name: str) -> tuple[str, bool]:
    """Return (pk, was_created) for Authentik group, creating if absent."""
    resp = ak.get("core/groups/", name=group_name)
    existing = resp.get("results", [])
    if existing:
        green(f"  Authentik group '{group_name}' already exists (pk={existing[0]['pk']})")
        return existing[0]["pk"], False
    group = ak.post("core/groups/", {"name": group_name})
    green(f"  Created Authentik group '{group_name}' (pk={group['pk']})")
    return group["pk"], True


def _find_or_create_expression_policy(ak: AuthentikClient, group_name: str) -> tuple[str, bool]:
    """Return (pk, was_created) for expression policy gating on group_name, creating if absent.

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
        return existing[0]["pk"], False
    policy = ak.post("policies/expression/", {
        "name": policy_name,
        "expression": (
            f'return request.user.ak_groups.filter(name="{group_name}").exists()'
        ),
    })
    green(f"  Created expression policy '{policy_name}' (pk={policy['pk']})")
    return policy["pk"], True


def _find_or_create_service_expression_policy(
    ak: AuthentikClient, slug: str, group_name: str, global_group_name: str = ""
) -> tuple[str, bool]:
    """Return (pk, was_created) for 'entra-access-{slug}' expression policy, creating or updating.

    The policy grants access when the user is in group_name (service-specific) OR
    global_group_name (global-access). Always patches existing policies so re-running
    sync keeps expressions up to date.
    """
    for val, label in ((slug, "slug"), (group_name, "group_name")):
        if not re.match(r'^[\w\-]+$', val):
            red(f"Invalid characters in {label} '{val}' (allowed: a-z A-Z 0-9 _ -)")
            sys.exit(1)
    if global_group_name and not re.match(r'^[\w\-]+$', global_group_name):
        red(f"Invalid characters in global_group_name '{global_group_name}'")
        sys.exit(1)

    if global_group_name:
        expression = (
            f'return ('
            f'request.user.ak_groups.filter(name="{group_name}").exists() or '
            f'request.user.ak_groups.filter(name="{global_group_name}").exists()'
            f')'
        )
    else:
        expression = f'return request.user.ak_groups.filter(name="{group_name}").exists()'

    policy_name = f"entra-access-{slug}"
    resp = ak.get("policies/expression/", name=policy_name)
    existing = resp.get("results", [])
    if existing:
        pk = existing[0]["pk"]
        if existing[0].get("expression") != expression:
            ak.patch(f"policies/expression/{pk}/", {"expression": expression})
            green(f"  Updated expression policy '{policy_name}'")
        else:
            green(f"  Expression policy '{policy_name}' already up to date")
        return pk, False
    policy = ak.post("policies/expression/", {"name": policy_name, "expression": expression})
    green(f"  Created expression policy '{policy_name}' (pk={policy['pk']})")
    return policy["pk"], True


def _find_or_create_policy_binding(
    ak: AuthentikClient,
    policy_pk: str,
    target_pk: str,
    order: int = 0,
) -> tuple[str, bool]:
    """Return (pk, was_created) for policy binding, creating if absent.

    Does NOT filter by target in the GET query: Authentik's GenericFK target filter
    returns HTTP 400 when the target has no prior bindings ("not a valid choice").
    Fetches all bindings for the policy and matches target client-side instead.
    """
    page = 1
    while True:
        resp = ak.get("policies/bindings/", policy=policy_pk, page=str(page), page_size="100")
        for b in resp.get("results", []):
            if str(b.get("target")) == str(target_pk):
                green(f"  Policy binding already exists (pk={b['pk']})")
                return b["pk"], False
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    binding = ak.post("policies/bindings/", {
        "policy": policy_pk,
        "target": target_pk,
        "enabled": True,
        "order": order,
    })
    green(f"  Created policy binding (pk={binding['pk']})")
    return binding["pk"], True


def _find_or_create_group_binding(
    ak: AuthentikClient,
    group_pk: str,
    target_pk: str,
    order: int = 0,
) -> tuple[str, bool]:
    """Return (pk, was_created) for group binding (application-level, not expression policy)."""
    page = 1
    while True:
        resp = ak.get("policies/bindings/", group=group_pk, page=str(page), page_size="100")
        for b in resp.get("results", []):
            if str(b.get("target")) == str(target_pk):
                green(f"  Group binding already exists (pk={b['pk']})")
                return b["pk"], False
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    binding = ak.post("policies/bindings/", {
        "group":   group_pk,
        "target":  target_pk,
        "enabled": True,
        "order":   order,
    })
    green(f"  Created group binding (pk={binding['pk']})")
    return binding["pk"], True


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
    source_pk: str,
) -> tuple[str, str, str]:
    """Phase 4 orchestrator — Authentik group, expression policy, flow + source bindings.

    Binds policy to both the authorization flow (blocks app access) and the Entra ID
    OAuth source (blocks source-level authentication for unprovisioned users).

    Source-level binding: evaluated after email_link resolves request.user to the linked
    Authentik user, so group membership checks work correctly for provisioned users.

    Returns (group_pk, policy_pk, flow_binding_pk).
    """
    step("Phase 4 — Authentik access-group policy")
    auth_flow_pk = _get_authorization_flow_pk(ak)
    group_pk, _ = _find_or_create_authentik_group(ak, access_group_name)
    policy_pk, _ = _find_or_create_expression_policy(ak, access_group_name)
    binding_pk, _ = _find_or_create_policy_binding(ak, policy_pk, auth_flow_pk)
    # Bind to Entra source: prevents users not in the access group from authenticating
    # via the Entra ID source at all, even before reaching an application.
    _find_or_create_policy_binding(ak, policy_pk, source_pk, order=0)
    return group_pk, policy_pk, binding_pk


# ── Compose profile helpers ───────────────────────────────────────────────────

def _read_service_profiles(compose_path: Path) -> dict[str, list[str]]:
    """Parse docker-compose.yml and return {service_name: [profile, ...]}."""
    if not _HAS_YAML:
        yellow("  WARNING: pyyaml not installed — profile groups will be skipped.")
        yellow("  Install with: pip install pyyaml")
        return {}
    if not compose_path.exists():
        yellow(f"  WARNING: docker-compose.yml not found at {compose_path} — profile groups skipped")
        return {}
    assert _yaml is not None  # _HAS_YAML guard above ensures this
    with compose_path.open(encoding="utf-8") as f:
        data = _yaml.safe_load(f)
    services: dict = (data or {}).get("services", {})
    result: dict[str, list[str]] = {}
    for svc_name, svc_cfg in services.items():
        if svc_cfg and "profiles" in svc_cfg:
            profiles = svc_cfg["profiles"]
            if isinstance(profiles, list) and profiles:
                result[svc_name] = [str(p) for p in profiles]
    return result


def _profiles_for_slug(slug: str, service_profiles: dict[str, list[str]]) -> list[str]:
    """Return compose profiles for an Authentik app slug.

    Tries exact match first, then prefix match (e.g. 'wazuh' matches 'wazuh-dashboard').
    """
    if slug in service_profiles:
        return service_profiles[slug]
    for svc_name, profiles in service_profiles.items():
        if svc_name.startswith(f"{slug}-") or slug.startswith(f"{svc_name}-"):
            return profiles
    return []


def _nest_entra_group(gc: GraphClient, parent_id: str, child_id: str, child_name: str) -> None:
    """Add child Entra group as a member of parent Entra group. Silently skips if already nested.

    Retries on 404 Request_ResourceNotFound: Azure AD replication lag after group creation
    means the child may not be visible to Graph API for several seconds after creation.
    """
    for attempt in range(1, 5):
        try:
            gc.post(f"groups/{parent_id}/members/$ref", {
                "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{child_id}"
            })
            green(f"    Nested '{child_name}'")
            return
        except RuntimeError as exc:
            err = str(exc)
            if "already exist" in err.lower() or ("400" in err and "does not exist" not in err.lower()):
                green(f"    '{child_name}' already nested")
                return
            if "404" in err and "does not exist" in err.lower() and attempt < 4:
                delay = attempt * 8
                yellow(f"    Replication lag — retrying '{child_name}' in {delay}s (attempt {attempt}/4)")
                time.sleep(delay)
                continue
            raise


def _get_service_url(slug: str, env: "EnvFile", public_fqdn: str) -> str:
    """Return '{subdomain}.{public_fqdn}' for an Authentik app slug, or '' if not found."""
    env_key = f"{slug.upper().replace('-', '_')}_SUBDOMAIN"
    subdomain = env.get(env_key)
    return f"{subdomain}.{public_fqdn}" if subdomain and public_fqdn else ""


# ── Phase 4b — Per-service access groups ──────────────────────────────────────

def phase4b_service_groups(
    gc: GraphClient,
    ak: AuthentikClient,
    global_group_name: str,
    entra_prefix: str = _DEFAULT_ENTRA_GROUP_PREFIX,
    authentik_prefix: str = _DEFAULT_AUTHENTIK_GROUP_PREFIX,
    env: Optional["EnvFile"] = None,
    profile_infix: str = "profile",
    compose_path: Optional[Path] = None,  # retained for call-site compat, unused
    manifest: Optional[dict] = None,
) -> None:
    """Phase 4b — per-service Entra groups, coarse-category nesting, Authentik groups, policies.

    For each OIDC application (excluding forward-auth):
    - Entra security group '{entra_prefix}-{slug}'
    - Authentik group '{authentik_prefix}-{slug}'
    - Expression policy 'entra-access-{slug}' gating ONLY on the service Authentik group
      (global and category access arrives via Entra transitive-member sync, not Authentik OR-logic)
    - Policy binding on the OIDC app (service-specific access)
    - Global Entra group nested AS A MEMBER OF each service group (transitive members reach all services)
    - Coarse-category profile group '{entra_prefix}-{profile_infix}-{category}' nested AS A MEMBER OF
      each service group in that category (transitive members reach their category's services)

    Category mapping is driven by profiles.py rbac_category() — the single source of truth from
    Sub-project A. Services with no RBAC category (core infra) get service-group pairs and global
    nesting but no category group.
    """
    step("Phase 4b — per-service access groups + coarse-category nesting")

    if not _HAS_PROFILES:
        yellow("  WARNING: profiles.py not importable — RBAC category nesting skipped")

    public_fqdn = env.get("PUBLIC_FQDN") if env else ""

    # Fetch all Authentik apps (superuser_full_list bypasses per-app policy filtering)
    all_apps: list[dict] = []
    page = 1
    while True:
        resp = ak.get(
            "core/applications/",
            page=str(page), page_size="100", superuser_full_list="true",
        )
        all_apps.extend(resp.get("results", []))
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    service_apps = [a for a in all_apps if a["slug"] != "forward-auth"]
    service_apps.sort(key=lambda a: a["slug"])
    green(f"  {len(service_apps)} service applications found")

    # Ensure global Entra group exists — this group is nested INTO every service group
    global_entra_id, global_entra_created = _find_or_create_group(
        gc, global_group_name,
        description=(
            "Global access group. Members reach ALL services transitively — "
            "this group is nested as a member of every authentik-<service> Entra group."
        ),
    )
    if manifest is not None:
        _merge_entra_group(manifest, global_entra_id, global_group_name, global_entra_created, "global")
    global_group_pk, global_ak_created = _find_or_create_authentik_group(ak, global_group_name)
    if manifest is not None:
        _merge_authentik_group(manifest, global_group_pk, global_group_name, global_ak_created)

    # Coarse-category Entra groups are created on-demand and cached here
    category_entra_ids: dict[str, str] = {}

    def _get_or_create_category_group(category: str) -> str:
        if category not in category_entra_ids:
            cat_group_name = f"{entra_prefix}-{profile_infix}-{category}"
            cat_id, cat_created = _find_or_create_group(
                gc, cat_group_name,
                description=(
                    f"RBAC category group for {category!r} services. Members reach all "
                    f"{category} services transitively — nested as a member of each "
                    f"{category} service's Entra group."
                ),
            )
            if manifest is not None:
                _merge_entra_group(manifest, cat_id, cat_group_name, cat_created, "category")
            category_entra_ids[category] = cat_id
        return category_entra_ids[category]

    for app in service_apps:
        slug = app["slug"]
        app_pk = app["pk"]
        app_display_name = app.get("name") or slug
        entra_group_name = f"{entra_prefix}-{slug}"
        ak_group_name = f"{authentik_prefix}-{slug}"

        service_url = _get_service_url(slug, env, public_fqdn) if env else ""
        description = (
            f"Access group for {app_display_name} ({service_url})."
            if service_url else
            f"Access group for {app_display_name}."
        )

        step(f"  Service: {slug}")
        service_entra_id, svc_entra_created = _find_or_create_group(gc, entra_group_name, description=description)
        if manifest is not None:
            _merge_entra_group(manifest, service_entra_id, entra_group_name, svc_entra_created, "service")

        ak_group_pk, ak_group_created = _find_or_create_authentik_group(ak, ak_group_name)
        if manifest is not None:
            _merge_authentik_group(manifest, ak_group_pk, ak_group_name, ak_group_created)

        # Expression policy: checks only the service Authentik group.
        # Global/category access arrives via transitive Entra sync — no OR-logic needed.
        policy_pk, policy_created = _find_or_create_service_expression_policy(ak, slug, ak_group_name)
        if manifest is not None:
            _merge_authentik_policy(manifest, policy_pk, f"entra-access-{slug}", policy_created)

        binding_pk, binding_created = _find_or_create_policy_binding(ak, policy_pk, app_pk, order=0)
        if manifest is not None:
            _merge_authentik_binding(manifest, binding_pk, policy_pk, app_pk, binding_created)

        if service_url:
            launch_url = f"https://{service_url}"
            if (app.get("meta_launch_url") or "") != launch_url:
                ak.patch(f"core/applications/{slug}/", {"meta_launch_url": launch_url})
                green(f"  Updated meta_launch_url → {launch_url}")

        # Nest global Entra group AS A MEMBER OF this service group (correct direction).
        # Transitive members of the service group now include all global-group members.
        _nest_entra_group(gc, service_entra_id, global_entra_id, global_group_name)

        # Nest coarse-category profile group AS A MEMBER OF this service group.
        category = _rbac_category(slug)
        if category:
            cat_entra_id = _get_or_create_category_group(category)
            cat_group_name = f"{entra_prefix}-{profile_infix}-{category}"
            _nest_entra_group(gc, service_entra_id, cat_entra_id, cat_group_name)

    # Bind global Authentik group to forward-auth outpost so its members can use the outpost.
    forward_auth_apps = [a for a in all_apps if a["slug"] == "forward-auth"]
    if forward_auth_apps:
        fa_binding_pk, fa_binding_created = _find_or_create_group_binding(
            ak, global_group_pk, forward_auth_apps[0]["pk"], order=0,
        )
        if manifest is not None:
            _merge_authentik_binding(manifest, fa_binding_pk, global_group_pk, forward_auth_apps[0]["pk"], fa_binding_created)
        green("  Global group bound to forward-auth outpost")

    if category_entra_ids:
        green(f"  Category groups provisioned: {', '.join(sorted(category_entra_ids.keys()))}")


# ── run_nesting — standalone entra-nesting subcommand ─────────────────────────

def run_nesting(env: EnvFile) -> int:
    """Provision Entra group nesting: Global Access + coarse-category groups → service groups.

    Requires ENTRA_WRITE_CLIENT_ID/SECRET + ENTRA_TENANT_ID. Idempotent and safe to re-run.
    Skips silently when credentials are absent (Entra integration is optional).
    """
    gc = _graph_client_for(env, "write")
    if gc is None:
        yellow("  ENTRA_WRITE_CLIENT_ID/SECRET not configured — skipping nesting provisioning")
        return 0

    ak = connect_authentik(env)
    entra_prefix     = env.get("ENTRA_GROUP_PREFIX")                       or _DEFAULT_ENTRA_GROUP_PREFIX
    authentik_prefix = env.get("AUTHENTIK_GROUP_PREFIX")                   or _DEFAULT_AUTHENTIK_GROUP_PREFIX
    profile_infix    = env.get("ENTRA_PROFILE_INFIX")                      or "profile"
    global_group_name = env.get("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME") or ""
    if not global_group_name:
        yellow("  ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME not set — defaulting to 'Global Access'")
        global_group_name = "Global Access"

    m_path = _manifest_path(env)
    manifest = _load_manifest(m_path)
    phase4b_service_groups(
        gc, ak, global_group_name,
        entra_prefix, authentik_prefix,
        env=env, profile_infix=profile_infix,
        manifest=manifest,
    )
    _save_manifest(manifest, m_path)
    return 0


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
    """Modify identification stage: add entra-id source, clear password stage, remove user fields.

    Setting user_fields=[] removes the email/username input entirely — only the Entra
    source button is shown. Authentik 2024.2+ auto-redirects to the source when there is
    exactly one source, no password stage, and no user fields to collect.
    Break-glass admin access is unaffected: /if/admin/ bypasses this flow.
    """
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
        "user_fields": [],
    })
    green("  Authentication flow updated: Entra ID source added, user fields cleared, password stage removed")


def _disable_password_change_for_entra_users(ak: AuthentikClient) -> None:
    """Block Entra-provisioned users from setting or changing their Authentik password.

    Adds an expression policy to:
    - 'stage_configuration' flows whose slug/name contains 'password' (Change Password UI)
    - All 'recovery' flows (Forgot Password / unauthenticated password reset)

    Users with the 'entra_id' attribute (set by --sync) are blocked from these flows,
    forcing exclusive Entra authentication with no local password bypass.
    """
    policy_name = "entra-deny-password-change"
    resp = ak.get("policies/expression/", name=policy_name)
    existing = resp.get("results", [])
    if existing:
        policy_pk = existing[0]["pk"]
        green(f"  Expression policy '{policy_name}' already exists (pk={policy_pk})")
    else:
        policy = ak.post("policies/expression/", {
            "name": policy_name,
            "expression": (
                "# Block Entra-provisioned users from setting a local Authentik password.\n"
                "# Users synced from Entra have the 'entra_id' attribute set during --sync.\n"
                "if request.user.attributes.get(\"entra_id\"):\n"
                "    return False\n"
                "return True"
            ),
        })
        policy_pk = policy["pk"]
        green(f"  Created expression policy '{policy_name}' (pk={policy_pk})")

    bound = 0

    # Block authenticated users from changing their password via user settings
    stage_config_flows = ak.get("flows/instances/", designation="stage_configuration").get("results", [])
    for flow in stage_config_flows:
        slug = flow.get("slug", "")
        name = flow.get("name", "")
        if "password" in slug.lower() or "password" in name.lower():
            _, _ = _find_or_create_policy_binding(ak, policy_pk, flow["pk"], order=0)
            green(f"  Bound to change-password flow '{slug}'")
            bound += 1

    # Block unauthenticated password reset (Forgot Password)
    recovery_flows = ak.get("flows/instances/", designation="recovery").get("results", [])
    for flow in recovery_flows:
        _, _ = _find_or_create_policy_binding(ak, policy_pk, flow["pk"], order=0)
        green(f"  Bound to recovery flow '{flow.get('slug', flow['pk'])}'")
        bound += 1

    if bound == 0:
        yellow("  No password-related flows found — policy created but not yet bound to any flow")
    else:
        green(f"  Entra users blocked from password change/recovery ({bound} flow(s))")


def phase5_enforce_entra_only(ak: AuthentikClient, source_pk: str) -> None:
    """Phase 5 orchestrator."""
    step("Phase 5 — Enforce Entra-only login")
    _verify_break_glass_account(ak)
    _enforce_entra_only_login(ak, source_pk)
    _disable_password_change_for_entra_users(ak)
    green("  Entra-only login enforced. Break-glass admin can still use /if/admin/")


# ── Authentik connection helper ────────────────────────────────────────────────

def connect_authentik(env: EnvFile) -> AuthentikClient:
    """Build AuthentikClient from .env. Verifies connectivity. Exits on failure."""
    token = resolve_admin_token(env)
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


def run_report(env: EnvFile) -> int:
    """Print read-only user × application access control table (Authentik-only)."""
    ak = connect_authentik(env)

    step("Fetching Authentik users")
    users: list[dict] = []
    page = 1
    while True:
        resp = ak.get("core/users/", page=str(page), page_size="100")
        for u in resp.get("results", []):
            if not u["username"].startswith("ak-outpost-"):
                users.append(u)
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    users.sort(key=lambda u: u["username"])
    green(f"  {len(users)} users")

    step("Fetching groups and memberships")
    # Build user_pk → set of group names by iterating groups and their members
    user_group_names: dict[str, set[str]] = {str(u["pk"]): set() for u in users}
    page = 1
    while True:
        resp = ak.get("core/groups/", page=str(page), page_size="100")
        for g in resp.get("results", []):
            detail = ak.get(f"core/groups/{g['pk']}/")
            for member in detail.get("users_obj", []):
                m_pk = str(member["pk"])
                if m_pk in user_group_names:
                    user_group_names[m_pk].add(g["name"])
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    step("Fetching applications")
    apps: list[dict] = []
    page = 1
    while True:
        # superuser_full_list=true — see phase4b_service_groups for rationale.
        resp = ak.get(
            "core/applications/",
            page=str(page), page_size="100", superuser_full_list="true",
        )
        for a in resp.get("results", []):
            if a["slug"] != "forward-auth":
                apps.append(a)
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    apps.sort(key=lambda a: a["slug"])
    green(f"  {len(apps)} applications")

    step("Checking application access policies")
    app_required = discover_app_access_groups(ak, apps)

    # Column widths
    user_w = max((len(u["username"]) for u in users), default=8)
    slug_ws = [max(len(a["slug"]), 6) for a in apps]

    # Header
    print()
    print("=" * 80)
    print("  Access Control Report")
    print("=" * 80)
    header = f"  {'Username':<{user_w}}  "
    for i, app in enumerate(apps):
        header += f"{app['slug']:<{slug_ws[i]}}  "
    print(header)
    print("  " + "-" * (len(header) - 2))

    for user in users:
        u_pk = str(user["pk"])
        u_groups = user_group_names.get(u_pk, set())
        row = f"  {user['username']:<{user_w}}  "
        for i, app in enumerate(apps):
            required = app_required.get(app["pk"], [])
            if not required:
                cell = "open"
            elif any(g in u_groups for g in required):
                cell = "YES"
            else:
                cell = "no"
            row += f"{cell:<{slug_ws[i]}}  "
        print(row)

    print()
    print("  Group memberships:")
    for user in users:
        u_groups = user_group_names.get(str(user["pk"]), set())
        glist = ", ".join(sorted(u_groups)) if u_groups else "(none)"
        print(f"    {user['username']}: {glist}")

    print()
    print("  Legend:  open = no access policy  |  YES = access granted  |  no = access denied")
    print()
    return 0


def _discover_service_group_pairs(
    ak: AuthentikClient,
    entra_prefix: str = _DEFAULT_ENTRA_GROUP_PREFIX,
    authentik_prefix: str = _DEFAULT_AUTHENTIK_GROUP_PREFIX,
) -> list[tuple[str, str]]:
    """Return [(entra_group_name, authentik_group_name)] for all service apps in Authentik.

    Derives names from configured prefixes and each app's slug. Groups for apps that
    don't yet exist in Entra or Authentik are included — _resolve_entra_group_ids and
    _reconcile_group_memberships will warn and skip them gracefully.
    """
    all_apps: list[dict] = []
    page = 1
    while True:
        resp = ak.get(
            "core/applications/",
            page=str(page), page_size="100", superuser_full_list="true",
        )
        all_apps.extend(resp.get("results", []))
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    pairs = []
    for app in all_apps:
        slug = app["slug"]
        if slug == "forward-auth":
            continue
        pairs.append((f"{entra_prefix}-{slug}", f"{authentik_prefix}-{slug}"))
    return pairs


def run_sync(env: EnvFile) -> int:
    """Sync Entra group members into Authentik.

    Requires ENTRA_TENANT_ID + at least one of ENTRA_READ_CLIENT_* or ENTRA_WRITE_CLIENT_*.
    ENTRA_ACCESS_GROUP is no longer required — access is now gated per-service via nested groups.
    Returns 0 on success, 1 on per-user errors.
    """
    gc = _graph_client_for(env, "read")
    if gc is None:
        tenant_id = env.get("ENTRA_TENANT_ID")
        if not tenant_id:
            yellow("  ENTRA_TENANT_ID not set — skipping Entra sync")
        else:
            yellow("  ENTRA_READ_CLIENT_ID/SECRET (or ENTRA_WRITE_CLIENT_ID/SECRET) not set — skipping Entra sync")
        return 0

    entra_prefix     = env.get("ENTRA_GROUP_PREFIX")     or _DEFAULT_ENTRA_GROUP_PREFIX
    authentik_prefix = env.get("AUTHENTIK_GROUP_PREFIX") or _DEFAULT_AUTHENTIK_GROUP_PREFIX

    step("Connecting to Microsoft Graph (client credentials)")
    ak = connect_authentik(env)

    # Build sync pairs: [(entra_group_name, authentik_group_name)]
    # 1. Global access group — synced by name (same in both Entra and Authentik)
    sync_pairs: list[tuple[str, str]] = []
    global_group = (env.get("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME") or "").strip()
    if global_group:
        sync_pairs.append((global_group, global_group))

    # 2. Per-service groups — discovered from Authentik apps at runtime
    step("Discovering per-service group pairs from Authentik apps")
    service_pairs = _discover_service_group_pairs(ak, entra_prefix, authentik_prefix)
    sync_pairs.extend(service_pairs)
    green(f"  {len(service_pairs)} service application group pair(s) discovered")

    # 3. Custom groups from ENTRA_SYNC_GROUPS — user-defined, synced 1:1 by name
    custom_raw = env.get("ENTRA_SYNC_GROUPS")
    if custom_raw:
        custom_groups = [g.strip() for g in custom_raw.split(",") if g.strip()]
        for g in custom_groups:
            sync_pairs.append((g, g))
        if custom_groups:
            green(f"  {len(custom_groups)} custom group(s) from ENTRA_SYNC_GROUPS: {', '.join(custom_groups)}")

    # Deduplicate, preserving order
    seen_pairs: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str]] = []
    for p in sync_pairs:
        if p not in seen_pairs:
            seen_pairs.add(p)
            deduped.append(p)
    sync_pairs = deduped

    step("Pass 1 — Resolving Entra group IDs and members")
    seen_entra: set[str] = set()
    entra_group_names: list[str] = []
    for entra_name, _ in sync_pairs:
        if entra_name not in seen_entra:
            seen_entra.add(entra_name)
            entra_group_names.append(entra_name)
    group_ids = _resolve_entra_group_ids(gc, entra_group_names)

    # {entra_user_id: [entra_group_names_they_belong_to]}
    user_groups: dict[str, list[str]] = {}
    for entra_name in entra_group_names:
        group_id = group_ids.get(entra_name)
        if not group_id:
            continue
        members = _fetch_entra_group_members(gc, group_id)
        for m in members:
            user_groups.setdefault(m["id"], []).append(entra_name)
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
    for entra_name, ak_name in sync_pairs:
        if entra_name not in group_ids:
            continue
        group_entra_ids = {uid for uid, gnames in user_groups.items() if entra_name in gnames}
        ak_pks = {user_pk_map[eid] for eid in group_entra_ids if eid in user_pk_map}
        _reconcile_group_memberships(ak, ak_name, ak_pks)

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
        return 1
    return 0


# ── --setup main ───────────────────────────────────────────────────────────────

def run_setup(env: EnvFile) -> int:
    tenant_id = env.get("ENTRA_TENANT_ID")
    if not tenant_id:
        red("ENTRA_TENANT_ID is not set in .env")
        red("Set it to your Azure Tenant ID (Entra ID → Overview → Tenant ID) and re-run.")
        return 1

    app_name = (env.get("ENTRA_APP_NAME") or "Authentik-Sync").strip("\"'")

    # Global access group: nested into every service group so its members reach all services.
    # No longer a source-level gate group — any Entra user can authenticate; access is
    # per-service-group only.
    global_group_name = env.get("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME") or ""
    if not global_group_name:
        default_global = "Global Access"
        if sys.stdin.isatty():
            raw = input(f"Global access group name [{default_global}]: ").strip()
            global_group_name = raw or default_global
        else:
            global_group_name = default_global
        env.force_set("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME", global_group_name)
    else:
        green(f"  Using ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME={global_group_name!r} from .env")

    # Connect to Authentik early — verify break-glass before any Graph work
    ak = connect_authentik(env)
    _verify_break_glass_account(ak)

    # Build redirect URIs
    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    tailnet_fqdn = env.get("TAILNET_FQDN") or ""
    redirect_uris = [f"https://{auth_sub}.{public_fqdn}/source/oauth/callback/entra-id/"]
    if tailnet_fqdn:
        redirect_uris.append(f"https://{auth_sub}.{tailnet_fqdn}/source/oauth/callback/entra-id/")

    # --setup uses device-code (delegated) auth so Application.* operations work.
    # Client credentials lack Application.* and cannot read/patch the App Registration.
    step("Phase 1 — Azure device-code authentication")
    gc = GraphClient(tenant_id)
    gc.authenticate()

    client_id, client_secret = phase1_app_registration(gc, env, app_name, redirect_uris)
    phase2_entra_group(gc, env, global_group_name, add_self=True)
    source_pk, source_created = phase3_authentik_source(ak, tenant_id, client_id, client_secret)
    entra_prefix      = env.get("ENTRA_GROUP_PREFIX")     or _DEFAULT_ENTRA_GROUP_PREFIX
    authentik_prefix  = env.get("AUTHENTIK_GROUP_PREFIX") or _DEFAULT_AUTHENTIK_GROUP_PREFIX
    profile_infix     = env.get("ENTRA_PROFILE_INFIX")    or "profile"

    m_path = _manifest_path(env)
    manifest = _load_manifest(m_path)
    _merge_authentik_source(manifest, source_pk, "entra-id", source_created)

    phase4b_service_groups(
        gc, ak, global_group_name, entra_prefix, authentik_prefix,
        env=env, profile_infix=profile_infix, manifest=manifest,
    )
    phase5_enforce_entra_only(ak, source_pk)
    _save_manifest(manifest, m_path)

    env.force_set("ENTRA_LOCAL_LOGIN_RESTORED", "")

    green("\n==> entra-setup complete.")
    green(f"    Global access group: {global_group_name}")
    green(f"    To restore local logins: python3 scripts/undo-entra.py {env.path}")
    green(f"    To sync group members:   python3 scripts/set-auth.py entra-sync")
    green(f"    To reprovision nesting:  python3 scripts/set-auth.py entra-nesting")
    return 0


# ── --update-policies ─────────────────────────────────────────────────────────

def run_update_policies(env: EnvFile) -> int:
    """Non-interactively patch every service expression policy and meta_launch_url.

    Only requires AUTHENTIK_BOOTSTRAP_TOKEN — no Entra credentials needed.
    Safe to run on cron alongside entra-sync. Each service policy checks only its
    own Authentik group (global/category access arrives via transitive Entra sync).
    """
    authentik_prefix = env.get("AUTHENTIK_GROUP_PREFIX") or _DEFAULT_AUTHENTIK_GROUP_PREFIX
    public_fqdn      = env.get("PUBLIC_FQDN") or ""

    ak = connect_authentik(env)

    step("Discovering Authentik applications")
    apps: list[dict] = []
    page = 1
    while True:
        resp = ak.get("core/applications/", page=str(page), page_size="100",
                      superuser_full_list="true")
        apps += [a for a in resp.get("results", []) if a["slug"] != "forward-auth"]
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1
    green(f"  {len(apps)} applications")

    step("Patching expression policies and launch URLs")
    for app in apps:
        slug = app["slug"]
        app_pk = app["pk"]
        ak_group_name = f"{authentik_prefix}-{slug}"
        try:
            # No global_group_name — policy checks only service group.
            # Re-running this patches existing OR-logic policies to single-group.
            _, _ = _find_or_create_service_expression_policy(ak, slug, ak_group_name)
        except RuntimeError as exc:
            yellow(f"  {slug}: {exc}")
        service_url = _get_service_url(slug, env, public_fqdn) if public_fqdn else ""
        if service_url:
            launch_url = f"https://{service_url}"
            if (app.get("meta_launch_url") or "") != launch_url:
                try:
                    ak.patch(f"core/applications/{slug}/", {"meta_launch_url": launch_url})
                    green(f"  {slug}: meta_launch_url → {launch_url}")
                except RuntimeError as exc:
                    yellow(f"  {slug}: meta_launch_url update failed: {exc}")

    green("  Done")
    return 0


# ── Argument parsing ───────────────────────────────────────────────────────────

