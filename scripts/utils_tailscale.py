#!/usr/bin/env python3
"""utils_tailscale.py — Tailscale ACL and auth key provisioning.

Integrates the stack's RBAC model (profiles.CATEGORIES) with the Tailscale
control plane:
  1. Builds an ACL policy: tagOwners for all 7 RBAC categories + infra tags
     (tag:ingress, tag:docker); optional per-category user groups populated
     from Entra group members via the existing GraphClient; ACL rules granting
     tailnet ingress access per group (or autogroup:member fallback).
  2. Fetches the existing tailnet policy and merges the stack-generated content
     non-destructively (operator-authored rules, tagOwners, ssh, postures, etc.
     are preserved).
  3. Pushes the merged policy via POST /api/v2/tailnet/-/acl.
  4. Creates a reusable pre-authorized auth key tagged tag:ingress,tag:docker
     and writes it to TAILSCALE_AUTHKEY in .env only if currently blank.

Ordering requirement: run `set-auth.py tailscale` BEFORE `docker compose up`
so TAILSCALE_AUTHKEY is populated with a properly tagged key before the
tailscale-ingress container starts.

Do NOT use --advertise-tags in TS_EXTRA_ARGS — it triggers a separate
tagOwners ownership check against the key's issuing user (fails for
OAuth-issued keys even when the key already carries those tags).
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from utils import EnvFile, red, green, yellow, step
from profiles import CATEGORIES

# ── Constants ─────────────────────────────────────────────────────────────────

_TOKEN_URL       = "https://api.tailscale.com/api/v2/oauth/token"
_API_BASE        = "https://api.tailscale.com/api/v2"
_INFRA_TAGS      = ["tag:ingress", "tag:docker"]
_KEY_EXPIRY_SECS = 7_776_000  # 90 days — rotate before expiry


# ── Tailscale OAuth 2.0 client ────────────────────────────────────────────────

class TailscaleClient:
    """Minimal Tailscale REST API client (stdlib only, OAuth 2.0 client_credentials)."""

    def __init__(self, client_id: str, client_secret: str, tailnet: str) -> None:
        self._client_id     = client_id
        self._client_secret = client_secret
        self.tailnet        = tailnet
        self._token: Optional[str] = None

    def _ensure_token(self) -> str:
        if self._token:
            return self._token
        body = urllib.parse.urlencode({
            "client_id":     self._client_id,
            "client_secret": self._client_secret,
            "grant_type":    "client_credentials",
        }).encode()
        req = urllib.request.Request(
            _TOKEN_URL, data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"Tailscale OAuth token exchange failed {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Tailscale OAuth: network error: {exc.reason}"
            ) from exc
        try:
            token: str = json.loads(raw)["access_token"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(
                f"Tailscale OAuth: unexpected token response: {exc}"
            ) from exc
        self._token = token
        return token

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url  = f"{_API_BASE}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {self._ensure_token()}",
                "Content-Type":  "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Tailscale API: network error {method} {url}: {exc.reason}"
            ) from exc

    def get_acl(self) -> dict:
        return self._request("GET", f"tailnet/{self.tailnet}/acl")

    def set_acl(self, policy: dict) -> dict:
        return self._request("POST", f"tailnet/{self.tailnet}/acl", policy)

    def list_keys(self) -> list:
        return self._request("GET", f"tailnet/{self.tailnet}/keys").get("keys", [])

    def create_key(
        self,
        tags: list,
        reusable: bool = True,
        ephemeral: bool = False,
        expiry_seconds: int = _KEY_EXPIRY_SECS,
    ) -> str:
        """Create a pre-authorized device key and return the key string."""
        body: dict = {
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable":      reusable,
                        "ephemeral":     ephemeral,
                        "preauthorized": True,
                        "tags":          tags,
                    }
                }
            },
            "expirySeconds": expiry_seconds,
        }
        return self._request("POST", f"tailnet/{self.tailnet}/keys", body)["key"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tailnet_id() -> str:
    """Return the API tailnet identifier.

    Tailscale OAuth clients are scoped to exactly one tailnet; '-' resolves
    to that tailnet without requiring us to parse TAILNET_FQDN.
    """
    return "-"


# ── ACL policy builder ────────────────────────────────────────────────────────

def build_acl_policy(
    categories: tuple[str, ...],
    user_groups: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """Build a Tailscale ACL policy dict from the RBAC category list.

    Args:
        categories: CATEGORIES tuple from profiles.py (7 coarse RBAC names).
        user_groups: optional dict mapping category name (or 'global') to a
                     list of Tailscale user email strings. Empty dict or None
                     triggers the autogroup:member fallback ACL rule so the
                     tailnet stays accessible even without Entra creds.

    Returns a JSON-serializable dict ready for POST to /api/v2/tailnet/-/acl.
    This is the stack-owned slice of the policy; pass it to _merge_acl_policy
    before pushing to avoid overwriting operator-authored content.
    """
    # tagOwners — only autogroup:admin may apply any tag in this stack
    tag_owners: dict[str, list[str]] = {}
    for infra_tag in _INFRA_TAGS:
        tag_owners[infra_tag] = ["autogroup:admin"]
    for cat in categories:
        tag_owners[f"tag:{cat}"] = ["autogroup:admin"]

    # groups — per-category + global, populated from Entra when available
    groups: dict[str, list[str]] = {}
    has_groups = False
    if user_groups:
        for key, members in user_groups.items():
            if members:
                groups[f"group:{key}"] = list(members)
                has_groups = True

    # acls — docker inter-service traffic is always allowed;
    # user access is gated per-group or falls back to all tailnet members
    acls: list[dict[str, Any]] = [
        # Docker-tagged devices communicate freely within the tailnet
        {"action": "accept", "src": ["tag:docker"], "dst": ["tag:docker:*"]},
    ]

    if has_groups:
        for key, members in user_groups.items():  # type: ignore[union-attr]
            if members:
                acls.append({
                    "action": "accept",
                    "src":    [f"group:{key}"],
                    "dst":    ["tag:ingress:443", "tag:ingress:80"],
                })
    else:
        # Fallback: any authenticated tailnet member can reach the ingress.
        # Application-layer access control is still enforced by Authentik.
        acls.append({
            "action": "accept",
            "src":    ["autogroup:member"],
            "dst":    ["tag:ingress:443", "tag:ingress:80"],
        })

    return {
        "tagOwners":     tag_owners,
        "groups":        groups,
        "acls":          acls,
        "autoApprovers": {"exitNode": [], "routes": {}},
    }


def _merge_acl_policy(
    existing: dict[str, Any],
    generated: dict[str, Any],
) -> dict[str, Any]:
    """Non-destructively merge stack-generated policy into an existing tailnet policy.

    Only the keys this stack owns are replaced:
    - tagOwners: infra tags (tag:ingress, tag:docker) + RBAC category tags
    - groups: stack-named groups (group:{category}, group:global)
    - acls: rules referencing stack-owned tags/groups are replaced; all other
            operator-authored rules are preserved

    All other top-level keys in the existing policy (ssh, postures, nodeAttrs,
    hosts, autoApprovers for non-stack routes, etc.) are preserved unchanged.
    """
    merged: dict[str, Any] = dict(existing)

    # tagOwners — upsert stack-owned entries, leave operator entries intact
    existing_tag_owners = dict(existing.get("tagOwners") or {})
    existing_tag_owners.update(generated.get("tagOwners") or {})
    merged["tagOwners"] = existing_tag_owners

    # groups — upsert stack-owned entries, leave operator entries intact
    existing_groups = dict(existing.get("groups") or {})
    existing_groups.update(generated.get("groups") or {})
    merged["groups"] = existing_groups

    # acls — identify rules referencing stack-owned tags/groups, remove them,
    # then append the new stack rules. Preserves operator rules for other devices.
    owned_tags  = set((generated.get("tagOwners") or {}).keys())
    owned_groups = set((generated.get("groups") or {}).keys())

    def _refs_stack(rule: dict[str, Any]) -> bool:
        """True if the rule references any stack-owned tag or group."""
        all_refs: list[str] = list(rule.get("src") or []) + list(rule.get("dst") or [])
        for ref in all_refs:
            # Strip port suffix: "tag:ingress:443" → "tag:ingress"
            parts = ref.split(":")
            base  = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else ref
            if base in owned_tags or base in owned_groups:
                return True
        return False

    existing_acls = list(existing.get("acls") or [])
    preserved = [r for r in existing_acls if not _refs_stack(r)]  # type: ignore[arg-type]
    merged["acls"] = preserved + list(generated.get("acls") or [])

    # autoApprovers — preserve existing (we don't manage exit nodes or subnet routes)
    if "autoApprovers" not in existing:
        merged["autoApprovers"] = {"exitNode": [], "routes": {}}

    return merged


# ── Entra → Tailscale user-group bridge ───────────────────────────────────────

def build_user_groups_from_entra(
    env: EnvFile,
    categories: tuple[str, ...],
) -> Optional[dict[str, list[str]]]:
    """Fetch Entra category-group members and return {category: [email, ...]}.

    Return values:
      None   — Entra not configured; caller should use autogroup:member fallback
      {}     — Entra configured but auth/fetches failed; caller should abort
               (fail closed to avoid granting autogroup:member unintentionally)
      {..}   — (partial) success; use for ACL group population

    Uses existing ENTRA_READ_CLIENT_* credentials and GraphClient from
    utils_entra (imported lazily — Entra integration is optional).
    Also fetches ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME members as 'global'.
    """
    tenant_id     = env.get("ENTRA_TENANT_ID")
    client_id     = env.get("ENTRA_READ_CLIENT_ID") or env.get("ENTRA_WRITE_CLIENT_ID")
    client_secret = (env.get("ENTRA_READ_CLIENT_SECRET")
                     or env.get("ENTRA_WRITE_CLIENT_SECRET"))

    if not (tenant_id and client_id and client_secret):
        yellow("  Tailscale: Entra credentials not configured — skipping user group sync")
        return None  # not configured — autogroup:member fallback is intentional

    try:
        from utils_entra import GraphClient
    except ImportError:
        yellow("  Tailscale: utils_entra not importable — skipping user group sync")
        return None

    # GraphClient.from_client_credentials calls sys.exit(1) on auth failure;
    # catch it so a bad/expired token doesn't abort the Entra-independent ACL
    # push and key creation steps that follow in run().
    try:
        gc = GraphClient.from_client_credentials(tenant_id, client_id, client_secret)
    except SystemExit:
        yellow("  Tailscale: Entra authentication failed")
        return {}  # configured but failed — caller aborts

    entra_prefix = env.get("ENTRA_GROUP_PREFIX") or "authentik"
    entra_infix  = env.get("ENTRA_PROFILE_INFIX") or "profile"
    global_name  = env.get("ENTRA_GLOBAL_AUTHENTIK_ACCESS_GROUP_NAME") or "Global Access"

    def _fetch_members(display_name: str) -> list[str]:
        try:
            search = gc.get("groups", **{
                "$filter": f"displayName eq '{display_name}'",
                "$select": "id",
            })
            items = search.get("value", [])
            if not items:
                yellow(f"  Tailscale: Entra group '{display_name}' not found — skipping")
                return []
            gid  = items[0]["id"]
            page = gc.get(
                f"groups/{gid}/transitiveMembers",
                **{"$select": "mail,userPrincipalName"},
            )
            emails: list[str] = []
            while True:
                for member in page.get("value", []):
                    # transitiveMembers returns groups and service principals too;
                    # only include user objects to avoid group mailbox addresses.
                    if member.get("@odata.type") != "#microsoft.graph.user":
                        continue
                    addr = member.get("mail") or member.get("userPrincipalName", "")
                    if addr:
                        emails.append(addr)
                next_link = page.get("@odata.nextLink")
                if not next_link:
                    break
                # nextLink is a full URL — call _request directly to avoid
                # GraphClient.get() prepending the base URL a second time
                page = gc._request("GET", next_link)
            return emails
        except RuntimeError as exc:
            yellow(f"  Tailscale: failed fetching members of '{display_name}': {exc}")
            return []

    result: dict[str, list[str]] = {}

    # Per-category groups: e.g. authentik-profile-netsec
    for cat in categories:
        group_name = f"{entra_prefix}-{entra_infix}-{cat}"
        members    = _fetch_members(group_name)
        if members:
            result[cat] = members

    # Global access group
    global_members = _fetch_members(global_name)
    if global_members:
        result["global"] = global_members

    return result  # may be {} if all fetches failed


# ── Entry point ───────────────────────────────────────────────────────────────

def run(env: EnvFile, sync_entra: bool = True) -> int:
    """Main entry point called from set-auth.py tailscale. Returns exit code."""
    step("Tailscale: loading credentials")
    client_id     = env.get("TAILSCALE_OAUTH_CLIENT_ID")
    client_secret = env.get("TAILSCALE_OAUTH_API_KEY")
    tailnet_fqdn  = env.get("TAILNET_FQDN")

    if not (client_id and client_secret):
        red("TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_API_KEY must be set in .env")
        return 1
    if not tailnet_fqdn:
        red("TAILNET_FQDN must be set in .env")
        return 1

    client = TailscaleClient(client_id, client_secret, tailnet=_tailnet_id())

    step("Tailscale: fetching Entra user groups for ACL")
    user_groups: Optional[dict[str, list[str]]] = None
    if sync_entra:
        entra_result = build_user_groups_from_entra(env, CATEGORIES)
        if entra_result is None:
            # Not configured — autogroup:member fallback is intentional
            yellow("  Entra not configured — ACL will allow all tailnet members")
        elif not entra_result:
            # Configured but all fetches failed — fail closed
            red("  Entra credentials present but no groups resolved")
            red("  Use --skip-entra to explicitly opt into autogroup:member fallback")
            return 1
        else:
            user_groups = entra_result
            green(f"  Entra groups synced: {sorted(user_groups.keys())}")

    step("Tailscale: generating stack ACL slice")
    generated = build_acl_policy(CATEGORIES, user_groups)
    green(
        f"  Generated: {len(generated['tagOwners'])} tagOwners, "
        f"{len(generated['groups'])} groups, "
        f"{len(generated['acls'])} rules"
    )

    step("Tailscale: fetching existing tailnet policy")
    try:
        existing = client.get_acl()
    except RuntimeError as exc:
        red(f"  Failed to fetch existing ACL: {exc}")
        return 1
    green("  Existing policy fetched")

    merged = _merge_acl_policy(existing, generated)
    green(
        f"  Merged: {len(merged.get('tagOwners') or {})} tagOwners, "
        f"{len(merged.get('groups') or {})} groups, "
        f"{len(merged.get('acls') or [])} rules (including preserved operator rules)"
    )

    step("Tailscale: pushing merged ACL policy")
    try:
        client.set_acl(merged)
    except RuntimeError as exc:
        red(f"  Failed to push ACL: {exc}")
        return 1
    green("  ACL policy applied")

    step("Tailscale: ensuring auth key has required tags")
    existing_key = env.get("TAILSCALE_AUTHKEY")
    if existing_key:
        yellow("  TAILSCALE_AUTHKEY already set — skipping key creation")
        yellow("  To rotate: clear TAILSCALE_AUTHKEY in .env then re-run this subcommand")
    else:
        try:
            new_key = client.create_key(_INFRA_TAGS, reusable=True, ephemeral=False)
        except RuntimeError as exc:
            red(f"  Failed to create auth key: {exc}")
            return 1
        env.set_if_blank("TAILSCALE_AUTHKEY", new_key)
        green(f"  Created reusable auth key tagged: {', '.join(_INFRA_TAGS)}")
        green("  TAILSCALE_AUTHKEY written to .env")
        green(
            f"  Key expires in {_KEY_EXPIRY_SECS // 86_400} days"
            " — add a calendar reminder to rotate before expiry"
        )

    green("\nTailscale provisioning complete.")
    return 0
