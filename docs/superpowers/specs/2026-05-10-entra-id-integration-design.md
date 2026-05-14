# Design: Optional Authentik ↔ Entra ID Integration

**Date:** 2026-05-10  
**Status:** Approved  
**Scope:** `unified-stack/scripts/setup-entra.py`, `unified-stack/scripts/undo-entra.py`, `.env.example`, `README.md`

---

## Overview

An **optional** script pair that federates Authentik with Microsoft Entra ID (formerly Azure AD).
The core unified stack operates identically whether or not this integration is configured — no
existing service, compose file, or Caddyfile entry changes when this is skipped.

When enabled, Entra ID becomes the **exclusive identity source**: all users authenticate via
Microsoft. A single Entra group (`openirvana-homies` by default) gates access to every service.
A local break-glass Authentik admin account remains active for recovery.

### What gets automated

| Script | Mode | What it does |
|--------|------|--------------|
| `setup-entra.py` | `--setup` | Creates App Registration in Entra ID, configures Authentik OIDC source, enforces Entra-only login, binds access-group policy to all services |
| `setup-entra.py` | `--sync` | Reconciles Entra group members → Authentik users/groups; safe to run on cron |
| `undo-entra.py` | *(no args)* | Restores local Authentik logins without touching Entra credentials or synced users |

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `ENTRA_TENANT_ID` in `.env` | Azure portal → Entra ID → Overview → Tenant ID |
| Microsoft account with **Global Admin** or **Application Administrator** role | Needed for device-code login during `--setup`; used interactively, never stored |
| `pip install msal` on the machine running the script | Only third-party dependency; handles OAuth2 device-code and client-credentials flows |
| Authentik running and `AUTHENTIK_BOOTSTRAP_TOKEN` set in `.env` | Same requirement as `setup-oidc.py` |
| Break-glass local admin account active in Authentik | Script verifies this before enforcing Entra-only login |

---

## `.env` variables

```bash
# ── Entra ID integration (optional — setup-entra.py fills most of these) ──────
ENTRA_TENANT_ID=                  # set manually before running --setup
ENTRA_APP_NAME=Authentik-Sync     # display name for the App Registration (default shown)
ENTRA_ACCESS_GROUP=openirvana-homies  # Entra group that gates all service access
ENTRA_SYNC_GROUPS=                # comma-separated group names to sync (filled by --setup)
ENTRA_CLIENT_ID=                  # filled by --setup
ENTRA_CLIENT_SECRET=              # filled by --setup
ENTRA_LOCAL_LOGIN_RESTORED=       # set to "true" by undo-entra.py; cleared by --setup
```

---

## `--setup` flow (one-time, interactive)

Idempotent: each phase checks its `.env` output vars before executing. Re-running after a
partial failure resumes from the first incomplete phase.

### Phase 1 — Azure App Registration

1. Read `ENTRA_TENANT_ID` from `.env`; exit with instructions if absent.
2. Verify break-glass Authentik account is active — refuse to proceed if not.
3. Prompt: *"Primary access group name [openirvana-homies]:"* → write `ENTRA_ACCESS_GROUP`.
4. Prompt: *"Additional groups to sync (comma-separated, or Enter to skip):"* → append to `ENTRA_SYNC_GROUPS`. `ENTRA_ACCESS_GROUP` is always included.
5. Launch **MSAL device-code flow**: print `https://microsoft.com/devicelogin` + code; wait for completion.
6. Create (or find existing) App Registration named `ENTRA_APP_NAME`:
   - Add a client secret (2-year expiry).
   - Request application permissions: `User.Read.All`, `Group.Read.All`, `GroupMember.Read.All`.
   - Grant admin consent inline: create the service principal for the app, then call `POST /servicePrincipals/{sp_id}/appRoleAssignments` for each required role on the Microsoft Graph service principal (requires Global Admin role on the authenticated account — exits with portal URL if 403).
   - Add Authentik OIDC callback redirect URIs: `https://{auth_sub}.{public_fqdn}/source/oauth/callback/entra-id/` and `https://{auth_sub}.{tailnet_fqdn}/source/oauth/callback/entra-id/` (if `TAILNET_FQDN` set).
   - Write `ENTRA_CLIENT_ID` and `ENTRA_CLIENT_SECRET` to `.env`.

### Phase 2 — Create access group in Entra ID

7. Create (or find existing) Entra security group named `ENTRA_ACCESS_GROUP`.
8. Fetch the UPN of the device-code authenticated user (`/me`).
9. Add that user as the group's first member.

### Phase 3 — Authentik OIDC source

10. Create (or find existing) OAuth2 source with slug `entra-id`:
    - Authorization URL: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
    - Token URL: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
    - JWKS URL: `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`
    - User-info URL: `https://graph.microsoft.com/oidc/userinfo`
    - Scopes: `openid profile email`
    - `user_matching_mode`: match by email (links sign-ins to pre-provisioned accounts)
11. Create Authentik property mappings for each group in `ENTRA_SYNC_GROUPS`, mapping the Entra group `object_id` claim to the corresponding Authentik group name.

### Phase 4 — Access-group policy

12. Create Authentik group named `ENTRA_ACCESS_GROUP` (or find existing by name).
13. Create a group-membership expression policy: evaluates `True` only when the authenticating user is a member of this group.
14. Bind the policy to the **default authorization flow** — one binding covers every service (Nextcloud, Jellyfin, Immich, Vikunja, AFFiNE, Tandoor, Wazuh, etc.) without modifying individual application configs.

### Phase 5 — Enforce Entra-only login

15. Modify the default Authentik authentication flow to require the `entra-id` source — removes the password login stage for non-admin users, leaving only the "Sign in with Microsoft" button.
16. Print a summary of all created resources and the `undo-entra.py` recovery command.

---

## `--sync` flow (repeatable, non-interactive)

Reads all credentials from `.env`. Designed for cron or manual re-runs.

**Auth:** MSAL `ConfidentialClientApplication` with `ENTRA_CLIENT_ID` + `ENTRA_CLIENT_SECRET` (client-credentials flow). Token cached in memory for the run duration.

### Pass 1 — Resolve groups

- For each name in `ENTRA_SYNC_GROUPS`, resolve the Entra object ID via Graph (`/groups?$filter=displayName eq '{name}'`).
- Fetch all transitive members per group (`/groups/{id}/transitiveMembers`), building a `{entra_user_id → [group_names]}` map.

### Pass 2 — Upsert users in Authentik

For each Entra user in any synced group, fetch `displayName`, `mail`, `userPrincipalName`, `accountEnabled` from Graph:

- **Create** if no Authentik user with matching email exists. Sets username, name, email, `is_active`. Stores `entra_id` as a custom Authentik user attribute for stable cross-reference.
- **Update** if name, email, or active state differs from the Authentik record.
- **Deactivate** (not delete) any Authentik user with an `entra_id` attribute who is no longer a member of any synced group — preserves audit trail.

### Pass 3 — Reconcile group memberships

For each synced Authentik group:
- Add users present in the Entra group but absent from the Authentik group.
- Remove users present in the Authentik group but no longer in the Entra group.

### Output

```
Sync complete: +3 created  ~1 updated  -2 deactivated  47 unchanged
```

Exits `0` on full success, `1` if any per-user errors occurred (suitable for cron alerting). Respects `Retry-After` headers from Graph API rate limiting.

---

## `undo-entra.py` — restore local logins

Runnable any time, requires only `AUTHENTIK_BOOTSTRAP_TOKEN` and a reachable Authentik instance. No Graph API calls — works even when Entra ID is unavailable.

1. Verify Authentik is reachable and the bootstrap token is valid.
2. Disable the `entra-id` OAuth2 source (`enabled: false`) — stops new Entra logins without deleting config.
3. Unbind the access-group policy from the default authorization flow — restores open access for local accounts.
4. Restore the password login stage to the default authentication flow — local accounts can log in again.
5. Print the break-glass account username and remind operator to verify it works before closing terminal.
6. Write `ENTRA_LOCAL_LOGIN_RESTORED=true` to `.env` — `setup-entra.py --setup` detects this on re-run and re-applies from current state rather than re-creating resources.

**Does NOT:** delete the App Registration, remove synced users, or clear `.env` credentials.

---

## Error handling

| Scenario | Behaviour |
|----------|-----------|
| `ENTRA_TENANT_ID` not set | Exit 1 with instructions before any API calls |
| Break-glass account not active | Refuse Phase 5; print remediation steps |
| Device-code token expires mid-run | Exit with message; re-run resumes from first incomplete phase |
| Admin consent returns 403 | Exit with Azure portal URL and required permissions listed |
| Graph API rate limit | Respect `Retry-After` header, sleep and retry |
| Single user Graph error during sync | Log UPN + error, skip user, continue; exit 1 at end |
| `msal` not installed | Exit 1 with `pip install msal` command before any other work |

---

## README changes

- New **optional** callout section in the Authentik integration Mermaid diagram: Entra ID shown as a dashed upstream node with label `optional · setup-entra.py`.
- New quickstart **Step 7** (clearly marked optional): prerequisites table, before/after instructions, recovery command.
- `undo-entra.py` documented inline in the troubleshooting section under "Authentik admin lockout."

---

## Files created / modified

| File | Change |
|------|--------|
| `unified-stack/scripts/setup-entra.py` | New |
| `unified-stack/scripts/undo-entra.py` | New |
| `unified-stack/.env.example` | Add Entra ID section (commented out, clearly optional) |
| `unified-stack/README.md` | Update Mermaid chart + add Step 7 + troubleshooting entry |
