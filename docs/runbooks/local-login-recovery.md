# Local-login recovery (break-glass)

Authentik (federated to Entra) is the sole interactive login for the stack.
If Authentik or Entra is **down** and you must log in without SSO, revert local
login per service below.

**Prefer the Tailnet path first.** Every UI service is also reachable on its
`*.{TAILNET_FQDN}` (Tailscale) URL, which is **not** publicly exposed. Reaching a
service over Tailnet avoids the public-exposure concern entirely and is the
preferred break-glass route before re-enabling any local form.

## Disable the whole lockdown

Set `SSO_LOCKDOWN_ENABLED=false` in `.env`, then revert the per-service flags
below and `docker compose up -d <service>`.

## Per-service revert

| Service | Restore local login |
|---|---|
| **grafana** | set `GF_AUTH_DISABLE_LOGIN_FORM=false` in `docker-compose.yml` → `docker compose up -d grafana` |
| **vikunja** | set `VIKUNJA_AUTH_LOCAL_ENABLED=true` in `.env` → `docker compose up -d vikunja` |
| **nextcloud** | `docker exec --user www-data nextcloud php occ config:system:set hide_login_form --value false --type boolean` — OR, without reverting, reach `https://cloud.{FQDN}/login?direct=1` (the form still renders even while hidden — instant break-glass) |
| **immich** | API keys keep working regardless of `passwordLogin`. Re-enable: `GET` then `PUT` `http://immich-server:2283/api/system-config` with `passwordLogin.enabled=true` using header `x-api-key: $IMMICH_API_KEY` (run `setup-sso-lockdown.py` logic in reverse, or via the admin UI once OAuth is back) |

## Documented exceptions (local login intentionally kept)

- **jellyfin** — native apps/clients authenticate against local Jellyfin users;
  OIDC is plugin-based and disabling local login breaks those clients. Local
  login stays; access is still gated by Authentik forward-auth at the edge.
- **\*arr (prowlarr/radarr/sonarr/lidarr)** — already `AuthenticationMethod=None`
  (no local login form at all); they are gated by Authentik forward-auth +
  gluetun. Nothing to disable.
- **tandoor** — auth is configured in-app (django-allauth). If the pinned image
  exposes no safe "disable local login" toggle, local login is **kept**
  (fail-safe) and it remains OIDC-capable; it stays gated at the edge.

## Notes

- `setup-sso-lockdown.py` is **fail-safe**: it never disables local login on a
  service unless that service's OIDC is confirmed working first.
- API-key / token auth (jellyseerr↔*arr, notify_push, exporters) is
  non-interactive and is **never** touched by the lockdown.
