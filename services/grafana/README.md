# grafana

<!-- TODO: one-line description -->

## Access

| URL | Auth |
|-----|------|
| `https://metrics.{PUBLIC_FQDN}` | Authentik forward-auth (session required). |
| `http://metrics.{TAILNET_FQDN}` | Authentik forward-auth (session required). |

## Environment variables

| Variable | Description |
|----------|-------------|
| `GRAFANA_SUBDOMAIN` | External subdomain slug (default: `metrics`) |

## Initial setup

1. Update `.env` / `unified-stack/.env` with required values.
2. Bring up the service:
   ```bash
   docker compose up -d grafana
   ```
3. <!-- TODO: first-run steps (create admin user, run migrations, etc.) -->

## Notes

- Internal port: `3000`
- Data persisted to `/dock/data/grafana`, config to `/dock/conf/grafana`.
