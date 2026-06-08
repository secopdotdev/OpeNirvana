# kafka

<!-- TODO: one-line description -->

## Access

| URL | Auth |
|-----|------|
| `https://kafka.{PUBLIC_FQDN}` | Authentik forward-auth (session required). |
| `http://kafka.{TAILNET_FQDN}` | Authentik forward-auth (session required). |

## Environment variables

| Variable | Description |
|----------|-------------|
| `KAFKA_SUBDOMAIN` | External subdomain slug (default: `kafka`) |

## Initial setup

1. Update `.env` / `unified-stack/.env` with required values.
2. Bring up the service:
   ```bash
   docker compose up -d kafka
   ```
3. <!-- TODO: first-run steps (create admin user, run migrations, etc.) -->

## Notes

- Internal port: `80`
- Data persisted to `/dock/data/kafka`, config to `/dock/conf/kafka`.
