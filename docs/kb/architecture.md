# OpeNirvana — Architecture

## What is this

OpeNirvana is the public mirror of a profile-gated, self-hosted security and productivity Docker stack targeting Ubuntu hosts. It provides a modular, compose-driven platform with SSO via Authentik, TLS ingress via a custom Caddy build, and approximately 30 integrated services spanning identity, observability, productivity, and media — all gated behind Docker Compose profiles so operators can deploy only the tiers they need.

## Module breakdown

| Name | Purpose |
|---|---|
| caddy | Ingress + TLS termination (custom build: CrowdSec, Coraza WAF, forward-auth, Souin cache, L4 proxy) |
| authentik | Identity provider + SSO (OIDC, forward-auth, Entra federation) |
| tailscale-ingress | Tailnet access + NAT traversal for private service exposure |
| postgres | Shared stateful store (Authentik, Nextcloud, n8n, etc.) |
| redis | Cache + session store |
| crowdsec | WAF + IP reputation agent (integrated into Caddy bouncer) |
| openbao | Secret engine + data encryption at rest |
| profile-resolver (run.sh + profiles.py) | Dependency validation, service graph resolution before compose up |
| observability (metrics, logs, viz) | Prometheus + Alertmanager, Loki + Alloy, Grafana |
| productivity (files, talk, photos, tasks) | Nextcloud + Spreed + Janus + coturn, Immich, Vikunja |
| media (vpn, downloads, movies/tv/audio/stream) | Gluetun, Qbittorrent, Prowlarr, Radarr/Sonarr/Lidarr, Jellyfin |

## Key design decisions

- **Profile-gated deployment:** Services are grouped into Docker Compose profiles; `run.sh` + `profiles.py` resolve the dependency graph and validate profile combinations before any `docker compose up`, preventing partial-up states.
- **Security-first ingress:** Caddy is compiled with CrowdSec bouncer, Coraza WAF (OWASP ruleset), and Souin caching in a single binary — avoiding a separate reverse-proxy hop and keeping the WAF inline with TLS termination.
- **SSO as the integration spine:** Authentik is the single identity authority; all services authenticate via OIDC forward-auth through Caddy, with Entra ID federation available for enterprise identity passthrough.

## Integration points

- **Cloudflare DNS:** DNS-01 ACME challenge for wildcard TLS certificates; requires zone API token.
- **Tailscale:** Authkey enrollment for Tailnet ingress; exposes selected services over Tailscale without public port forwarding.
- **Entra ID (optional):** OIDC federation into Authentik for SSO passthrough from Microsoft identity.
- **External storage:** `MEDIA_PATH` and `DOWNLOADS_PATH` are operator-mounted paths (NAS/external volumes); not managed by compose.
- **Consumers:** All ~30 services delegate authentication to Authentik; Grafana, Nextcloud, Jellyfin, n8n, and Vikunja are the primary end-user surfaces.

## Platform constraints

- Ubuntu 24.04+ required; Docker + Docker Compose (v2 plugin) required. No Kubernetes — pure compose.
- Resource tiers auto-detected from `/proc/meminfo`: 8 GB MICRO → 128+ GB MAX. Optional lower preset blocks in `.env` for smaller hosts.
- Volumes under `/dock/` (OS images, stateful data); `MEDIA_PATH` and `DOWNLOADS_PATH` are operator-mounted externals.
- Cloudflare zone control + DNS-01 ACME required for TLS. Tailscale authkey enrollment required for Tailnet ingress.
- Minimal port-forwarding: 443 TCP required, 80 TCP recommended for ACME redirect; WebRTC ports optional for Nextcloud Talk off-Tailnet.
