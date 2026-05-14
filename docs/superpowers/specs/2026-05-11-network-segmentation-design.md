# Network Micro-Segmentation Design

> For agentic workers: design document. Implementation plan will be generated via `superpowers:writing-plans`.

**Goal:** Replace the flat 7-network topology with semantically named, purpose-bounded networks that limit lateral movement between security zones, fix two silent bugs (Caddy/Souin Redis and authentik-migration), and enable Redis caching for n8n, Tandoor, and Vikunja.

---

## Current State

Seven Docker bridge networks exist, with imprecise naming and over-broad membership:

| Name | Subnet | Purpose |
|------|--------|---------|
| ingress | 10.0.10.0/24 | Edge traffic |
| auth | 10.0.11.0/24 | Auth services |
| data | 10.0.12.0/24 | Databases |
| observability | 10.0.13.0/24 | Security/monitoring |
| apps | 10.0.14.0/24 | Media services (misleading name) |
| productivity | 10.0.15.0/24 | App services (misleading name) |
| talk | 10.0.16.0/24 | Nextcloud Talk |

**Known bugs to fix in this change:**
- `tailscale-ingress` is not on `data`, so Caddy (which shares its netns) cannot reach Redis — the Souin cache plugin silently fails.
- `authentik-migration` has no `networks` key in docker-compose.yml, so it cannot reach Postgres or Redis during schema migrations.

---

## New Network Topology

Eight networks: seven renamed/repurposed + one new (`oidc-clients`). Subnets are unchanged — only names and memberships change.

| Name | Subnet | Services |
|------|--------|---------|
| ingress | 10.0.10.0/24 | tailscale-ingress, crowdsec, authentik-proxy, authentik-server |
| auth-internal | 10.0.11.0/24 | authentik-server, authentik-worker |
| data | 10.0.12.0/24 | postgres, redis, authentik-server, authentik-worker, authentik-proxy, authentik-migration, nextcloud, affine, immich-server, n8n, tandoor, vikunja, **tailscale-ingress** (new) |
| security | 10.0.13.0/24 | tailscale-ingress, crowdsec, dockhand, falco, falcosidekick, falcosidekick-ui, socket-proxy-ro, socket-proxy-rw, wazuh-manager, wazuh-indexer-1/2/3, wazuh-dashboard, wazuh-init, wazuh-security-init, redis-falco, zeek-logs, zeek |
| media | 10.0.14.0/24 | tailscale-ingress, gluetun (+ *arr/flaresolverr via `service:gluetun`), jellyfin, jellyseerr |
| apps | 10.0.15.0/24 | tailscale-ingress, nextcloud, affine, vikunja, tandoor, immich-server, immich-machine-learning, n8n, ntfy |
| cloud | 10.0.16.0/24 | tailscale-ingress, nextcloud, spreed-signaling, janus |
| oidc-clients | 10.0.17.0/24 | authentik-server, nextcloud, affine, vikunja, tandoor, immich-server, jellyfin |

### Network Name Mapping (renames)

| Old | New | Change type |
|-----|-----|------------|
| auth | auth-internal | rename |
| observability | security | rename |
| apps | media | rename |
| productivity | apps | rename |
| talk | cloud | rename |
| — | oidc-clients | new |

Subnets are preserved — existing static IPv4 addresses remain valid after the rename.

---

## Security Rationale

### Why `oidc-clients`?

OIDC-capable apps (Nextcloud, AFFiNE, Vikunja, Tandoor, Immich, Jellyfin) need to reach `authentik-server:9000` for token exchange. Currently they get full membership on the `auth` network, which also contains `authentik-worker` — the task queue that processes email, webhooks, and background policies. A compromised app on `auth` could reach the worker.

`oidc-clients` contains only `authentik-server`, not `authentik-worker`. A compromised OIDC app gains access to the token endpoint but not to the auth backplane.

### Why remove `auth` membership from app services?

Services previously joined `auth` so they could reach `authentik-server`. After this change they join `oidc-clients` instead. The result is identical reachability to authentik-server but no access to authentik-worker or the auth IP range in general.

### Why `authentik-proxy` on `ingress` instead of `auth`?

Caddy (running in `tailscale-ingress` netns) calls `authentik-proxy:9000` for `forward_auth`. Caddy is on `ingress`. Putting authentik-proxy on `ingress` keeps Caddy ↔ proxy communication on the edge network where it belongs, and removes the proxy from the auth zone.

### Why `tailscale-ingress` on `data`?

Caddy shares tailscale-ingress's network namespace. Caddy's Souin cache plugin talks to Redis on `data`. Without this membership, the cache silently falls back to in-memory (losing persistence across restarts, bypassing TTL controls). This has been broken since the Souin cache was introduced.

---

## IP Address Plan

### Existing IPs preserved (subnets renamed, no address change)

| Service | Network | IP |
|---------|---------|-----|
| tailscale-ingress | ingress | 10.0.10.200 |
| crowdsec | ingress | 10.0.10.21 |
| crowdsec | security (was observability) | 10.0.13.20 |
| tailscale-ingress | security (was observability) | 10.0.13.200 |
| tailscale-ingress | media (was apps) | 10.0.14.200 |
| gluetun | media (was apps) | 10.0.14.30 |
| jellyfin | media (was apps) | 10.0.14.21 |
| jellyseerr | media (was apps) | 10.0.14.22 |
| tailscale-ingress | apps (was productivity) | 10.0.15.200 |
| ntfy | apps (was productivity) | 10.0.15.20 |
| tandoor | apps (was productivity) | 10.0.15.21 |
| vikunja | apps (was productivity) | 10.0.15.22 |
| affine | apps (was productivity) | 10.0.15.23 |
| immich-server | apps (was productivity) | 10.0.15.24 |
| n8n | apps (was productivity) | 10.0.15.25 |
| tailscale-ingress | cloud (was talk) | 10.0.16.200 |
| nextcloud | cloud (was talk) | 10.0.16.20 |
| spreed-signaling | cloud (was talk) | 10.0.16.30 |
| janus | cloud (was talk) | 10.0.16.31 |
| authentik-server | auth-internal (was auth) | 10.0.11.20 |
| authentik-worker | auth-internal (was auth) | 10.0.11.21 |

### IPs that change (services gaining/losing networks)

| Service | Change | New IP |
|---------|--------|--------|
| authentik-proxy | leave auth, join ingress | ingress: 10.0.10.22 |
| authentik-server | join ingress | ingress: 10.0.10.50 |
| authentik-server | join oidc-clients | oidc-clients: 10.0.17.10 |
| tailscale-ingress | leave auth, join data | data: 10.0.12.200 |
| nextcloud | leave apps/media (10.0.14.20), join apps/apps | apps: 10.0.15.26 |
| nextcloud | join oidc-clients | oidc-clients: 10.0.17.20 |
| affine | join oidc-clients | oidc-clients: 10.0.17.21 |
| vikunja | join oidc-clients | oidc-clients: 10.0.17.22 |
| tandoor | join oidc-clients | oidc-clients: 10.0.17.23 |
| immich-server | join oidc-clients | oidc-clients: 10.0.17.24 |
| jellyfin | join oidc-clients | oidc-clients: 10.0.17.25 |
| authentik-migration | join data (was missing) | data: dynamic |

---

## Redis Enablement

All three services (n8n, Tandoor, Vikunja) are already on the `data` network and can reach Redis. This section adds the env vars to activate caching. Two services (Tandoor, Vikunja) get new DB index assignments; n8n Redis queue mode is deferred (see note below).

| Service | DB index | Env var | Purpose |
|---------|---------|---------|---------|
| Tandoor | 6 | `REDIS_DB_TANDOOR` | Django cache backend |
| Vikunja | 7 | `REDIS_DB_VIKUNJA` | Key-value session/data cache |

### Existing Redis DB assignments (unchanged)

| DB | Service |
|----|---------|
| 0 | authentik |
| 1 | Caddy/Souin cache |
| 2 | AFFiNE |
| 3 | Nextcloud |
| 4 | Immich |
| 5 | Falco (redis-falco, separate container) |

### Tandoor — Django cache Redis config

```
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}
REDIS_DB=${REDIS_DB_TANDOOR}
```

### Vikunja — Key-value Redis config

Vikunja config follows the `VIKUNJA_<SECTION>_<KEY>` env var pattern. Two sections control Redis: `keyvalue` (selects the backend) and `redis` (connection details):

```
VIKUNJA_KEYVALUE_TYPE=redis
VIKUNJA_REDIS_HOST=redis
VIKUNJA_REDIS_PORT=6379
VIKUNJA_REDIS_PASSWORD=${REDIS_PASSWORD}
VIKUNJA_REDIS_DB=${REDIS_DB_VIKUNJA}
```

### n8n — Redis queue mode (deferred)

n8n's only Redis use case is Bull queue mode (`EXECUTIONS_MODE=queue`), which requires a **separate worker container**. Enabling queue mode without a worker causes workflow executions to queue indefinitely and never run. n8n already has `N8N_RUNNERS_ENABLED: "true"` for JavaScript/Python task-runner isolation.

Redis queue mode for n8n is deferred to a future change that also adds the worker service. No n8n env vars change in this PR.

### `.env.example` additions

```
REDIS_DB_TANDOOR=6
REDIS_DB_VIKUNJA=7
```

---

## Complete Service Network Membership (post-change)

| Service | Networks |
|---------|---------|
| tailscale-ingress | ingress, security, media, apps, cloud, data |
| caddy | network_mode: service:tailscale-ingress |
| crowdsec | ingress, security |
| socket-proxy-ro | security |
| socket-proxy-rw | security |
| autoheal | security |
| postgres | data |
| redis | data |
| wazuh-init | security |
| wazuh-indexer-1/2/3 | security |
| wazuh-security-init | security |
| wazuh-manager | security |
| wazuh-dashboard | security |
| falco | security |
| zeek | security |
| zeek-logs | security |
| dockhand | security |
| falcosidekick | security |
| falcosidekick-ui | security |
| redis-falco | security |
| authentik-migration | data |
| authentik-server | ingress, auth-internal, data, oidc-clients |
| authentik-worker | auth-internal, data |
| authentik-proxy | ingress, data |
| nextcloud | apps, cloud, data, oidc-clients |
| coturn | host networking |
| spreed-signaling | cloud |
| janus | cloud |
| gluetun | media |
| prowlarr/radarr/sonarr/lidarr/flaresolverr/qbittorrent | network_mode: service:gluetun |
| jellyfin | media, oidc-clients |
| jellyseerr | media |
| ntfy | apps |
| tandoor | apps, data, oidc-clients |
| vikunja | apps, data, oidc-clients |
| affine | apps, data, oidc-clients |
| immich-server | apps, data, oidc-clients |
| immich-machine-learning | apps |
| n8n | apps, data |

---

## Wazuh Indexer TLS Certificate Impact

The Wazuh init script hard-codes IP SANs for the indexer nodes:

```
IP.1=10.0.13.31   # wazuh-indexer-1
IP.2=10.0.13.33   # wazuh-indexer-2
IP.3=10.0.13.34   # wazuh-indexer-3
```

These IPs are on the observability/security subnet (10.0.13.0/24). The rename from `observability` to `security` preserves the subnet, so all existing static IPs and TLS certificates remain valid. **No cert regeneration required.**

---

## Deployment Procedure

Because Docker Compose networks are referenced by name in service definitions, all changes must be applied atomically with a full stack restart:

```bash
# 1. Push updated docker-compose.yml to streamer
# 2. On streamer:
cd /home/rooter/git/finnsbeincaddy/unified-stack
docker compose down
docker compose up -d
```

Docker will destroy and recreate all network bridges with new names. Containers reconnect to the renamed networks on startup. No data volumes are affected.

**Risk:** brief downtime during the restart (expected: 2–5 minutes for all services to become healthy).

---

## Files Changed

| File | Change |
|------|--------|
| `unified-stack/docker-compose.yml` | Rename networks; update all service network blocks; add oidc-clients; add Redis env vars to tandoor and vikunja; add data to tailscale-ingress and authentik-migration; move nextcloud from media to apps |
| `unified-stack/.env.example` | Add REDIS_DB_TANDOOR, REDIS_DB_VIKUNJA |
| `unified-stack/README.md` | Update network diagram |
