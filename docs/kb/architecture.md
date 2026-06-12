---
type: reference
title: "architecture"
tags: [type/reference]
created: 2026-06-11
updated: 2026-06-11
---

# Architecture

## Modules

| Module | Purpose |
|---|---|
| `tailscale-ingress` | WireGuard VPN netns anchor; provides the network namespace through which Caddy receives traffic from the Tailnet and Cloudflare-proxied internet |
| `caddy` | Custom-built reverse proxy: Crowdsec bouncer, Coraza OWASP WAF, Souin cache, Brotli compression, L4 proxy, forward-auth to Authentik outpost; sole TLS terminator |
| `crowdsec` | Behavioral threat detection LAPI; parses Caddy/Falco/Zeek/auth logs; pushes IP ban decisions back to the Caddy bouncer; consumes external blocklists |
| `authentik-server` + `authentik-worker` | SSO identity provider: OIDC + SAML; issues tokens; manages users, groups, flows, and outpost configuration |
| `authentik-proxy` | Forward-auth outpost; receives `X-Forwarded-*` headers from Caddy and enforces auth for non-OIDC apps |
| `postgres` | Shared Postgres 16 + pgvector cluster; per-app databases and roles; no published ports |
| `redis` | Shared Redis 7; Authentik sessions and cache; no published ports |
| `openbao` | OpenBao 2.4.1 (digest-pinned) secrets backend; KV v2; file storage on the `security` network; replaces direct `.env` secret handling in production |
| `falco` | eBPF-based runtime container security monitor; detects terminal shell exec, write-below-root, exec-from-tmp, unexpected outbound connections, unauthorized Docker API calls |
| `zeek` | Network security monitor in cluster mode; produces `conn`, `dns`, `ssl`, `notice`, `intel` logs in JSON; Intel framework consumes URLhaus/Feodo/CrowdStrike feeds |
| `wazuh-manager` + `wazuh-indexer` (×3) + `wazuh-dashboard` | SIEM: Wazuh Manager correlates Falco/Zeek/Caddy/Crowdsec/Cloudflare events; three-node OpenSearch indexer cluster; Kibana-style dashboard |
| `socket-proxy-ro` | Read-only Docker API proxy (Falco inspection); blocks write operations at proxy layer |
| `socket-proxy-rw` | Read-write Docker API proxy (autoheal + dockhand); scoped to restart and inspect operations only |
| `autoheal` | Monitors container health via `socket-proxy-rw`; restarts unhealthy containers automatically |
| `gluetun` | ProtonVPN WireGuard tunnel container; all `--profile media` services route their internet traffic through this netns |
| Media services | Jellyfin (direct play/transcode), Jellyseerr (request management), Prowlarr/Radarr/Sonarr/Lidarr (indexing + *arr), qBittorrent (downloads), FlareSolverr (Cloudflare challenge solver; internal only) |
| Productivity services | Nextcloud + notify-push (file sync + Rust push daemon), Tandoor (recipe manager), Vikunja (task manager), AFFiNE (note/whiteboard), ntfy (push notifications) |
| `coturn` | TURN/STUN server for Nextcloud Talk WebRTC; binds to host network on UDP 3478/5349 + media ports 49152–49200 |

## Data flow

### Public request path

```
Internet → Cloudflare (WAF/DDoS edge) → Host UFW (443/80 allow from CF ranges)
  → tailscale-ingress netns → Caddy
    → @cloudflare matcher (source-IP allowlist)
    → Crowdsec bouncer (IP reputation check; block if banned)
    → Coraza WAF (OWASP CRS rules; block if rule match)
    → Authentik forward-auth (or native-OIDC redirect)
    → Upstream app container (on isolated Docker network)
```

### Tailnet request path

```
Tailscale client → tailscale-ingress (WireGuard) → Caddy (*.tailnet.domain)
  → Crowdsec bouncer → App container
```

### Logging pipeline

```
caddy (access.log JSON)
crowdsec (decisions.log JSONL)
falco (events.log JSON)
zeek (conn/dns/ssl/notice .log JSON)
cloudflare (logpush HTTPS) → bind-mounted log files on host
  → Wazuh Agent (file-tail, host-level; reads outside Docker)
  → wazuh-manager → wazuh-indexer (3-node OpenSearch)
  → wazuh-dashboard
```

### Bootstrap order

```
tailscale-ingress → postgres + redis → authentik-migration
  → authentik-server → authentik-worker → caddy
  wazuh-indexer (3 nodes) → wazuh-manager → wazuh-dashboard
  (falco, zeek, crowdsec, openbao start independently after data layer)
```

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| Docker Compose | v2 (plugin) | Container orchestration; no Swarm |
| Caddy | custom build | Reverse proxy with Crowdsec, Coraza, Souin, Brotli, L4, forward-auth modules |
| Authentik | latest stable | Identity provider (OIDC + forward-auth) |
| Postgres | 16 | Shared relational DB with pgvector extension |
| Redis | 7 | Session store and cache |
| OpenBao | 2.4.1 (digest-pinned) | Secrets backend (KV v2) |
| Wazuh | 4.x | SIEM (OpenSearch-backed) |
| Falco | latest stable | eBPF runtime security |
| Zeek | latest stable | Network security monitoring |
| Crowdsec | latest stable | IP reputation LAPI + Caddy bouncer |
| Tailscale | latest stable | VPN ingress sidecar |
| ProtonVPN / gluetun | latest stable | WireGuard VPN tunnel for media stack |
| Python | 3.9+ | Operator scripts in `scripts/` |
| pytest | latest | Test framework for scripts |

## Networks

Eight Docker networks enforce security boundaries:

| Network | Members | Purpose |
|---|---|---|
| `ingress` | Caddy, Tailscale-ingress, Crowdsec | External traffic entry; only Caddy bridges to other networks |
| `auth-internal` | Authentik server, worker | Internal Authentik communication; isolated from app traffic |
| `data` | Postgres, Redis | Database layer; no direct app access except via declared membership |
| `security` | Wazuh, Falco, Crowdsec, OpenBao, socket-proxies | Security tooling; isolated from app traffic |
| `media` | Jellyfin, *arr stack | Media services; no cross-contamination with productivity apps |
| `apps` | Nextcloud, productivity apps | User-facing productivity; separate from media |
| `cloud` | Nextcloud, notify-push | Nextcloud push notification path |
| `oidc-clients` | OIDC-aware apps + Authentik proxy | OIDC token exchange network |

## Security model

| Threat | Mitigation |
|---|---|
| DDoS | Cloudflare edge WAF + rate-limit; Crowdsec community blocklists; Caddy `@cloudflare` source-IP allowlist |
| Credential stuffing | Authentik rate-limit + MFA enforcement; Crowdsec `auth-brute` scenario |
| Web exploits (SQLi, XSS, RCE) | Coraza OWASP CRS in Caddy; per-app egress isolation |
| Container escape | Falco eBPF (terminal-shell, write-below-root); host UFW; kernel hardening; UID 1010, read-only rootfs, cap_drop ALL, no-new-privileges, seccomp |
| DNS exfiltration | Zeek `dns.log` + Intel framework hits → Wazuh correlation + Crowdsec egress rules |
| C2 beaconing | Zeek `ssl.log` JA3/JA4 anomaly detection |
| Supply-chain | Falco (exec-from-/tmp, unexpected outbound); digest-pinned images (OpenBao) |
| Docker socket abuse | Falco unauthorized API detection; RO/RW proxy split limits blast radius |
| `.env` leak | `.gitignore`; CI secret scanning; all secrets regenerable by `gen-secrets.py` |
| DB exfiltration | Data-layer network isolation; per-app Postgres roles; no published ports |
| Lateral movement | Apps never share network layers; only Caddy is multi-homed; Crowdsec intra-network rules |
| Log tampering | Logs bind-mounted to host; Wazuh Agent reads outside Docker namespace |
| Backup failure | `pg-backup` level-12 Wazuh alert; pruning skips on failure |
| Tailscale key leak | Ephemeral keys with reusable-disabled; rotation via `gen-secrets.py --set` |
| Authentik outage | `AUTHENTIK_BOOTSTRAP_TOKEN` API fallback; direct `psql` reset procedure documented in README |

## Design decisions

No formal ADRs are recorded in `active/decisions/` for this project as of SHA `13869a251c1eec812656933c69d87d47fa3a67be`. Key architectural choices embedded in the implementation:

- **Custom Caddy build over nginx/Traefik** — single binary bundles Crowdsec bouncer, Coraza WAF, Souin, and forward-auth; fewer moving parts than a plugin-laden nginx.
- **OpenBao over HashiCorp Vault** — open-source fork; digest-pinned; identical KV v2 API.
- **Single-host Docker Compose over K8s/K3s** — acceptable for homelab scale; eliminates CNI/etcd complexity; Compose profiles substitute for namespace isolation.
- **Tailscale netns sidecar** — avoids host-network mode; Caddy receives traffic through the VPN netns without exposing the Docker socket or host ports to WireGuard peers.
