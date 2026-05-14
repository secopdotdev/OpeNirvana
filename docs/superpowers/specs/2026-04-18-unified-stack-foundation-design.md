# Unified Stack Foundation Design

**Date:** 2026-04-18
**Status:** Draft — pending user review
**Author:** sean@secop.dev + Claude
**Pilot app:** Authentik (SSO layer)
**Out of scope:** Phase 3+ apps (Affine, Nextcloud, media, smart-home) — added onto this foundation later.

---

## 1. Purpose

One repository, one `docker compose up --build` command, producing a fully-hardened self-hosted infrastructure foundation that:

- Terminates public ingress on `*.secop.dev` via Cloudflare + Caddy with TLS, WAF, bot protection, forward-auth, and log pipeline to Wazuh.
- Simultaneously serves the same services on `*.neon-lenok.ts.net` over Tailscale.
- Runs a shared Postgres + Redis so per-app state is minimized.
- Observes every container and the host network with runtime security (Falco) and network monitoring (Zeek), correlated in Wazuh SIEM.
- Is reproducible on any freshly-imaged Ubuntu host via a single `docker-host-config.sh` script.

**Priority order (drives every trade-off):** Functionality > Security > Efficiency > Stability.

---

## 2. Scope

### Pilot (this design)

- Foundation containers: Tailscale ingress sidecar, Caddy (custom build), Crowdsec, Coraza (Caddy plugin, not a container), Falco, Zeek, socket-proxy (RO + RW), Postgres, Redis, Wazuh manager/indexer/dashboard, Autoheal, one-shot init containers (`postgres-init`, `wazuh-init`, `authentik-migration`).
- Pilot application: **Authentik** (authentik-server + authentik-worker).
- Repo artifacts: `docker-compose.yml`, `.env.example`, `build/caddy/` (Dockerfile + plugin list), `templates/` (Caddy, Crowdsec, Falco, Zeek, Postgres init, Wazuh decoders/rules/ISM), `scripts/`, `README.md` (with Mermaid diagrams + `/dock` tree), `docker-host-config.sh`.
- Ubuntu host bootstrap via `docker-host-config.sh` — fully idempotent, safe to re-run.

### Out of scope

- Phase 3+ apps (media stack, productivity, smart-home).
- Data migration from existing `AAAIbeVibin/errythang-compose.yml` (greenfield deploy).
- HSM-backed secrets, immutable-image infra, Anycast DDoS (Cloudflare handles).

---

## 3. Network topology & IP plan

Per-layer `/24`s within `10.0.10.0/24`–`10.0.20.0/24`. Gateway on each is `.10`. Apps `.20+`, DBs `.30+`, sidecars `.200+`.

| Network | CIDR | Gateway | Purpose | Members (pilot) |
|---|---|---|---|---|
| `ingress` | `10.0.10.0/24` | `.10` | Public + Tailnet ingress | tailscale-ingress `.200`, socket-proxy-ro `.21`, crowdsec secondary `.21` |
| `auth` | `10.0.11.0/24` | `.10` | SSO layer | authentik-server `.20`, authentik-worker `.21` |
| `data` | `10.0.12.0/24` | `.10` | Shared stateful | postgres `.30`, redis `.31` |
| `observability` | `10.0.13.0/24` | `.10` | Security, logs, runtime monitoring | crowdsec `.20`, socket-proxy-ro `.21`, socket-proxy-rw `.22`, autoheal `.23`, falco `.24`, wazuh-manager `.30`, wazuh-indexer `.31`, wazuh-dashboard `.32` |
| `media` | `10.0.14.0/24` | `.10` | *reserved (Phase 4)* | — |
| `productivity` | `10.0.15.0/24` | `.10` | *reserved (Phase 5)* | — |
| `smarthome` | `10.0.16.0/24` | `.10` | *reserved (Phase 6)* | — |
| *reserved* | `10.0.17.0/24`–`10.0.20.0/24` | — | Growth | — |

**Convention within each `/24`:** `.10` gateway, `.11`–`.19` reserved (DNS/infra), `.20`–`.29` apps, `.30`–`.39` DBs, `.200`–`.254` sidecars.

**Multi-homing rules:**
- `tailscale-ingress` joins every network Caddy fronts (pilot: `ingress`, `auth`). Adding a future layer = add one network to the sidecar.
- `caddy` uses `network_mode: service:tailscale-ingress` — inherits all sidecar interfaces, no IP of its own.
- `crowdsec` joins `observability` + `ingress`.
- Apps join their own layer + `data` (if Postgres/Redis needed) + `observability` (if socket-proxy-ro needed).
- Apps never join each other's layers. East-west traffic goes via Caddy.
- `zeek` uses `network_mode: host` to tap `docker0` + `br-*` — not assigned a per-layer IP.

IPv4-only. IPv6 deferrable.

---

## 4. Foundation services (pilot day-1)

**18 containers total** (15 foundation + 3 pilot-app; 3 of these are one-shot init containers that exit after success). All referenced by `docker-compose.yml`.

| # | Service | Image | Network (IP) | Role |
|---|---|---|---|---|
| 1 | `tailscale-ingress` | `tailscale/tailscale:latest` | `ingress .200`, `auth .200` | Tailnet presence for Caddy |
| 2 | `caddy` | local build (`build/caddy/Dockerfile`) | `network_mode: service:tailscale-ingress` | TLS termination, WAF (Coraza), Crowdsec bouncer, forward-auth, cache |
| 3 | `crowdsec` | `crowdsecurity/crowdsec:latest` | `observability .20`, `ingress .21` | LAPI, parsers, bouncer decisions |
| 4 | `socket-proxy-ro` | `tecnativa/docker-socket-proxy` | `ingress .21`, `observability .21` | Read-only Docker API |
| 5 | `socket-proxy-rw` | `tecnativa/docker-socket-proxy` | `observability .22` | Read-write Docker API (Autoheal only) |
| 6 | `autoheal` | `willfarrell/autoheal` | `observability .23` | Restarts unhealthy containers labelled `autoheal=true` |
| 7 | `falco` | `falcosecurity/falco:latest` (modern_ebpf) | `observability .24` | Runtime container security monitoring |
| 8 | `zeek` | `zeek/zeek:latest` | `network_mode: host` | Passive network monitoring + Intel framework |
| 9 | `postgres` | `pgvector/pgvector:pg16` | `data .30` | Shared Postgres cluster with pgvector |
| 10 | `redis` | `redis:7-alpine` | `data .31` | Shared Redis with logical DB per app |
| 11 | `wazuh-manager` | `wazuh/wazuh-manager:4.9.2` | `observability .30` | Event ingest, decoders/rules, agent registration |
| 12 | `wazuh-indexer` | `wazuh/wazuh-indexer:4.9.2` | `observability .31` | OpenSearch-based log store |
| 13 | `wazuh-dashboard` | `wazuh/wazuh-dashboard:4.9.2` | `observability .32` | Web UI |
| 14 | `postgres-init` | `postgres:16-alpine` | `data` | One-shot: provisions roles/DBs from `.env` |
| 15 | `wazuh-init` | `alpine:3` + mounted `wazuh-certs-tool.sh` | `observability` | One-shot: generates internal TLS on first boot |
| 16 | `authentik-migration` | `ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}` | `auth` | One-shot: DB migrations |
| 17 | `authentik-server` | `ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}` | `auth .20` | Web UI + API + embedded outpost (forward-auth) |
| 18 | `authentik-worker` | `ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}` (CMD `worker`) | `auth .21` | Background jobs |

### Common hardening (applied via YAML anchor `x-hardened`)

```yaml
x-hardened: &hardened
  user: "1010:1010"
  read_only: true
  tmpfs: [/tmp, /run]
  security_opt: [no-new-privileges:true, seccomp:default]
  cap_drop: [ALL]
  restart: unless-stopped
  labels:
    - autoheal=true
```

Documented exceptions (additive):

| Container | Additive |
|---|---|
| `tailscale-ingress` | `cap_add: [NET_ADMIN]`, `devices: [/dev/net/tun]`, not `read_only` |
| `postgres` | `cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE, FOWNER]`, not `read_only` |
| `wazuh-manager` | `cap_add: [SYS_RESOURCE, SYS_PTRACE]`, `ulimits.memlock=-1` |
| `wazuh-indexer` | `ulimits.memlock=-1`, `ulimits.nofile=65536` |
| `falco` | `privileged: true`, `pid: host`, `user: 0:0`, mounts `/proc`, `/sys`, `/etc`, `/usr`, `/dev` — scope exception for eBPF runtime security |
| `zeek` | `network_mode: host`, `cap_add: [NET_ADMIN, NET_RAW]` |

### Resource limits — variable-driven, three tiers

Every resource knob is `${VAR:-default}`. Active tier is uncommented in `.env`; other two are commented alternatives.

#### HIGH (64 GB+ RAM / 16+ cores) — active in `.env.example`

```dotenv
POSTGRES_MEM_LIMIT=8g
POSTGRES_CPUS=4
POSTGRES_SHARED_BUFFERS=2GB
POSTGRES_EFFECTIVE_CACHE_SIZE=6GB
POSTGRES_WORK_MEM=32MB
POSTGRES_MAX_CONNECTIONS=300
REDIS_MEM_LIMIT=4g
REDIS_MAXMEMORY=3584mb
REDIS_IO_THREADS=4
CADDY_MEM_LIMIT=2g
CADDY_CPUS=2
CROWDSEC_MEM_LIMIT=1g
AUTHENTIK_SERVER_MEM_LIMIT=2g
AUTHENTIK_WORKER_MEM_LIMIT=2g
WAZUH_INDEXER_MEM_LIMIT=8g
WAZUH_INDEXER_JVM_HEAP=4g
WAZUH_MANAGER_MEM_LIMIT=2g
WAZUH_DASHBOARD_MEM_LIMIT=1g
FALCO_MEM_LIMIT=1g
ZEEK_MEM_LIMIT=2g
ZEEK_WORKER_COUNT=4
```

#### MED (16–32 GB / 8 cores)

```dotenv
POSTGRES_MEM_LIMIT=4g
POSTGRES_CPUS=2
POSTGRES_SHARED_BUFFERS=1GB
POSTGRES_EFFECTIVE_CACHE_SIZE=3GB
POSTGRES_WORK_MEM=16MB
POSTGRES_MAX_CONNECTIONS=200
REDIS_MEM_LIMIT=2g
REDIS_MAXMEMORY=1792mb
REDIS_IO_THREADS=2
CADDY_MEM_LIMIT=1g
CADDY_CPUS=2
CROWDSEC_MEM_LIMIT=512m
AUTHENTIK_SERVER_MEM_LIMIT=1536m
AUTHENTIK_WORKER_MEM_LIMIT=1536m
WAZUH_INDEXER_MEM_LIMIT=4g
WAZUH_INDEXER_JVM_HEAP=2g
WAZUH_MANAGER_MEM_LIMIT=1g
WAZUH_DASHBOARD_MEM_LIMIT=512m
FALCO_MEM_LIMIT=512m
ZEEK_MEM_LIMIT=1g
ZEEK_WORKER_COUNT=2
```

#### LOW (8 GB / 4 cores)

```dotenv
POSTGRES_MEM_LIMIT=2g
POSTGRES_CPUS=1
POSTGRES_SHARED_BUFFERS=512MB
POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
POSTGRES_WORK_MEM=8MB
POSTGRES_MAX_CONNECTIONS=100
REDIS_MEM_LIMIT=768m
REDIS_MAXMEMORY=640mb
REDIS_IO_THREADS=1
CADDY_MEM_LIMIT=512m
CADDY_CPUS=1
CROWDSEC_MEM_LIMIT=256m
AUTHENTIK_SERVER_MEM_LIMIT=768m
AUTHENTIK_WORKER_MEM_LIMIT=768m
WAZUH_INDEXER_MEM_LIMIT=2g
WAZUH_INDEXER_JVM_HEAP=1g
WAZUH_MANAGER_MEM_LIMIT=512m
WAZUH_DASHBOARD_MEM_LIMIT=256m
FALCO_MEM_LIMIT=256m
ZEEK_MEM_LIMIT=512m
ZEEK_WORKER_COUNT=1
```

**Estimated foundation+pilot RAM footprint** (sum of `mem_limit` caps, actual usage typically 40–60% of cap):
- HIGH ≈ 33 GB (headroom ≈ 31 GB on 64 GB host for Phase 3+)
- MED ≈ 18 GB
- LOW ≈ 9 GB (tight — pruning Wazuh retention may be needed)

`docker-host-config.sh` inspects `nproc` + `/proc/meminfo` and **prints** a recommendation (`"Host looks like MED tier — consider editing .env"`) without auto-editing.

---

## 5. Authentik pilot

Three containers on `auth` (+ one-shot migration), reach `data` for Postgres and Redis.

**Env var convention** (`.env` uses clean `APPLICATIONNAME_VALUE_NAME`; compose maps to Authentik's native double-underscore schema):

```yaml
authentik-server:
  environment:
    AUTHENTIK_POSTGRESQL__HOST: postgres
    AUTHENTIK_POSTGRESQL__USER: ${AUTHENTIK_DB_USER}
    AUTHENTIK_POSTGRESQL__PASSWORD: ${AUTHENTIK_DB_PASSWORD}
    AUTHENTIK_POSTGRESQL__NAME: ${AUTHENTIK_DB_NAME}
    AUTHENTIK_REDIS__HOST: redis
    AUTHENTIK_REDIS__PASSWORD: ${REDIS_PASSWORD}
    AUTHENTIK_REDIS__DB: ${AUTHENTIK_REDIS_DB}
    AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
    AUTHENTIK_BOOTSTRAP_EMAIL: ${ADMIN_EMAIL}
    AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
    AUTHENTIK_BOOTSTRAP_TOKEN: ${AUTHENTIK_BOOTSTRAP_TOKEN}
    AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
    AUTHENTIK_DISABLE_UPDATE_CHECK: "true"
```

**Caddy forward-auth snippet** (reused by every future gated app):

```caddyfile
# templates/caddy/snippets/authentik-forward-auth.caddy
route /outpost.goauthentik.io/* {
    reverse_proxy authentik-server:9000
}
forward_auth authentik-server:9000 {
    uri /outpost.goauthentik.io/auth/caddy
    copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email \
                 X-Authentik-Name X-Authentik-Uid X-Authentik-Jwt X-Authentik-Meta-*
}
```

**Hostnames:** `auth.secop.dev` (public via Cloudflare), `auth.neon-lenok.ts.net` (tailnet via Tailscale Serve).

---

## 6. Observability pipeline

Four ingest channels into Wazuh, all via host-level Wazuh Agent reading bind-mounted files. No in-compose log shippers.

| Channel | Source | Writer | Reader | Rule range |
|---|---|---|---|---|
| A | Caddy access logs | `caddy` → `/dock/conf/caddy/logs/access.log` (JSON) | Wazuh Agent → `caddy_json.xml` decoder | 100100–100199 |
| B | Crowdsec decisions | `crowdsec` file-notification plugin → `/dock/conf/crowdsec/notifications/decisions.log` (JSONL) | Wazuh Agent → `crowdsec_decision.xml` | 100200–100299 |
| C | Falco runtime events | `falco` `file_output` (JSON) → `/dock/conf/falco/events.log` | Wazuh Agent → `falco_json.xml` | 100300–100399 |
| D | Zeek network logs | `zeek` JSON logs (`redef LogAscii::use_json = T`) → `/dock/conf/zeek/logs/current/*.log` | Wazuh Agent → `zeek_conn.xml`, `zeek_dns.xml`, `zeek_ssl.xml`, `zeek_http.xml`, `zeek_notice.xml`, `zeek_intel.xml` | 100400–100599 |

**Severity mapping (all channels):**
- 4xx / NOTICE / WARNING → Wazuh level 5–9
- 5xx / WAF block / ERROR → level 10–12
- Crowdsec ban / Falco CRITICAL / Zeek Intel hit → level 12–15

**Dashboards** (created at first boot via Wazuh API):
- *Ingress security* — req/sec, status heatmap, top offenders, geo-map (MaxMind GeoLite2 if creds present).
- *WAF activity* — Coraza rule hits, top blocked paths, SQLi/XSS/LFI breakdowns.
- *Crowdsec state* — active bans, decisions by source.
- *Runtime anomalies* — Falco events by rule, container-level breakdown.
- *Network monitoring* — Zeek conn/DNS/TLS timeline, Intel hits, JA3/JA4 anomalies.

**Retention:**
- Wazuh indexer: `${WAZUH_INDEXER_RETENTION_DAYS:-45}` days via ISM policy (applied at first boot).
- Postgres dumps: `${POSTGRES_BACKUP_RETENTION_DAYS:-14}` days via `pg-backup.sh`.
- **Backup safety rule:** `pg-backup.sh` prunes old dumps **only after** a new dump succeeds. On failure: retain everything + emit level-12 alert to Wazuh via Crowdsec decisions file.

**Zeek Intel feeds:** CrowdStrike's free malicious domains list, URLhaus, Feodo tracker. Refreshed nightly by host cron, written to `/dock/conf/zeek/intel/`, reloaded via Zeek management framework.

**Access:** Wazuh dashboard exposed at `wazuh.secop.dev` / `wazuh.neon-lenok.ts.net`, gated by Authentik forward-auth. Manager port 1514/1515 only on Docker bridge + `tailscale serve --tcp=1514`; indexer 9200 never exposed.

---

## 7. `.env` conventions

### Rules

1. **Convention:** `APPLICATIONNAME_VALUE_NAME` (single underscore, all caps). Compose translates to upstream schemas when they differ (e.g., Authentik's `__`).
2. **Sectioning:** Globals first, then per-app sections alphabetical. Banner-comment separators. Reserved future-app sections present but empty.
3. **Globals** shared across containers: `PUID`, `PGID`, `DOCKER_SUPPLEMENTAL_GID`, `TZ`, `PUBLIC_FQDN`, `TAILNET_FQDN`, `ADMIN_EMAIL`, `DOCK_CONF/DATA/DB/TAIL`, `EXTRA_ALLOWED_IP`.
4. **No secrets in repo.** `.env.example` ships with keys + blank values + inline comments. Real `.env` is `.gitignore`d. `docker-host-config.sh` generates random values (via `openssl rand -base64 48 | tr -d '/+=\n' | head -c 50`) for any blank key ending in `_PASSWORD` / `_KEY` / `_TOKEN` / `_SECRET`, writing in-place and preserving comments. Never overwrites existing values.
5. **Per-app DB credentials:** `<APP>_DB_NAME` / `<APP>_DB_USER` / `<APP>_DB_PASSWORD` — `postgres-init` discovers and provisions automatically.

### Key values (finalized)

```dotenv
PUID=1010
PGID=1010
DOCKER_SUPPLEMENTAL_GID=1010        # reserved; pilot uses socket-proxy so no container needs docker group membership
TZ=America/Chicago
PUBLIC_FQDN=secop.dev
TAILNET_FQDN=neon-lenok.ts.net
ADMIN_EMAIL=sean@secop.dev
EXTRA_ALLOWED_IP=148.170.209.198
DOCK_CONF=/dock/conf
DOCK_DATA=/dock/data
DOCK_DB=/dock/db
DOCK_TAIL=/dock/tail
```

### Full section list (pilot `.env.example`)

- `GLOBAL`, `RESOURCE LIMITS` (HIGH/MED/LOW blocks), `TAILSCALE`, `CLOUDFLARE`, `POSTGRES` (+ backup retention), `REDIS` (+ logical DB map), `CADDY`, `CROWDSEC`, `WAZUH` (+ indexer retention), `FALCO`, `ZEEK`, `AUTHENTIK`, `PHASE 3+ (RESERVED)`.

---

## 8. Volume layout & persistence

All bind mounts, no named Docker volumes. Tree created by `docker-host-config.sh`, owned `1010:1010`, mode `770` (DBs `700`, logs `770`).

```
/dock/
├── conf/
│   ├── caddy/{Caddyfile, snippets/, data/, logs/, souin/}
│   ├── crowdsec/{config.yaml, acquis.yaml, profiles.yaml, notifications/, db/}
│   ├── socket-proxy-ro/        # (empty)
│   ├── socket-proxy-rw/        # (empty)
│   ├── authentik/{media/, custom-templates/, certs/}
│   ├── wazuh/{manager/, indexer/, dashboard/, certs/}
│   ├── falco/{falco.yaml, rules.d/, events.log}
│   └── zeek/{local.zeek, node.cfg, networks.cfg, intel/, logs/current/}
├── data/
│   ├── authentik/
│   └── wazuh/{indexer/, manager/}
├── db/
│   ├── postgres/{data/, init.d/}
│   └── redis/
├── tail/
│   └── ingress/
└── backups/
    ├── postgres/    # pg-backup.sh output
    └── redis/       # RDB snapshots
```

### Mount modes

| Pattern | Mode | Notes |
|---|---|---|
| `${DOCK_CONF}/<svc>:/config:ro` | RO | Default for config dirs |
| `${DOCK_CONF}/<svc>/<writable-subdir>:/.../path:rw` | RW | Caddy `data/logs`, Crowdsec `notifications/db`, Falco events, Zeek logs |
| `${DOCK_DATA}/<svc>:/data:rw` | RW | App state |
| `${DOCK_DB}/<svc>:/var/lib/postgresql/data:rw` | RW | DBs only |
| `${DOCK_TAIL}/<svc>:/var/lib/tailscale:rw` | RW | Tailscale state |

### Log files shared with host-level Wazuh Agent

| Path on host | Writer | Host reader |
|---|---|---|
| `/dock/conf/caddy/logs/access.log` | caddy | Wazuh Agent localfile |
| `/dock/conf/crowdsec/notifications/decisions.log` | crowdsec | Wazuh Agent localfile |
| `/dock/conf/falco/events.log` | falco | Wazuh Agent localfile |
| `/dock/conf/zeek/logs/current/*.log` | zeek | Wazuh Agent localfile |

### Backup strategy

- **Postgres**: nightly `pg-backup.sh` cron → `/dock/backups/postgres/dump-YYYYMMDD.sql.zst` (zstd -19). Prune old only on success (see §6 backup safety rule).
- **Redis**: AOF (`appendonly yes`) in `/dock/db/redis/` + RDB snapshot on SIGTERM.
- **Caddy data** (certs, OCSP), **Authentik media + blueprints**, **Wazuh certs** — backed up with config dirs.
- **Repo** is the source of truth for compose/Caddyfile/Dockerfiles/init SQL/decoders/rules.

---

## 9. `docker compose up --build` — bootstrap DAG

```
tailscale-ingress ──healthy─┐
                            │
postgres          ──healthy─┼─┐
redis             ──healthy─┘ │
                              ├─ postgres-init ──completed─┐
                              │                            │
wazuh-init  ──completed───────┤                            │
                              │                            │
wazuh-indexer    ──healthy────┤                            │
wazuh-manager    ──healthy────┤ (after indexer)            │
wazuh-dashboard  ──healthy────┘ (after manager)            │
                                                           │
authentik-migration ──completed ←──────────────────────────┤
authentik-server    ──healthy                              │
authentik-worker    ──healthy                              │
                                                           │
socket-proxy-ro  ──healthy (mounts /var/run/docker.sock)   │
socket-proxy-rw  ──healthy                                 │
crowdsec         ──healthy                                 │
autoheal         ──started (after socket-proxy-rw)         │
falco            ──healthy                                 │
zeek             ──healthy                                 │
                                                           │
caddy  ──starts last ──────────────────────────────────────┘
   (waits: tailscale-ingress healthy, authentik-server healthy, crowdsec healthy)
```

### Healthcheck matrix

| Container | Test | Interval |
|---|---|---|
| tailscale-ingress | `wget -q -O- http://127.0.0.1:41234/healthz` | 10s |
| postgres | `pg_isready -U postgres` | 10s |
| redis | `redis-cli -a $REDIS_PASSWORD ping` | 10s |
| wazuh-indexer | `curl -k https://localhost:9200/_cluster/health` | 20s |
| wazuh-manager | `/var/ossec/bin/wazuh-control status` | 30s |
| wazuh-dashboard | `curl -f http://localhost:5601/status` | 20s |
| crowdsec | `cscli lapi status` | 10s |
| authentik-server | `curl -fk https://localhost:9443/-/health/ready/` | 30s |
| authentik-worker | `celery -A authentik.root.celery inspect ping` | 30s |
| caddy | `curl -fk http://127.0.0.1:2019/config/` | 10s |
| socket-proxy-{ro,rw} | `wget -q -O- http://localhost:2375/_ping` | 10s |
| falco | `pgrep falco` (stdin healthcheck) | 30s |
| zeek | `zeekctl status` | 30s |
| autoheal | (no healthcheck — simple watchdog) | — |

### One-shot init (`restart: "no"`, `condition: service_completed_successfully`)

1. **`postgres-init`** — reads every `<APP>_DB_NAME/_DB_USER/_DB_PASSWORD` triple in env, idempotently provisions role + DB + grants. Additional `.sql` files in `/dock/db/postgres/init.d/` also applied.
2. **`wazuh-init`** — if `/dock/conf/wazuh/certs/admin.pem` is absent, runs `wazuh-certs-tool.sh --all`. Otherwise exits `0`.
3. **`authentik-migration`** — `ak migrate`, exits. Safe to re-run every `up`.

### First-run side effects

- Authentik bootstrap admin seeded; flag file `/dock/conf/.bootstrap-state/authentik-bootstrapped` prevents re-seed.
- Crowdsec enrolls to CAPI; Caddy bouncer API key registered in Crowdsec and written into `.env`.
- Caddy provisions `*.secop.dev` cert via Cloudflare DNS-01 (cached in `/dock/conf/caddy/data`).
- Tailscale joins tailnet using `TAILSCALE_AUTHKEY`, state persisted in `/dock/tail/ingress/`.
- Wazuh applies ISM policy (retention = `WAZUH_INDEXER_RETENTION_DAYS`).
- Zeek fetches Intel feeds (first run) via host cron.

### Idempotence

- Second `docker compose up --build` reuses builder cache, init containers see state and exit `0`, full stack healthy in ~30s.
- `docker compose down` keeps bind-mounted state + bootstrap flags.
- `docker compose down -v` is a no-op (no named volumes) — intentional safety.
- Destructive reset (documented, not automated): `sudo rm -rf /dock/db /dock/data /dock/conf/.bootstrap-state && docker compose up --build`.

### Failure-mode behaviors

| Failure | Behavior |
|---|---|
| Postgres won't come healthy | authentik-*, caddy blocked; clear `depends_on` error |
| Wazuh indexer OOM | autoheal restarts; >3 restarts in 10 min = dashboard down, rest unaffected |
| Caddy cert provisioning fails | ACME retry with backoff; stack still serves over Tailscale (self-signed TS cert) |
| Tailscale authkey expired | tailscale-ingress unhealthy → caddy stays down (clear signal) |
| Missing required `.env` key | `docker compose config` fails in `docker-host-config.sh` pre-flight check |
| Falco eBPF driver fails | container restart loop; autoheal backoff; documented in troubleshooting |
| Zeek can't open interfaces | fails healthcheck; manager+dashboard keep running without Channel D |

---

## 10. Build artifacts & repo layout

```
/
├── docker-compose.yml
├── .env.example
├── .gitignore                             # .env, /dock/, backups/
├── README.md                              # overview + diagrams + /dock tree
├── docker-host-config.sh                  # host bootstrap, idempotent
│
├── build/
│   └── caddy/
│       ├── Dockerfile                     # xcaddy build
│       └── plugins.txt                    # one plugin per line
│
├── templates/                             # copied to /dock/conf/ on first host-config run
│   ├── caddy/
│   │   ├── Caddyfile
│   │   ├── snippets/
│   │   │   ├── cloudflare-allowlist.caddy
│   │   │   ├── crowdsec.caddy
│   │   │   ├── coraza.caddy
│   │   │   ├── authentik-forward-auth.caddy
│   │   │   ├── wazuh-log.caddy
│   │   │   ├── security-headers.caddy
│   │   │   └── souin-cache.caddy
│   │   └── coraza/
│   │       ├── coraza.conf
│   │       ├── crs-setup.conf
│   │       └── rules/                     # OWASP CRS 4.x pinned
│   ├── crowdsec/{config.yaml, acquis.yaml, profiles.yaml}
│   ├── postgres/init.d/00-create-app-dbs.sh
│   ├── falco/{falco.yaml, falco_rules.local.yaml, rules.d/}
│   ├── zeek/{local.zeek, node.cfg, networks.cfg, intel/}
│   └── wazuh/
│       ├── decoders/{caddy_json, crowdsec_decision, falco_json, zeek_conn, zeek_dns, zeek_ssl, zeek_http, zeek_notice, zeek_intel}.xml
│       ├── rules/{caddy_rules, crowdsec_rules, falco_rules, zeek_rules}.xml
│       ├── ism-policy.json
│       └── agent-host.conf                # localfile blocks for host-level agent
│
├── scripts/
│   ├── pg-backup.sh                       # installed to /usr/local/bin
│   ├── wazuh-agent-ingest.sh              # installs decoders/rules to host agent
│   ├── health-recommend.sh                # prints tier recommendation
│   └── zeek-intel-refresh.sh              # nightly Intel feed refresh (cron)
│
└── docs/superpowers/specs/
    └── 2026-04-18-unified-stack-foundation-design.md
```

### Caddy `Dockerfile`

```dockerfile
# syntax=docker/dockerfile:1.7
FROM caddy:2-builder AS builder
COPY build/caddy/plugins.txt /tmp/plugins.txt
RUN xcaddy build $(awk '{printf "--with %s ", $1}' /tmp/plugins.txt)

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

### Caddy plugin list (`plugins.txt`)

```
github.com/caddy-dns/cloudflare
github.com/WeidiDeng/caddy-cloudflare-ip
github.com/hslatman/caddy-crowdsec-bouncer
github.com/mholt/caddy-l4
github.com/corazawaf/coraza-caddy/v2
github.com/caddyserver/cache-handler
github.com/ueffel/caddy-brotli
```

### Caddyfile structure

```caddyfile
{
    admin 127.0.0.1:2019
    servers { protocols h1 h2 h3 }
    email {$ADMIN_EMAIL}
    cache {
        ttl 10m
        api { basepath /souin-api }
        redis { url redis:6379 }
    }
    crowdsec {
        api_url http://crowdsec:8080
        api_key {$CROWDSEC_BOUNCER_KEY}
        ticker_interval 15s
    }
    log default {
        output file /var/log/caddy/access.log { roll_size 50mb roll_keep 10 }
        format json
    }
}

(common) {
    import cloudflare-allowlist      # 403 if not CF + 148.170.209.198
    import crowdsec                   # bouncer check
    import coraza                     # WAF
    import security-headers           # HSTS, CSP, X-Frame, X-Content-Type
}

*.secop.dev {
    import common
    tls { dns cloudflare {$CLOUDFLARE_API_TOKEN} resolvers 1.1.1.1 }
    @auth host auth.secop.dev
    handle @auth { reverse_proxy authentik-server:9000 }
    @wazuh host wazuh.secop.dev
    handle @wazuh {
        import authentik-forward-auth
        reverse_proxy wazuh-dashboard:5601
    }
    handle { abort }
}

*.neon-lenok.ts.net {
    import crowdsec
    import coraza
    import security-headers
    @auth host auth.neon-lenok.ts.net
    handle @auth { reverse_proxy authentik-server:9000 }
    @wazuh host wazuh.neon-lenok.ts.net
    handle @wazuh {
        import authentik-forward-auth
        reverse_proxy wazuh-dashboard:5601
    }
    handle { abort }
}
```

### `postgres-init` script — `templates/postgres/init.d/00-create-app-dbs.sh`

```bash
#!/bin/bash
set -euo pipefail
env | grep -oE '^[A-Z0-9]+_DB_NAME=' | sed 's/_DB_NAME=//' | while read -r APP; do
    db_var="${APP}_DB_NAME"  db="${!db_var}"
    user_var="${APP}_DB_USER" user="${!user_var}"
    pw_var="${APP}_DB_PASSWORD" pw="${!pw_var}"
    [ -z "$db" ] || [ -z "$user" ] || [ -z "$pw" ] && continue
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        SELECT 'CREATE ROLE $user LOGIN PASSWORD ''$pw'''
            WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$user')\gexec
        SELECT 'CREATE DATABASE $db OWNER $user'
            WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db')\gexec
        GRANT ALL PRIVILEGES ON DATABASE $db TO $user;
EOSQL
done
```

### `docker-host-config.sh` — outline

```bash
#!/usr/bin/env bash
set -euo pipefail

main() {
    require_root
    detect_ubuntu_version_or_exit          # >= 22.04
    apt_update_and_upgrade
    install_base_packages                  # curl, jq, zstd, fail2ban, ufw, gnupg, ca-certificates, cron
    install_docker                         # official apt repo, enable service
    install_tailscale                      # official apt repo
    create_user_and_groups                 # docktaetor uid 1010 / media gid 1010, docker supplemental
    create_dock_tree                       # /dock/{conf,data,db,tail,backups}/... , chown 1010:1010, chmod 770 (DBs 700)
    copy_templates                         # templates/ → /dock/conf/ (skip if file exists)
    generate_missing_secrets               # openssl rand for empty _PASSWORD/_KEY/_TOKEN/_SECRET keys in .env
    install_wazuh_agent                    # host-level deb + custom decoders/rules from scripts/wazuh-agent-ingest.sh
    install_cron_jobs                      # pg-backup.sh (nightly 0200), zeek-intel-refresh.sh (nightly 0300)
    install_systemd_units                  # compose-stack.service: `docker compose up -d` at boot
    harden_ufw                             # allow 22, 80, 443, tailscale0; deny else
    kernel_tuning                          # vm.max_map_count=262144, net.ipv4.ip_forward=1, net.core.rmem_max tuning for Zeek
    health_tier_recommend                  # prints LOW/MED/HIGH suggestion from host specs
    validate_env                           # docker compose config dry-run
    print_summary                          # next-steps + URL(s) to visit
}

main "$@"
```

### Key generation (idempotent, never overwrites)

```bash
generate_missing_secrets() {
    local env_file="$(pwd)/.env"
    [ -f "$env_file" ] || cp .env.example "$env_file"
    grep -E '^[A-Z0-9_]+_(PASSWORD|KEY|TOKEN|SECRET)=$' "$env_file" | while IFS='=' read -r key _; do
        local val
        val="$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 50)"
        sed -i "s|^${key}=$|${key}=${val}|" "$env_file"
        echo "Generated: $key"
    done
    chmod 600 "$env_file"
    chown docktaetor:media "$env_file"
}
```

---

## 11. Security model — ingress path, hardening, threat matrix

### Ingress path (what every public request crosses)

```
Internet client
    │  TLS 1.3 + HTTP/3
[1] Cloudflare edge           ─── DDoS absorption, bot score, CF WAF
    │  connection from CF IP only
[2] Host UFW                   ─── ACCEPT 80/443 from any, DROP else
    │
[3] Caddy (via tailscale-ingress netns)  ─── TLS termination (CF DNS-01 cert)
    │
[4] Caddy @cloudflare matcher  ─── 403 if remote_ip ∉ (CF ranges ∪ 148.170.209.198)
    │
[5] Crowdsec bouncer           ─── reputation, community blocklist, local decisions
    │
[6] Coraza WAF (OWASP CRS)     ─── SQLi/XSS/LFI/RCE signatures, anomaly score
    │
[7] Authentik forward-auth     ─── SSO (except login paths)
    │
[8] App container              ─── 1010:1010, read-only, cap_drop ALL
    │ (continuously observed by)
[9] Falco                      ─── syscall/FS/network anomalies inside container
[10] Zeek                      ─── passive network observation on docker bridges + host
```

Both [9] and [10] observe in parallel; they do not gate requests. They feed Wazuh for detection-and-response.

### Threat × mitigation matrix

| Threat | Primary mitigation | Backup |
|---|---|---|
| Public DDoS | Cloudflare edge | CF allowlist (step 4) drops non-CF traffic |
| Credential stuffing | Authentik rate-limit + MFA | Crowdsec scenarios detect auth brute force |
| Zero-day web exploit | Coraza OWASP CRS | Egress isolation (data + app layers separate) |
| Container escape via unknown exploit | Falco (`Terminal shell in container`, `Write below root`, `Unexpected privileged container`) | Host UFW + kernel hardening |
| Malicious DNS exfiltration | Zeek `dns.log` + Intel hits → Wazuh correlation | Crowdsec egress blocklist scenarios |
| TLS fingerprint-based C2 beaconing | Zeek `ssl.log` JA3/JA4 fingerprint anomalies | Cloudflare WAF on ingress side |
| Supply-chain compromise post-install | Falco detects execution from `/tmp`, unexpected outbound | Image pinning, renovate review |
| Socket-proxy abuse from compromised container | Falco `Contact Docker API from unauthorized container`; RO/RW proxy split | Proxy permission env vars, no host `/var/run/docker.sock` in apps |
| Leaked `.env` in git | `.gitignore` `.env`, CI grep for secret patterns | All keys regenerable by `docker-host-config.sh` |
| Container escape (generic) | `user: 1010:1010`, `read_only`, `cap_drop ALL`, `no-new-privileges`, seccomp | Falco + host UFW |
| DB exfiltration | `data` layer isolation, per-app DB/role, no published ports | Wazuh rule flags external 5432 connection attempts |
| Lateral movement between apps | Apps never share layers; only Caddy multi-homes | Crowdsec intra-network scenarios + Zeek `conn.log` |
| Log tampering | Logs bind-mounted to host, Wazuh Agent reads outside Docker | Decisions file append-only from host |
| Silent backup failure | `pg-backup.sh` level-12 alert, skips pruning | Retention floor = manual delete only |
| Tailscale key leak | Ephemeral + reusable-disabled keys where possible | Re-issue + bounce sidecar |
| Authentik outage locks out admins | Emergency `AUTHENTIK_BOOTSTRAP_TOKEN` via API | Direct `psql` reset documented |

### Secrets lifecycle

| Stage | Mechanism |
|---|---|
| Generation | `openssl rand -base64 48` in `docker-host-config.sh`, only for blank keys |
| Storage | `/dock/conf/.env` mode `600` owner `docktaetor:media`; never in repo |
| Injection | Compose `env_file`, process env only (not build ARG, not image layer) |
| Rotation | Per-service procedure documented in README troubleshooting |
| Revocation | Tailscale admin console; CF dashboard; Wazuh API |

### Explicit non-goals (scoped out for pilot)

- HSM-backed secrets.
- Immutable infrastructure (image bake-and-ship).
- External-to-CF DDoS (CF handles).

---

## 12. README content (outline)

The repo `README.md` will contain:

1. **Project overview** (what it is, the sidecar/ingress pattern in plain English, priority order).
2. **Architectural diagrams** (Mermaid, render on GitHub):
   - Network topology (layers, IP ranges, multi-homing).
   - Request flow (public → CF → Caddy → Crowdsec + Coraza → forward-auth → app).
   - `docker compose up` bootstrap order.
   - Logging pipeline (4 channels → Wazuh).
3. **Host layout** — the `/dock/` tree diagram from §8.
4. **Security model** — the ingress-path diagram + threat × mitigation matrix from §11.
5. **Quickstart**:
   - Prereqs (Ubuntu ≥ 22.04, Tailscale account, Cloudflare API token with DNS:edit on `secop.dev`, `148.170.209.198` as secondary allowed IP).
   - Run `sudo ./docker-host-config.sh`.
   - Edit `/dock/conf/.env` (tier, auth keys, per-app DB passwords if not auto-generated).
   - `docker compose up --build`.
6. **Per-layer service index.**
7. **Troubleshooting** (auth reset, cert stall, Wazuh indexer OOM, backup failure investigation, Zeek tap down).
8. **Adding a new app** — reference procedure (new `.env` section, new Caddy `@host handle`, new Postgres DB triple, depends_on wiring).

---

## 13. Acceptance criteria — pilot is "done" when

1. `docker-host-config.sh` runs successfully on a fresh Ubuntu 22.04+ host; running it a second time produces no changes (idempotent).
2. `docker compose up --build` brings all 18 pilot containers to healthy state within 5 minutes on HIGH-tier hardware.
3. `https://auth.secop.dev` loads from a Cloudflare-originating request; direct-IP requests return 403.
4. `https://auth.neon-lenok.ts.net` loads from any authenticated tailnet peer.
5. Bootstrap admin (from `AUTHENTIK_BOOTSTRAP_*`) can log in, create a user, and protect a dummy test app via forward-auth.
6. Wazuh dashboard (at `wazuh.secop.dev`) shows events from all four channels (Caddy, Crowdsec, Falco, Zeek) within 2 minutes of boot.
7. Deliberate test events trigger appropriate alerts:
   - `curl 'https://auth.secop.dev/?id=1%27 OR 1=1--'` → Coraza block → Wazuh level-10 rule.
   - `docker exec authentik-server sh -c 'bash'` → Falco "terminal shell in container" → level-12.
   - DNS query for a known-bad domain from a container → Zeek Intel hit → level-13.
8. `pg-backup.sh` produces a zstd dump; simulated failure (drop Postgres mid-run) leaves prior backups untouched and emits a level-12 alert.
9. `docker compose down && docker compose up --build` completes in < 60 s on warm cache with no data loss.
10. `.env.example` contains every variable referenced by `docker-compose.yml` (verified by a grep-diff test in CI).

---

## 14. Deliverables checklist

- [ ] `docker-compose.yml`
- [ ] `.env.example`
- [ ] `.gitignore`
- [ ] `README.md` (with Mermaid diagrams + `/dock` tree + threat matrix + ingress-path diagram)
- [ ] `docker-host-config.sh`
- [ ] `build/caddy/Dockerfile`
- [ ] `build/caddy/plugins.txt`
- [ ] `templates/caddy/` (Caddyfile + 7 snippets + Coraza config + CRS rules)
- [ ] `templates/crowdsec/` (config.yaml, acquis.yaml, profiles.yaml)
- [ ] `templates/postgres/init.d/00-create-app-dbs.sh`
- [ ] `templates/falco/` (falco.yaml, falco_rules.local.yaml, rules.d/)
- [ ] `templates/zeek/` (local.zeek, node.cfg, networks.cfg, intel/)
- [ ] `templates/wazuh/decoders/` (7 files)
- [ ] `templates/wazuh/rules/` (4 files)
- [ ] `templates/wazuh/ism-policy.json`
- [ ] `templates/wazuh/agent-host.conf`
- [ ] `scripts/pg-backup.sh`
- [ ] `scripts/wazuh-agent-ingest.sh`
- [ ] `scripts/health-recommend.sh`
- [ ] `scripts/zeek-intel-refresh.sh`

---

## 15. Open questions (tracked; resolve during implementation)

- **Falco driver fallback**: if `modern_ebpf` won't load on target kernel, fall back to `ebpf` legacy driver? Document in troubleshooting.
- **Zeek cluster topology at LOW tier**: single-process mode vs minimal cluster (1 manager + 1 worker)? Lean single-process to minimize overhead.
- **Cloudflare API token scopes**: document exact permissions in README (DNS:edit on `secop.dev` zone, Zone:read on `secop.dev`).
- **Wazuh ISM policy hot-warm split**: pilot uses single tier; consider hot-warm at 100GB+ indices.
- **OWASP CRS tuning**: ship with `paranoia_level=1` + `blocking_paranoia_level=1`; document how to raise.
