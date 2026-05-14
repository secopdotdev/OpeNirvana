# Unified Stack Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single `docker compose up --build`-driven self-hosted foundation (Caddy + Tailscale + Crowdsec + Coraza + Falco + Zeek + shared Postgres/Redis + Wazuh SIEM + Autoheal) with Authentik as the pilot SSO app, deployable on a freshly-imaged Ubuntu host via one bootstrap script.

**Architecture:** All work lives under a new `unified-stack/` directory at repo root (preserves existing stacks). Caddy is custom-built via xcaddy in-compose and uses `network_mode: service:tailscale-ingress` to inherit every layer's network. Per-layer `/24` networks isolate app tiers; apps never share layers. Postgres + Redis are shared across apps (per-app DB + logical Redis DB). Wazuh ingests logs from four channels (Caddy, Crowdsec, Falco, Zeek) via host-level Wazuh Agent tailing bind-mounted files.

**Tech Stack:** Docker Compose v2, Caddy 2 + xcaddy plugins, Coraza WAF (OWASP CRS 4.x), Crowdsec, Falco (modern_ebpf), Zeek, Wazuh 4.9.2, pgvector/pgvector:pg16, redis:7-alpine, Authentik 2024.12.x, Tailscale, Cloudflare DNS-01, bash (host bootstrap), Ubuntu ≥ 22.04.

**Full spec:** `docs/superpowers/specs/2026-04-18-unified-stack-foundation-design.md`

---

## File Structure

All files created under `unified-stack/` unless noted.

| File | Purpose |
|---|---|
| `unified-stack/docker-compose.yml` | All 18 services, networks, anchors |
| `unified-stack/.env.example` | Template env with sections, HIGH/MED/LOW tiers, all variables |
| `unified-stack/.gitignore` | Excludes `.env`, `/dock/`, local backups |
| `unified-stack/README.md` | Overview, Mermaid diagrams, quickstart, `/dock` tree, threat matrix |
| `unified-stack/docker-host-config.sh` | Host bootstrap: packages, docker, tailscale, users, dirs, secrets, wazuh-agent, cron, ufw, kernel |
| `unified-stack/build/caddy/Dockerfile` | xcaddy build stage + runtime stage |
| `unified-stack/build/caddy/plugins.txt` | One plugin module path per line |
| `unified-stack/templates/caddy/Caddyfile` | Master config, imports snippets, defines `*.secop.dev` and `*.neon-lenok.ts.net` stanzas |
| `unified-stack/templates/caddy/snippets/cloudflare-allowlist.caddy` | 403 if remote_ip not in CF + EXTRA_ALLOWED_IP |
| `unified-stack/templates/caddy/snippets/crowdsec.caddy` | Bouncer directive |
| `unified-stack/templates/caddy/snippets/coraza.caddy` | WAF directive pointing at coraza.conf + CRS |
| `unified-stack/templates/caddy/snippets/authentik-forward-auth.caddy` | Reusable SSO gate |
| `unified-stack/templates/caddy/snippets/security-headers.caddy` | HSTS/CSP/X-Frame |
| `unified-stack/templates/caddy/snippets/souin-cache.caddy` | HTTP cache policy |
| `unified-stack/templates/caddy/snippets/wazuh-log.caddy` | Log format override (no-op; format=json already set globally) |
| `unified-stack/templates/caddy/coraza/coraza.conf` | Coraza engine config |
| `unified-stack/templates/caddy/coraza/crs-setup.conf` | CRS tuning (paranoia level) |
| `unified-stack/templates/caddy/coraza/rules/` | OWASP CRS 4.x ruleset files (fetched during build) |
| `unified-stack/templates/crowdsec/config.yaml` | LAPI config |
| `unified-stack/templates/crowdsec/acquis.yaml` | Log source: tails Caddy log |
| `unified-stack/templates/crowdsec/profiles.yaml` | File notification to decisions.log |
| `unified-stack/templates/postgres/init.d/00-create-app-dbs.sh` | Idempotent role+DB provisioner |
| `unified-stack/templates/falco/falco.yaml` | Driver, outputs, buffered off |
| `unified-stack/templates/falco/falco_rules.local.yaml` | Custom container-escape + socket-abuse rules |
| `unified-stack/templates/zeek/local.zeek` | JSON output, Intel framework, custom scripts |
| `unified-stack/templates/zeek/node.cfg` | Cluster topology |
| `unified-stack/templates/zeek/networks.cfg` | Local networks |
| `unified-stack/templates/zeek/intel/.gitkeep` | Dir seeded at runtime by intel-refresh |
| `unified-stack/templates/wazuh/decoders/*.xml` | 7 decoder files (caddy_json, crowdsec_decision, falco_json, zeek_{conn,dns,ssl,http,notice,intel}) |
| `unified-stack/templates/wazuh/rules/*.xml` | 4 rule files (caddy, crowdsec, falco, zeek) |
| `unified-stack/templates/wazuh/ism-policy.json` | Index lifecycle / retention |
| `unified-stack/templates/wazuh/agent-host.conf` | localfile blocks for host agent |
| `unified-stack/scripts/pg-backup.sh` | Nightly pg_dumpall with safety rule |
| `unified-stack/scripts/health-recommend.sh` | Prints LOW/MED/HIGH tier based on host |
| `unified-stack/scripts/wazuh-agent-ingest.sh` | Installs decoders/rules into host-level Wazuh Agent |
| `unified-stack/scripts/zeek-intel-refresh.sh` | Nightly Intel feed refresh |

---

## Conventions used in this plan

- **Working directory**: `c:\goonGIT\finnsbeincaddy\` (Windows host doing the editing). Final deployment target is an Ubuntu host.
- **Line endings**: all shell scripts + Dockerfiles use LF. Git will convert on checkout per `.gitattributes`.
- **Commit cadence**: one commit per task (step 5).
- **Validation tools (run from a Linux shell or Docker container — Windows dev host cannot run actual stack)**:
  - `docker compose config` — YAML + schema validation.
  - `docker run --rm -v "$PWD:/mnt" -w /mnt caddy:2 caddy validate --config /mnt/<file>` — Caddyfile validation.
  - `docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable <script>` — shell linting.
  - `docker run --rm -v "$PWD:/mnt" -w /mnt cytopia/yamllint <file>` — YAML linting.
- **Expected container healthchecks**: documented in spec §9; used as the "test passes" gate during integration tasks.
- **No end-to-end acceptance test on Windows dev host.** Final acceptance (Task 19) assumes user runs it on the Ubuntu target after `docker-host-config.sh`.

---

## Task 1: Repo scaffolding

**Files:**
- Create: `unified-stack/.gitignore`
- Create: `unified-stack/README.md` (skeleton only; filled in Task 18)
- Create directory tree (empty dirs with `.gitkeep` where git requires): `unified-stack/build/caddy/`, `unified-stack/templates/{caddy/snippets,caddy/coraza/rules,crowdsec,postgres/init.d,falco/rules.d,zeek/intel,wazuh/decoders,wazuh/rules}/`, `unified-stack/scripts/`

- [ ] **Step 1: Create the directory tree**

Run:
```bash
mkdir -p unified-stack/{build/caddy,scripts,templates/{caddy/snippets,caddy/coraza/rules,crowdsec,postgres/init.d,falco/rules.d,zeek/intel,wazuh/decoders,wazuh/rules}}
touch unified-stack/templates/caddy/coraza/rules/.gitkeep
touch unified-stack/templates/falco/rules.d/.gitkeep
touch unified-stack/templates/zeek/intel/.gitkeep
```

Expected: dirs exist. Verify: `find unified-stack -type d | sort`.

- [ ] **Step 2: Write `.gitignore`**

File: `unified-stack/.gitignore`
```gitignore
# Secrets and runtime state
.env
.env.local

# Runtime bind-mount directories (created by docker-host-config.sh on target host)
/dock/

# Local backups (if tester runs scripts on the repo host)
/backups/
*.sql.zst
*.rdb

# Caddy builder intermediate
build/caddy/.xcaddy-cache/

# OS cruft
.DS_Store
Thumbs.db
```

- [ ] **Step 3: Write README skeleton**

File: `unified-stack/README.md`
```markdown
# Unified Stack

Single-command docker-compose foundation for self-hosted services, featuring:
- Tailscale + Cloudflare dual ingress through custom-built Caddy (Crowdsec, Coraza WAF, forward-auth, HTTP/3, Brotli, Souin cache)
- Shared Postgres + Redis (per-app DB + logical Redis DB)
- Wazuh SIEM ingesting from Caddy, Crowdsec, Falco runtime events, and Zeek network logs
- Authentik SSO pilot

> **Full design:** `../docs/superpowers/specs/2026-04-18-unified-stack-foundation-design.md`
>
> **Implementation plan:** `../docs/superpowers/plans/2026-04-18-unified-stack-foundation-implementation.md`

This README is filled in by Task 18 of the implementation plan.
```

- [ ] **Step 4: Verify tree**

Run from repo root: `find unified-stack -type f -o -type d | sort`
Expected: shows `.gitignore`, `README.md`, all directories, all `.gitkeep` files.

- [ ] **Step 5: Commit**

```bash
cd c:/goonGIT/finnsbeincaddy
git add unified-stack/
git commit -m "Scaffold unified-stack directory tree"
```

---

## Task 2: `.env.example`

**File:** Create `unified-stack/.env.example`

- [ ] **Step 1: Write the full `.env.example`**

File: `unified-stack/.env.example`
```dotenv
# ==========================================================
# GLOBAL — applies to all/most containers
# ==========================================================
COMPOSE_PROJECT_NAME=stack
PUID=1010
PGID=1010
DOCKER_SUPPLEMENTAL_GID=1010        # reserved; pilot uses socket-proxy so no container needs docker group
TZ=America/Chicago
PUBLIC_FQDN=secop.dev
TAILNET_FQDN=neon-lenok.ts.net
ADMIN_EMAIL=sean@secop.dev

# Host paths (must match docker-host-config.sh tree)
DOCK_CONF=/dock/conf
DOCK_DATA=/dock/data
DOCK_DB=/dock/db
DOCK_TAIL=/dock/tail

# External IPs outside Cloudflare that are permitted to reach *.secop.dev
EXTRA_ALLOWED_IP=148.170.209.198

# ==========================================================
# RESOURCE LIMITS — uncomment ONE tier block
# HIGH: 64GB+/16+ cores | MED: 16-32GB/8 cores | LOW: 8GB/4 cores
# ==========================================================
# ---------- HIGH tier (active) ----------
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

# ---------- MED tier (commented) ----------
#POSTGRES_MEM_LIMIT=4g
#POSTGRES_CPUS=2
#POSTGRES_SHARED_BUFFERS=1GB
#POSTGRES_EFFECTIVE_CACHE_SIZE=3GB
#POSTGRES_WORK_MEM=16MB
#POSTGRES_MAX_CONNECTIONS=200
#REDIS_MEM_LIMIT=2g
#REDIS_MAXMEMORY=1792mb
#REDIS_IO_THREADS=2
#CADDY_MEM_LIMIT=1g
#CADDY_CPUS=2
#CROWDSEC_MEM_LIMIT=512m
#AUTHENTIK_SERVER_MEM_LIMIT=1536m
#AUTHENTIK_WORKER_MEM_LIMIT=1536m
#WAZUH_INDEXER_MEM_LIMIT=4g
#WAZUH_INDEXER_JVM_HEAP=2g
#WAZUH_MANAGER_MEM_LIMIT=1g
#WAZUH_DASHBOARD_MEM_LIMIT=512m
#FALCO_MEM_LIMIT=512m
#ZEEK_MEM_LIMIT=1g
#ZEEK_WORKER_COUNT=2

# ---------- LOW tier (commented) ----------
#POSTGRES_MEM_LIMIT=2g
#POSTGRES_CPUS=1
#POSTGRES_SHARED_BUFFERS=512MB
#POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
#POSTGRES_WORK_MEM=8MB
#POSTGRES_MAX_CONNECTIONS=100
#REDIS_MEM_LIMIT=768m
#REDIS_MAXMEMORY=640mb
#REDIS_IO_THREADS=1
#CADDY_MEM_LIMIT=512m
#CADDY_CPUS=1
#CROWDSEC_MEM_LIMIT=256m
#AUTHENTIK_SERVER_MEM_LIMIT=768m
#AUTHENTIK_WORKER_MEM_LIMIT=768m
#WAZUH_INDEXER_MEM_LIMIT=2g
#WAZUH_INDEXER_JVM_HEAP=1g
#WAZUH_MANAGER_MEM_LIMIT=512m
#WAZUH_DASHBOARD_MEM_LIMIT=256m
#FALCO_MEM_LIMIT=256m
#ZEEK_MEM_LIMIT=512m
#ZEEK_WORKER_COUNT=1

# ==========================================================
# TAILSCALE
# ==========================================================
TAILSCALE_AUTHKEY=
TAILSCALE_INGRESS_HOSTNAME=ingress    # becomes ingress.neon-lenok.ts.net

# ==========================================================
# CLOUDFLARE (DNS-01 + dynamic CF range Caddy plugin)
# ==========================================================
CLOUDFLARE_API_TOKEN=

# ==========================================================
# POSTGRES (shared cluster)
# ==========================================================
POSTGRES_VERSION=pg16
POSTGRES_SUPERUSER=postgres
POSTGRES_SUPERUSER_PASSWORD=
POSTGRES_INITDB_ARGS=--data-checksums --locale=C.UTF-8 --encoding=UTF8
POSTGRES_BACKUP_RETENTION_DAYS=14

# ==========================================================
# REDIS (shared, logical DB per app)
# ==========================================================
REDIS_PASSWORD=
REDIS_APPENDONLY=yes
REDIS_DB_AUTHENTIK=0
REDIS_DB_CADDY_CACHE=1
REDIS_DB_AFFINE=2                     # reserved (Phase 3)
REDIS_DB_NEXTCLOUD=3                  # reserved (Phase 3)

# ==========================================================
# CADDY
# ==========================================================
CADDY_METRICS_ENABLED=true
CADDY_LOG_LEVEL=INFO

# ==========================================================
# CROWDSEC
# ==========================================================
CROWDSEC_BOUNCER_KEY=
CROWDSEC_ENROLL_KEY=                   # optional, for CS Console

# ==========================================================
# WAZUH
# ==========================================================
WAZUH_VERSION=4.9.2
WAZUH_API_PASSWORD=
WAZUH_INDEXER_ADMIN_PASSWORD=
WAZUH_INDEXER_KIBANASERVER_PASSWORD=
WAZUH_INDEXER_RETENTION_DAYS=45

# ==========================================================
# FALCO (runtime container security)
# ==========================================================
FALCO_DRIVER=modern_ebpf               # fallback: ebpf

# ==========================================================
# ZEEK (network security monitoring)
# ==========================================================
ZEEK_INTERFACES=auto                   # auto = all non-loopback; or comma-list

# ==========================================================
# AUTHENTIK                                       (PILOT APP)
# ==========================================================
AUTHENTIK_VERSION=2024.12.2
AUTHENTIK_SECRET_KEY=
AUTHENTIK_BOOTSTRAP_PASSWORD=
AUTHENTIK_BOOTSTRAP_TOKEN=
AUTHENTIK_DB_NAME=authentik
AUTHENTIK_DB_USER=authentik
AUTHENTIK_DB_PASSWORD=
AUTHENTIK_REDIS_DB=${REDIS_DB_AUTHENTIK}

# ==========================================================
# PHASE 3+ (reserved — empty in pilot)
# ==========================================================
# AFFINE_DB_NAME=affine
# AFFINE_DB_USER=affine
# AFFINE_DB_PASSWORD=
# NEXTCLOUD_DB_NAME=nextcloud
# NEXTCLOUD_DB_USER=nextcloud
# NEXTCLOUD_DB_PASSWORD=
```

- [ ] **Step 2: Validate shape**

Run:
```bash
grep -c '^[A-Z]' unified-stack/.env.example
```
Expected: `>= 60` (all var lines).

Run:
```bash
grep -E '^[A-Z_]+=$' unified-stack/.env.example | wc -l
```
Expected: matches count of `_PASSWORD|_KEY|_TOKEN|_SECRET|_AUTHKEY|_API_TOKEN` — these are the keys `docker-host-config.sh` will fill (Task 17).

- [ ] **Step 3: Commit**

```bash
git add unified-stack/.env.example
git commit -m "Add unified-stack .env.example with HIGH/MED/LOW tiers"
```

---

## Task 3: Caddy custom build

**Files:**
- Create: `unified-stack/build/caddy/Dockerfile`
- Create: `unified-stack/build/caddy/plugins.txt`

- [ ] **Step 1: Write `plugins.txt`**

File: `unified-stack/build/caddy/plugins.txt`
```text
github.com/caddy-dns/cloudflare
github.com/WeidiDeng/caddy-cloudflare-ip
github.com/hslatman/caddy-crowdsec-bouncer/crowdsec
github.com/mholt/caddy-l4
github.com/corazawaf/coraza-caddy/v2
github.com/caddyserver/cache-handler
github.com/ueffel/caddy-brotli
```

- [ ] **Step 2: Write `Dockerfile`**

File: `unified-stack/build/caddy/Dockerfile`
```dockerfile
# syntax=docker/dockerfile:1.7

FROM caddy:2-builder AS builder
COPY plugins.txt /tmp/plugins.txt
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    xcaddy build \
      $(awk 'NF && $1 !~ /^#/ {printf "--with %s ", $1}' /tmp/plugins.txt)

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

- [ ] **Step 3: Validate Dockerfile syntax (lint only, no build on Windows dev host)**

Run:
```bash
docker run --rm -i hadolint/hadolint < unified-stack/build/caddy/Dockerfile
```
Expected: no errors. Ignore `DL3006` (no pinned base tag) — we pin elsewhere intentionally.

Run:
```bash
awk 'NF && $1 !~ /^#/' unified-stack/build/caddy/plugins.txt | wc -l
```
Expected: `7`.

- [ ] **Step 4: Commit**

```bash
git add unified-stack/build/caddy/
git commit -m "Add Caddy xcaddy build config with 7 plugins"
```

---

## Task 4: Caddyfile and snippets

**Files:**
- Create: `unified-stack/templates/caddy/Caddyfile`
- Create: `unified-stack/templates/caddy/snippets/cloudflare-allowlist.caddy`
- Create: `unified-stack/templates/caddy/snippets/crowdsec.caddy`
- Create: `unified-stack/templates/caddy/snippets/coraza.caddy`
- Create: `unified-stack/templates/caddy/snippets/authentik-forward-auth.caddy`
- Create: `unified-stack/templates/caddy/snippets/security-headers.caddy`
- Create: `unified-stack/templates/caddy/snippets/souin-cache.caddy`

- [ ] **Step 1: Write `Caddyfile`**

File: `unified-stack/templates/caddy/Caddyfile`
```caddyfile
{
    admin 127.0.0.1:2019
    email {$ADMIN_EMAIL}
    log default {
        output file /var/log/caddy/access.log {
            roll_size 50mb
            roll_keep 10
            roll_keep_for 720h
        }
        format json
        level {$CADDY_LOG_LEVEL}
    }

    servers {
        protocols h1 h2 h3
        metrics
    }

    cache {
        ttl 10m
        api {
            basepath /souin-api
        }
        redis {
            url redis:6379
            password {$REDIS_PASSWORD}
            database {$REDIS_DB_CADDY_CACHE}
        }
    }

    crowdsec {
        api_url http://crowdsec:8080
        api_key {$CROWDSEC_BOUNCER_KEY}
        ticker_interval 15s
    }
}

# ====== reusable policy blocks ======
(public-policy) {
    import cloudflare-allowlist
    import crowdsec
    import coraza
    import security-headers
}

(tailnet-policy) {
    import crowdsec
    import coraza
    import security-headers
}

# ====== public: *.secop.dev ======
*.{$PUBLIC_FQDN} {
    import public-policy

    tls {
        dns cloudflare {$CLOUDFLARE_API_TOKEN}
        resolvers 1.1.1.1
    }

    @auth host auth.{$PUBLIC_FQDN}
    handle @auth {
        reverse_proxy authentik-server:9000
    }

    @wazuh host wazuh.{$PUBLIC_FQDN}
    handle @wazuh {
        import authentik-forward-auth
        reverse_proxy https://wazuh-dashboard:5601 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }

    handle {
        abort
    }
}

# ====== tailnet: *.neon-lenok.ts.net (TLS via Tailscale Serve outside Caddy) ======
*.{$TAILNET_FQDN} {
    import tailnet-policy

    @auth host auth.{$TAILNET_FQDN}
    handle @auth {
        reverse_proxy authentik-server:9000
    }

    @wazuh host wazuh.{$TAILNET_FQDN}
    handle @wazuh {
        import authentik-forward-auth
        reverse_proxy https://wazuh-dashboard:5601 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }

    handle {
        abort
    }
}
```

- [ ] **Step 2: Write `cloudflare-allowlist.caddy`**

File: `unified-stack/templates/caddy/snippets/cloudflare-allowlist.caddy`
```caddyfile
# Dynamic Cloudflare range matcher (fetched & refreshed by caddy-cloudflare-ip plugin)
# Plus the operator-defined EXTRA_ALLOWED_IP (e.g., office uplink).
@cloudflare {
    remote_ip cloudflare {$EXTRA_ALLOWED_IP}
}

# Default-deny: return 403 for anything outside the allowed set.
@not_cloudflare not remote_ip cloudflare {$EXTRA_ALLOWED_IP}
handle @not_cloudflare {
    respond "Forbidden" 403
}
```

- [ ] **Step 3: Write `crowdsec.caddy`**

File: `unified-stack/templates/caddy/snippets/crowdsec.caddy`
```caddyfile
# Check every request against Crowdsec LAPI. Denied IPs get 403.
crowdsec
```

- [ ] **Step 4: Write `coraza.caddy`**

File: `unified-stack/templates/caddy/snippets/coraza.caddy`
```caddyfile
# Coraza WAF with OWASP CRS. Config file bind-mounted to /etc/caddy/coraza/.
coraza_waf {
    load_owasp_crs
    directives `
        Include /etc/caddy/coraza/coraza.conf
        Include /etc/caddy/coraza/crs-setup.conf
        Include /etc/caddy/coraza/rules/*.conf
    `
}
```

- [ ] **Step 5: Write `authentik-forward-auth.caddy`**

File: `unified-stack/templates/caddy/snippets/authentik-forward-auth.caddy`
```caddyfile
# Reusable Authentik SSO gate. Import inside any handle block that needs auth.
route /outpost.goauthentik.io/* {
    reverse_proxy authentik-server:9000
}

forward_auth authentik-server:9000 {
    uri /outpost.goauthentik.io/auth/caddy
    copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid X-Authentik-Jwt X-Authentik-Meta-Jwks X-Authentik-Meta-Outpost X-Authentik-Meta-Provider X-Authentik-Meta-App X-Authentik-Meta-Version
}
```

- [ ] **Step 6: Write `security-headers.caddy`**

File: `unified-stack/templates/caddy/snippets/security-headers.caddy`
```caddyfile
header {
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    X-Frame-Options "SAMEORIGIN"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
    Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; upgrade-insecure-requests"
    -Server
    -X-Powered-By
}
```

- [ ] **Step 7: Write `souin-cache.caddy`**

File: `unified-stack/templates/caddy/snippets/souin-cache.caddy`
```caddyfile
# Per-route Souin cache policy. Use this inside a handle block to enable caching.
# Default TTL 10m (set globally), override per-route if needed.
cache {
    ttl 10m
    stale 1h
    default_cache_control public
}
```

- [ ] **Step 8: Validate the Caddyfile (requires plugins — use a custom image built inline)**

Because Caddyfile uses plugin-provided directives (`coraza_waf`, `crowdsec`, `cache`), vanilla `caddy:2` can't validate. Skip full validation until the real build image is available (end of Task 11). For now, syntax-only:

Run:
```bash
docker run --rm -v "${PWD}/unified-stack/templates/caddy:/etc/caddy" caddy:2 caddy fmt /etc/caddy/Caddyfile --overwrite 2>&1 | head -20
```
Expected: completes without error; file reformatted in place (the overwrite is idempotent — running it again produces no diff).

- [ ] **Step 9: Commit**

```bash
git add unified-stack/templates/caddy/
git commit -m "Add Caddyfile with reusable policy snippets"
```

---

## Task 5: Coraza WAF configuration

**Files:**
- Create: `unified-stack/templates/caddy/coraza/coraza.conf`
- Create: `unified-stack/templates/caddy/coraza/crs-setup.conf`
- Add fetch instructions for: `unified-stack/templates/caddy/coraza/rules/` (OWASP CRS 4.x)

- [ ] **Step 1: Write `coraza.conf`**

File: `unified-stack/templates/caddy/coraza/coraza.conf`
```apache
# Coraza core engine configuration — minimal, CRS provides the rules.
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction Reject
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ
SecAuditLog /var/log/caddy/coraza-audit.log
SecAuditLogFormat JSON
SecArgumentSeparator &
SecCookieFormat 0
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
```

- [ ] **Step 2: Write `crs-setup.conf`**

File: `unified-stack/templates/caddy/coraza/crs-setup.conf`
```apache
# OWASP Core Rule Set 4.x initial tuning.
# Paranoia level 1 (default, fewest false positives). Raise after observation.
SecAction \
    "id:900000,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.blocking_paranoia_level=1,\
     setvar:tx.detection_paranoia_level=1,\
     setvar:tx.enforce_bodyproc_urlencoded=1,\
     setvar:tx.crs_validate_utf8_encoding=1,\
     setvar:tx.arg_name_length=100,\
     setvar:tx.arg_length=400,\
     setvar:tx.total_arg_length=64000,\
     setvar:tx.max_num_args=255,\
     setvar:tx.max_file_size=1048576,\
     setvar:tx.combined_file_sizes=1048576"

# Inbound/outbound anomaly thresholds at which requests are blocked.
SecAction \
    "id:900110,\
     phase:1,\
     nolog,\
     pass,\
     t:none,\
     setvar:tx.inbound_anomaly_score_threshold=5,\
     setvar:tx.outbound_anomaly_score_threshold=4"
```

- [ ] **Step 3: Document CRS rules fetch**

The OWASP CRS 4.x `rules/*.conf` set is fetched at build time. Add a fetch step to `docker-host-config.sh` (Task 17) and a placeholder README in `rules/`:

File: `unified-stack/templates/caddy/coraza/rules/README.md`
```markdown
# OWASP CRS 4.x rule files

This directory is populated by `docker-host-config.sh` (or manually):

```bash
CRS_VERSION=v4.7.0
curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
  | tar -xz --strip-components=2 -C . "coreruleset-${CRS_VERSION#v}/rules"
```

Pinning: any 4.x release. Upgrade by bumping `CRS_VERSION` in `docker-host-config.sh`.
```

Remove the `.gitkeep` placeholder created in Task 1 so the README replaces it:
```bash
rm -f unified-stack/templates/caddy/coraza/rules/.gitkeep
```

- [ ] **Step 4: Commit**

```bash
git add unified-stack/templates/caddy/coraza/
git commit -m "Add Coraza WAF config + OWASP CRS fetch instructions"
```

---

## Task 6: Crowdsec templates

**Files:**
- Create: `unified-stack/templates/crowdsec/config.yaml`
- Create: `unified-stack/templates/crowdsec/acquis.yaml`
- Create: `unified-stack/templates/crowdsec/profiles.yaml`

- [ ] **Step 1: Write `config.yaml`**

File: `unified-stack/templates/crowdsec/config.yaml`
```yaml
common:
  daemonize: false
  log_media: stdout
  log_level: info
  working_dir: /var/lib/crowdsec
config_paths:
  config_dir: /etc/crowdsec/
  data_dir: /var/lib/crowdsec/data/
  simulation_path: /etc/crowdsec/simulation.yaml
  hub_dir: /etc/crowdsec/hub/
  index_path: /etc/crowdsec/hub/.index.json
  notification_dir: /etc/crowdsec/notifications/
  plugin_dir: /usr/local/lib/crowdsec/plugins/
crowdsec_service:
  acquisition_path: /etc/crowdsec/acquis.yaml
  parser_routines: 1
cscli:
  output: human
db_config:
  log_level: info
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
api:
  client:
    insecure_skip_verify: false
    credentials_path: /etc/crowdsec/local_api_credentials.yaml
  server:
    log_level: info
    listen_uri: 0.0.0.0:8080
    profiles_path: /etc/crowdsec/profiles.yaml
    online_client:
      credentials_path: /etc/crowdsec/online_api_credentials.yaml
prometheus:
  enabled: true
  level: full
  listen_addr: 0.0.0.0
  listen_port: 6060
```

- [ ] **Step 2: Write `acquis.yaml`**

File: `unified-stack/templates/crowdsec/acquis.yaml`
```yaml
---
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
poll_without_inotify: false
---
listen_addr: 127.0.0.1:7422
source: syslog
labels:
  type: syslog
```

- [ ] **Step 3: Write `profiles.yaml`**

File: `unified-stack/templates/crowdsec/profiles.yaml`
```yaml
name: default_ip_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    duration: 4h
notifications:
  - file_default
on_success: break
---
name: default_range_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
  - type: ban
    duration: 4h
notifications:
  - file_default
on_success: break
```

Plus the file notification configuration:

File: `unified-stack/templates/crowdsec/notifications/file.yaml`
```yaml
type: file
name: file_default
log_level: info
format: |
  {"ts":"{{ .StartAt }}","source":"crowdsec","type":"{{ .Meta.service }}","scenario":"{{ .Scenario }}","message":"{{ .Message }}","events_count":{{ .EventsCount }},"capacity":{{ .Capacity }},"leaky_speed":"{{ .Leakspeed }}","decisions":[{{- range $i, $d := .Decisions }}{{ if $i }},{{ end }}{"value":"{{ $d.Value }}","scope":"{{ $d.Scope }}","type":"{{ $d.Type }}","duration":"{{ $d.Duration }}"}{{- end }}]}
log_file_path: /etc/crowdsec/notifications/decisions.log
```

- [ ] **Step 4: Validate YAML**

Run:
```bash
docker run --rm -v "${PWD}/unified-stack/templates/crowdsec:/data" cytopia/yamllint -d '{extends: default, rules: {line-length: disable, document-start: disable}}' /data/
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add unified-stack/templates/crowdsec/
git commit -m "Add Crowdsec config with file-notification output for Wazuh ingestion"
```

---

## Task 7: Postgres init script

**File:** Create `unified-stack/templates/postgres/init.d/00-create-app-dbs.sh`

- [ ] **Step 1: Write the script**

File: `unified-stack/templates/postgres/init.d/00-create-app-dbs.sh`
```bash
#!/bin/bash
# Idempotently provision role + database for every APP with a
# complete triple of ${APP}_DB_NAME / ${APP}_DB_USER / ${APP}_DB_PASSWORD
# environment variables set.
#
# Runs inside the pgvector/pgvector container as part of its initdb
# hook (see docker-compose.yml for the mount target
# /docker-entrypoint-initdb.d/).
set -euo pipefail

env | grep -oE '^[A-Z0-9]+_DB_NAME=' | sed 's/_DB_NAME=//' | while read -r APP; do
    db_var="${APP}_DB_NAME"
    user_var="${APP}_DB_USER"
    pw_var="${APP}_DB_PASSWORD"

    db="${!db_var:-}"
    user="${!user_var:-}"
    pw="${!pw_var:-}"

    if [ -z "$db" ] || [ -z "$user" ] || [ -z "$pw" ]; then
        echo "Skipping $APP: incomplete triple (DB=$db, USER=$user, PW is $([ -z "$pw" ] && echo empty || echo set))"
        continue
    fi

    echo "Provisioning $APP -> database '$db' owned by '$user'"

    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        SELECT 'CREATE ROLE $user LOGIN PASSWORD ''$pw'''
            WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$user')\gexec
        SELECT 'CREATE DATABASE $db OWNER $user'
            WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db')\gexec
        GRANT ALL PRIVILEGES ON DATABASE $db TO $user;
EOSQL
done

echo "Provisioning complete."
```

- [ ] **Step 2: Mark executable**

Run:
```bash
chmod +x unified-stack/templates/postgres/init.d/00-create-app-dbs.sh
```

(On Windows host, this is a no-op — the committed file mode is what matters to Linux readers. Set git's exec bit instead: `git update-index --chmod=+x unified-stack/templates/postgres/init.d/00-create-app-dbs.sh`.)

- [ ] **Step 3: Validate with shellcheck**

Run:
```bash
docker run --rm -v "${PWD}/unified-stack/templates/postgres:/mnt" -w /mnt koalaman/shellcheck:stable init.d/00-create-app-dbs.sh
```
Expected: no errors. `SC2016` on `${!var}` is a false positive (we need indirect expansion here).

- [ ] **Step 4: Commit**

```bash
git add unified-stack/templates/postgres/init.d/00-create-app-dbs.sh
git commit -m "Add idempotent per-app Postgres role+DB provisioner"
```

---

## Task 8: Falco templates

**Files:**
- Create: `unified-stack/templates/falco/falco.yaml`
- Create: `unified-stack/templates/falco/falco_rules.local.yaml`

- [ ] **Step 1: Write `falco.yaml`**

File: `unified-stack/templates/falco/falco.yaml`
```yaml
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d

engine:
  kind: modern_ebpf
  modern_ebpf:
    cpus_for_each_buffer: 2
    drop_failed_exit: true

json_output: true
json_include_output_property: true
json_include_tags_property: true

log_stderr: true
log_syslog: false
log_level: info
priority: notice

buffered_outputs: false

syscall_event_drops:
  actions:
    - log
    - alert
  rate: 0.03333
  max_burst: 10

syscall_event_timeouts:
  max_consecutives: 1000

outputs:
  rate: 1
  max_burst: 1000

stdout_output:
  enabled: false

file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.log

http_output:
  enabled: false

program_output:
  enabled: false

grpc:
  enabled: false

grpc_output:
  enabled: false

webserver:
  enabled: false

metadata_download:
  max_mb: 100
  chunk_wait_us: 1000
  watch_freq_sec: 1
```

- [ ] **Step 2: Write `falco_rules.local.yaml`**

File: `unified-stack/templates/falco/falco_rules.local.yaml`
```yaml
# Custom rules layered on top of the Falco stock ruleset.
# Rule IDs scoped in 100300–100399 (maps to Wazuh rule range).

- rule: Unauthorized Docker API access
  desc: >
    A container talks to the Docker API through an unexpected socket-proxy.
    Legitimate talkers are: homepage, autoheal, crowdsec, wazuh-manager.
  condition: >
    evt.type in (connect, socketcall)
    and fd.name in ("/var/run/docker.sock","dockerproxy")
    and not container.name in (autoheal, crowdsec, wazuh-manager, homepage, socket-proxy-ro, socket-proxy-rw)
  output: >
    Unauthorized container contacted Docker API
    (container=%container.name image=%container.image.repository
    fd=%fd.name proc=%proc.cmdline)
  priority: CRITICAL
  tags: [container, docker, mitre_privilege_escalation]

- rule: Write below read-only filesystem
  desc: Container writes to a path that should be read-only.
  condition: >
    (evt.type in (open,openat,openat2) and evt.is_open_write=true)
    and container.id != host
    and fd.name startswith /etc
    and not proc.name in (authentik, postgres, redis-server, wazuh-manager)
  output: >
    Write to /etc by container
    (container=%container.name proc=%proc.cmdline file=%fd.name)
  priority: ERROR
  tags: [filesystem, container]

- rule: Reverse shell in container
  desc: >
    Detects patterns of interactive remote shells (bash -i, nc -e, etc.)
    inside any container.
  condition: >
    spawned_process
    and container.id != host
    and (
      (proc.name = bash and proc.cmdline contains "-i")
      or (proc.name in (nc, ncat) and proc.cmdline contains "-e")
      or (proc.name = socat and proc.cmdline contains "EXEC:")
    )
  output: >
    Possible reverse shell
    (container=%container.name proc=%proc.cmdline user=%user.name)
  priority: CRITICAL
  tags: [container, shell, mitre_execution]

- rule: Sensitive mount by container
  desc: Container mounts a sensitive host path.
  condition: >
    spawned_process
    and container.id != host
    and (
      proc.cmdline contains "/proc/"
      or proc.cmdline contains "/etc/shadow"
      or proc.cmdline contains "/root/.ssh"
    )
  output: >
    Container accessed sensitive host path
    (container=%container.name proc=%proc.cmdline)
  priority: WARNING
  tags: [container, filesystem]
```

- [ ] **Step 3: Validate YAML**

Run:
```bash
docker run --rm -v "${PWD}/unified-stack/templates/falco:/data" cytopia/yamllint -d '{extends: default, rules: {line-length: disable, document-start: disable}}' /data/
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add unified-stack/templates/falco/
git commit -m "Add Falco config with modern_ebpf + custom container rules"
```

---

## Task 9: Zeek templates

**Files:**
- Create: `unified-stack/templates/zeek/local.zeek`
- Create: `unified-stack/templates/zeek/node.cfg`
- Create: `unified-stack/templates/zeek/networks.cfg`

- [ ] **Step 1: Write `local.zeek`**

File: `unified-stack/templates/zeek/local.zeek`
```zeek
# Load defaults + frameworks we use.
@load policy/tuning/defaults
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssh/software
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/http/detect-sqli
@load policy/frameworks/files/hash-all-files

# Emit JSON instead of TSV — Wazuh decoders parse JSON.
redef LogAscii::use_json = T;

# Intel framework: read feeds dropped into /usr/local/zeek/intel/ by the
# nightly zeek-intel-refresh.sh script. Each file must be a Zeek Intel
# TSV (see https://docs.zeek.org/en/current/frameworks/intel.html).
@load frameworks/intel/seen
redef Intel::read_files += {
    "/usr/local/zeek/intel/urlhaus.tsv",
    "/usr/local/zeek/intel/feodo.tsv",
    "/usr/local/zeek/intel/crowdstrike-domains.tsv",
};

# Tune noticed: promote Intel::Notice to an action-worthy event.
hook Notice::policy(n: Notice::Info) {
    if ( n$note == Intel::Notice ) {
        add n$actions[Notice::ACTION_LOG];
    }
}
```

- [ ] **Step 2: Write `node.cfg`**

File: `unified-stack/templates/zeek/node.cfg`
```ini
# Cluster topology. ZEEK_WORKER_COUNT in .env controls worker count
# via envsubst during docker-host-config.sh template copy.
# Defaults match the HIGH tier (4 workers).

[logger]
type=logger
host=localhost

[manager]
type=manager
host=localhost

[proxy-1]
type=proxy
host=localhost

[worker-1]
type=worker
host=localhost
interface=af_packet::eth0
lb_method=custom
lb_procs=${ZEEK_WORKER_COUNT:-4}
```

- [ ] **Step 3: Write `networks.cfg`**

File: `unified-stack/templates/zeek/networks.cfg`
```text
# Local networks Zeek should consider internal for logging context.
10.0.10.0/24    ingress
10.0.11.0/24    auth
10.0.12.0/24    data
10.0.13.0/24    observability
10.0.14.0/24    media
10.0.15.0/24    productivity
10.0.16.0/24    smarthome
100.64.0.0/10   tailscale_cgnat
172.17.0.0/16   docker_default_bridge
```

- [ ] **Step 4: Create an empty intel README**

File: `unified-stack/templates/zeek/intel/README.md`
```markdown
# Zeek Intel feeds

Populated nightly by `scripts/zeek-intel-refresh.sh` (Task 16). Each `.tsv`
file is a Zeek Intel file per the docs:
<https://docs.zeek.org/en/current/frameworks/intel.html>

Formats downloaded:
- `urlhaus.tsv` — URLhaus indicator feed
- `feodo.tsv` — Feodo tracker IP/domain feed
- `crowdstrike-domains.tsv` — CrowdStrike free malicious domain list

If any feed fails to download, the previous version is retained (never
leave Zeek with an empty Intel framework).
```

Remove the `.gitkeep` placeholder:
```bash
rm -f unified-stack/templates/zeek/intel/.gitkeep
```

- [ ] **Step 5: Commit**

```bash
git add unified-stack/templates/zeek/
git commit -m "Add Zeek cluster config with JSON output + Intel framework"
```

---

## Task 10: Wazuh templates (decoders, rules, ISM, agent config)

**Files (11 total):**
- Create: `unified-stack/templates/wazuh/decoders/caddy_json.xml`
- Create: `unified-stack/templates/wazuh/decoders/crowdsec_decision.xml`
- Create: `unified-stack/templates/wazuh/decoders/falco_json.xml`
- Create: `unified-stack/templates/wazuh/decoders/zeek_conn.xml`
- Create: `unified-stack/templates/wazuh/decoders/zeek_dns.xml`
- Create: `unified-stack/templates/wazuh/decoders/zeek_ssl.xml`
- Create: `unified-stack/templates/wazuh/decoders/zeek_notice.xml`
- Create: `unified-stack/templates/wazuh/rules/caddy_rules.xml`
- Create: `unified-stack/templates/wazuh/rules/crowdsec_rules.xml`
- Create: `unified-stack/templates/wazuh/rules/falco_rules.xml`
- Create: `unified-stack/templates/wazuh/rules/zeek_rules.xml`
- Create: `unified-stack/templates/wazuh/ism-policy.json`
- Create: `unified-stack/templates/wazuh/agent-host.conf`

- [ ] **Step 1: Write `caddy_json.xml` decoder**

File: `unified-stack/templates/wazuh/decoders/caddy_json.xml`
```xml
<decoder name="caddy-json">
  <prematch>^\{"level":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

- [ ] **Step 2: Write `crowdsec_decision.xml` decoder**

File: `unified-stack/templates/wazuh/decoders/crowdsec_decision.xml`
```xml
<decoder name="crowdsec-decision">
  <prematch>^\{"ts":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

- [ ] **Step 3: Write `falco_json.xml` decoder**

File: `unified-stack/templates/wazuh/decoders/falco_json.xml`
```xml
<decoder name="falco-json">
  <prematch>^\{"output":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

- [ ] **Step 4: Write each Zeek decoder**

File: `unified-stack/templates/wazuh/decoders/zeek_conn.xml`
```xml
<decoder name="zeek-conn">
  <prematch>^\{"ts":.+"id.orig_h":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

File: `unified-stack/templates/wazuh/decoders/zeek_dns.xml`
```xml
<decoder name="zeek-dns">
  <prematch>^\{"ts":.+"query":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

File: `unified-stack/templates/wazuh/decoders/zeek_ssl.xml`
```xml
<decoder name="zeek-ssl">
  <prematch>^\{"ts":.+"ja3":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

File: `unified-stack/templates/wazuh/decoders/zeek_notice.xml`
```xml
<decoder name="zeek-notice">
  <prematch>^\{"ts":.+"note":</prematch>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

- [ ] **Step 5: Write `caddy_rules.xml`**

File: `unified-stack/templates/wazuh/rules/caddy_rules.xml`
```xml
<group name="caddy,web,">
  <rule id="100100" level="0">
    <decoded_as>caddy-json</decoded_as>
    <description>Caddy access log (base).</description>
  </rule>

  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="status">^4\d\d$</field>
    <description>Caddy 4xx response.</description>
  </rule>

  <rule id="100102" level="8">
    <if_sid>100100</if_sid>
    <field name="status">^5\d\d$</field>
    <description>Caddy 5xx response.</description>
  </rule>

  <rule id="100110" level="10">
    <if_sid>100100</if_sid>
    <field name="logger">http.log.access.coraza</field>
    <description>Coraza WAF blocked a request.</description>
    <group>waf,attack,</group>
  </rule>

  <rule id="100120" level="12">
    <if_sid>100100</if_sid>
    <field name="headers.X-Crowdsec-Decision">\.+</field>
    <description>Crowdsec bouncer denied a request at Caddy.</description>
    <group>crowdsec,attack,</group>
  </rule>
</group>
```

- [ ] **Step 6: Write `crowdsec_rules.xml`**

File: `unified-stack/templates/wazuh/rules/crowdsec_rules.xml`
```xml
<group name="crowdsec,">
  <rule id="100200" level="0">
    <decoded_as>crowdsec-decision</decoded_as>
    <description>Crowdsec decision event (base).</description>
  </rule>

  <rule id="100201" level="10">
    <if_sid>100200</if_sid>
    <field name="decisions">"type":"ban"</field>
    <description>Crowdsec issued a ban decision.</description>
    <group>crowdsec_ban,</group>
  </rule>

  <rule id="100202" level="12">
    <if_sid>100200</if_sid>
    <field name="source">capi</field>
    <description>Community blocklist IP seen targeting this host.</description>
    <group>crowdsec_capi,</group>
  </rule>

  <rule id="100210" level="12">
    <if_sid>100200</if_sid>
    <field name="type">pg_backup_failed</field>
    <description>Postgres backup failed — pruning is paused until next success.</description>
    <group>ops,backup,</group>
  </rule>
</group>
```

- [ ] **Step 7: Write `falco_rules.xml`**

File: `unified-stack/templates/wazuh/rules/falco_rules.xml`
```xml
<group name="falco,container,">
  <rule id="100300" level="0">
    <decoded_as>falco-json</decoded_as>
    <description>Falco event (base).</description>
  </rule>

  <rule id="100301" level="6">
    <if_sid>100300</if_sid>
    <field name="priority">Notice</field>
    <description>Falco notice event.</description>
  </rule>

  <rule id="100302" level="9">
    <if_sid>100300</if_sid>
    <field name="priority">Warning</field>
    <description>Falco warning event.</description>
  </rule>

  <rule id="100303" level="12">
    <if_sid>100300</if_sid>
    <field name="priority">Error</field>
    <description>Falco error event.</description>
  </rule>

  <rule id="100304" level="15">
    <if_sid>100300</if_sid>
    <field name="priority">Critical</field>
    <description>Falco critical event — likely runtime attack.</description>
    <group>attack,</group>
  </rule>
</group>
```

- [ ] **Step 8: Write `zeek_rules.xml`**

File: `unified-stack/templates/wazuh/rules/zeek_rules.xml`
```xml
<group name="zeek,network,">
  <rule id="100400" level="0">
    <decoded_as>zeek-conn</decoded_as>
    <description>Zeek conn.log event (base).</description>
  </rule>

  <rule id="100420" level="0">
    <decoded_as>zeek-dns</decoded_as>
    <description>Zeek dns.log event (base).</description>
  </rule>

  <rule id="100440" level="0">
    <decoded_as>zeek-ssl</decoded_as>
    <description>Zeek ssl.log event (base).</description>
  </rule>

  <rule id="100460" level="0">
    <decoded_as>zeek-notice</decoded_as>
    <description>Zeek notice.log event (base).</description>
  </rule>

  <rule id="100470" level="13">
    <if_sid>100460</if_sid>
    <field name="note">Intel::Notice</field>
    <description>Zeek Intel framework matched a threat-intel indicator.</description>
    <group>threat_intel,attack,</group>
  </rule>

  <rule id="100471" level="10">
    <if_sid>100460</if_sid>
    <field name="note">SSL::Invalid_Server_Cert</field>
    <description>Zeek saw an invalid TLS server certificate.</description>
  </rule>
</group>
```

- [ ] **Step 9: Write `ism-policy.json`**

File: `unified-stack/templates/wazuh/ism-policy.json`
```json
{
  "policy": {
    "policy_id": "wazuh_retention",
    "description": "Retain wazuh indices for WAZUH_INDEXER_RETENTION_DAYS, then delete.",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "${WAZUH_INDEXER_RETENTION_DAYS}d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
        "priority": 100
      }
    ]
  }
}
```

Note: `${WAZUH_INDEXER_RETENTION_DAYS}` is substituted by `docker-host-config.sh` using `envsubst` when the template is copied to `/dock/conf/wazuh/`.

- [ ] **Step 10: Write `agent-host.conf`**

File: `unified-stack/templates/wazuh/agent-host.conf`
```xml
<!-- Snippet appended to /var/ossec/etc/ossec.conf on the host by
     scripts/wazuh-agent-ingest.sh (Task 16). Tails four bind-mounted
     log files produced by containers. -->

<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/caddy/logs/access.log</location>
    <label key="@source">caddy</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/crowdsec/notifications/decisions.log</location>
    <label key="@source">crowdsec</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/falco/events.log</location>
    <label key="@source">falco</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/zeek/logs/current/conn.log</location>
    <label key="@source">zeek-conn</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/zeek/logs/current/dns.log</location>
    <label key="@source">zeek-dns</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/zeek/logs/current/ssl.log</location>
    <label key="@source">zeek-ssl</label>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/dock/conf/zeek/logs/current/notice.log</location>
    <label key="@source">zeek-notice</label>
  </localfile>
</ossec_config>
```

- [ ] **Step 11: Validate XML**

Run:
```bash
for f in unified-stack/templates/wazuh/decoders/*.xml unified-stack/templates/wazuh/rules/*.xml unified-stack/templates/wazuh/agent-host.conf; do
  docker run --rm -v "${PWD}/$f:/tmp/file.xml" alpine:3 sh -c 'apk add --no-cache libxml2-utils >/dev/null && xmllint --noout /tmp/file.xml' && echo "OK: $f"
done
```
Expected: all files print `OK: <file>`.

- [ ] **Step 12: Validate JSON**

Run:
```bash
docker run --rm -v "${PWD}/unified-stack/templates/wazuh/ism-policy.json:/tmp/file.json" alpine:3 sh -c 'apk add --no-cache jq >/dev/null && jq empty /tmp/file.json'
```
Expected: no output (valid JSON). Note: the `${VAR}` placeholder is still valid JSON because it's inside a string.

- [ ] **Step 13: Commit**

```bash
git add unified-stack/templates/wazuh/
git commit -m "Add Wazuh decoders, rules, ISM policy, and host-agent localfile config"
```

---

## Task 11: Docker Compose — networks & anchors

**File:** Create `unified-stack/docker-compose.yml` (first slice only; subsequent tasks append).

- [ ] **Step 1: Write the networks + anchors header**

File: `unified-stack/docker-compose.yml` (initial content)
```yaml
# Unified foundation stack. See docs/superpowers/specs/ for the full design.
# All resource knobs come from .env; uncomment ONE tier block there.

x-hardened: &hardened
  user: "1010:1010"
  read_only: true
  tmpfs:
    - /tmp
    - /run
  security_opt:
    - no-new-privileges:true
    - seccomp:default
  cap_drop:
    - ALL
  restart: unless-stopped
  labels:
    - autoheal=true

x-logging: &default-logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"

networks:
  ingress:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.10.0/24
          gateway: 10.0.10.10
  auth:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.11.0/24
          gateway: 10.0.11.10
  data:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.12.0/24
          gateway: 10.0.12.10
  observability:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.13.0/24
          gateway: 10.0.13.10

services: {}
```

- [ ] **Step 2: Validate**

Run (requires `.env` in same dir; create a minimal stub):
```bash
cd unified-stack
cp .env.example .env
docker compose config --quiet
cd ..
```
Expected: no output, exit 0. The warning about empty env vars is fine — compose only errors on syntax/schema.

- [ ] **Step 3: Commit**

```bash
git add unified-stack/docker-compose.yml
git commit -m "Scaffold docker-compose.yml with networks + shared anchors"
```

---

## Task 12: Compose — foundation services (Tailscale, Caddy, Crowdsec, socket-proxies, Autoheal)

**File:** Modify `unified-stack/docker-compose.yml`

Replace the `services: {}` line with the block below, and leave the anchors/networks unchanged.

- [ ] **Step 1: Add `tailscale-ingress` service**

Modify `unified-stack/docker-compose.yml` — replace `services: {}` with:
```yaml
services:
  # ==========================================================
  # Tailscale ingress sidecar — caddy shares this netns.
  # ==========================================================
  tailscale-ingress:
    image: tailscale/tailscale:latest
    container_name: tailscale-ingress
    hostname: ${TAILSCALE_INGRESS_HOSTNAME}
    environment:
      TS_AUTHKEY: ${TAILSCALE_AUTHKEY}
      TS_STATE_DIR: /var/lib/tailscale
      TS_USERSPACE: "false"
      TS_ENABLE_HEALTH_CHECK: "true"
      TS_LOCAL_ADDR_PORT: 127.0.0.1:41234
      TS_ACCEPT_DNS: "true"
      TS_EXTRA_ARGS: --advertise-tags=tag:ingress
    volumes:
      - ${DOCK_TAIL}/ingress:/var/lib/tailscale
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
    networks:
      ingress:
        ipv4_address: 10.0.10.200
      auth:
        ipv4_address: 10.0.11.200
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://127.0.0.1:41234/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging: *default-logging
```

- [ ] **Step 2: Add `caddy` service**

Append inside `services:`
```yaml
  caddy:
    <<: *hardened
    build:
      context: ./build/caddy
    container_name: caddy
    depends_on:
      tailscale-ingress:
        condition: service_healthy
      crowdsec:
        condition: service_healthy
      authentik-server:
        condition: service_healthy
    environment:
      ADMIN_EMAIL: ${ADMIN_EMAIL}
      PUBLIC_FQDN: ${PUBLIC_FQDN}
      TAILNET_FQDN: ${TAILNET_FQDN}
      EXTRA_ALLOWED_IP: ${EXTRA_ALLOWED_IP}
      CADDY_LOG_LEVEL: ${CADDY_LOG_LEVEL}
      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}
      CROWDSEC_BOUNCER_KEY: ${CROWDSEC_BOUNCER_KEY}
      REDIS_PASSWORD: ${REDIS_PASSWORD}
      REDIS_DB_CADDY_CACHE: ${REDIS_DB_CADDY_CACHE}
    volumes:
      - ${DOCK_CONF}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ${DOCK_CONF}/caddy/snippets:/etc/caddy/snippets:ro
      - ${DOCK_CONF}/caddy/coraza:/etc/caddy/coraza:ro
      - ${DOCK_CONF}/caddy/data:/data
      - ${DOCK_CONF}/caddy/logs:/var/log/caddy
      - ${DOCK_CONF}/caddy/souin:/var/cache/souin
    network_mode: "service:tailscale-ingress"
    mem_limit: ${CADDY_MEM_LIMIT:-2g}
    cpus: ${CADDY_CPUS:-2}
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://127.0.0.1:2019/config/"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
    logging: *default-logging
    read_only: false  # Caddy's /data needs write access — socketed volume not enough
```

- [ ] **Step 3: Add `crowdsec` service**

Append:
```yaml
  crowdsec:
    <<: *hardened
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      GID: "1010"
      COLLECTIONS: "crowdsecurity/caddy crowdsecurity/linux crowdsecurity/iptables"
      PARSERS: "crowdsecurity/caddy-logs crowdsecurity/whitelists"
    volumes:
      - ${DOCK_CONF}/crowdsec/config.yaml:/etc/crowdsec/config.yaml:ro
      - ${DOCK_CONF}/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro
      - ${DOCK_CONF}/crowdsec/profiles.yaml:/etc/crowdsec/profiles.yaml:ro
      - ${DOCK_CONF}/crowdsec/notifications:/etc/crowdsec/notifications
      - ${DOCK_CONF}/crowdsec/db:/var/lib/crowdsec/data
      - ${DOCK_CONF}/caddy/logs:/var/log/caddy:ro
    networks:
      observability:
        ipv4_address: 10.0.13.20
      ingress:
        ipv4_address: 10.0.10.21
    mem_limit: ${CROWDSEC_MEM_LIMIT:-1g}
    healthcheck:
      test: ["CMD", "cscli", "lapi", "status"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    read_only: false
    logging: *default-logging
```

- [ ] **Step 4: Add socket-proxy-ro, socket-proxy-rw, autoheal**

Append:
```yaml
  socket-proxy-ro:
    <<: *hardened
    image: tecnativa/docker-socket-proxy:latest
    container_name: socket-proxy-ro
    environment:
      CONTAINERS: "1"
      SERVICES: "1"
      TASKS: "1"
      NETWORKS: "1"
      IMAGES: "1"
      INFO: "1"
      EVENTS: "1"
      VERSION: "1"
      POST: "0"
      ALLOW_START: "0"
      ALLOW_STOP: "0"
      ALLOW_RESTARTS: "0"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      observability:
        ipv4_address: 10.0.13.21
      ingress:
        ipv4_address: 10.0.10.21
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:2375/_ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    read_only: false
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    logging: *default-logging

  socket-proxy-rw:
    <<: *hardened
    image: tecnativa/docker-socket-proxy:latest
    container_name: socket-proxy-rw
    environment:
      CONTAINERS: "1"
      SERVICES: "1"
      TASKS: "1"
      NETWORKS: "1"
      IMAGES: "1"
      INFO: "1"
      EVENTS: "1"
      VERSION: "1"
      POST: "1"
      ALLOW_START: "1"
      ALLOW_STOP: "1"
      ALLOW_RESTARTS: "1"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      observability:
        ipv4_address: 10.0.13.22
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:2375/_ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    read_only: false
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    logging: *default-logging

  autoheal:
    <<: *hardened
    image: willfarrell/autoheal:latest
    container_name: autoheal
    depends_on:
      socket-proxy-rw:
        condition: service_healthy
    environment:
      AUTOHEAL_CONTAINER_LABEL: autoheal
      AUTOHEAL_INTERVAL: "30"
      DOCKER_SOCK: "tcp://socket-proxy-rw:2375"
      CURL_TIMEOUT: "30"
    networks:
      - observability
    mem_limit: 256m
    read_only: false  # container writes internal state
    logging: *default-logging
```

- [ ] **Step 5: Validate**

Run:
```bash
cd unified-stack && docker compose config --quiet && cd ..
```
Expected: no output, exit 0. (References to `authentik-server` in caddy's `depends_on` won't fail the config check — compose validates shape, not cross-refs at this stage.)

- [ ] **Step 6: Commit**

```bash
git add unified-stack/docker-compose.yml
git commit -m "Compose: add tailscale-ingress, caddy, crowdsec, socket-proxies, autoheal"
```

---

## Task 13: Compose — stateful services (Postgres, Redis, postgres-init)

**File:** Modify `unified-stack/docker-compose.yml`

- [ ] **Step 1: Add `postgres`, `redis`, `postgres-init`**

Append inside `services:`
```yaml
  postgres:
    image: pgvector/pgvector:pg16
    container_name: postgres
    environment:
      POSTGRES_USER: ${POSTGRES_SUPERUSER}
      POSTGRES_PASSWORD: ${POSTGRES_SUPERUSER_PASSWORD}
      POSTGRES_DB: postgres
      POSTGRES_INITDB_ARGS: ${POSTGRES_INITDB_ARGS}
      # Per-app triples consumed by 00-create-app-dbs.sh
      AUTHENTIK_DB_NAME: ${AUTHENTIK_DB_NAME}
      AUTHENTIK_DB_USER: ${AUTHENTIK_DB_USER}
      AUTHENTIK_DB_PASSWORD: ${AUTHENTIK_DB_PASSWORD}
    volumes:
      - ${DOCK_DB}/postgres/data:/var/lib/postgresql/data
      - ${DOCK_DB}/postgres/init.d:/docker-entrypoint-initdb.d:ro
    command:
      - postgres
      - -c
      - shared_buffers=${POSTGRES_SHARED_BUFFERS:-1GB}
      - -c
      - effective_cache_size=${POSTGRES_EFFECTIVE_CACHE_SIZE:-3GB}
      - -c
      - work_mem=${POSTGRES_WORK_MEM:-16MB}
      - -c
      - max_connections=${POSTGRES_MAX_CONNECTIONS:-200}
    networks:
      data:
        ipv4_address: 10.0.12.30
    mem_limit: ${POSTGRES_MEM_LIMIT:-4g}
    cpus: ${POSTGRES_CPUS:-2}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_SUPERUSER}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 20s
    restart: unless-stopped
    labels:
      - autoheal=true
    user: "1010:1010"
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - DAC_OVERRIDE
      - FOWNER
    security_opt:
      - no-new-privileges:true
    logging: *default-logging

  redis:
    <<: *hardened
    image: redis:7-alpine
    container_name: redis
    command:
      - redis-server
      - --requirepass
      - ${REDIS_PASSWORD}
      - --appendonly
      - ${REDIS_APPENDONLY}
      - --maxmemory
      - ${REDIS_MAXMEMORY}
      - --maxmemory-policy
      - allkeys-lru
      - --io-threads
      - ${REDIS_IO_THREADS}
      - --io-threads-do-reads
      - "yes"
      - --protected-mode
      - "yes"
    volumes:
      - ${DOCK_DB}/redis:/data
    networks:
      data:
        ipv4_address: 10.0.12.31
    mem_limit: ${REDIS_MEM_LIMIT:-2g}
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 10s
    read_only: false
    logging: *default-logging
```

Note on `postgres-init`: the `pgvector/pgvector` image natively runs scripts in `/docker-entrypoint-initdb.d/` on first boot of an empty `PGDATA`. That's where our `00-create-app-dbs.sh` lives (mounted RO). Therefore we do **not** need a separate `postgres-init` container; the mount handles it. Update the spec's service count accordingly when writing the README.

- [ ] **Step 2: Validate**

```bash
cd unified-stack && docker compose config --quiet && cd ..
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add unified-stack/docker-compose.yml
git commit -m "Compose: add postgres (pgvector) + redis with app-DB provisioning"
```

---

## Task 14: Compose — observability services (Wazuh trio, Falco, Zeek)

**File:** Modify `unified-stack/docker-compose.yml`

- [ ] **Step 1: Add `wazuh-indexer`**

Append:
```yaml
  wazuh-indexer:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION}
    container_name: wazuh-indexer
    environment:
      - cluster.name=wazuh-cluster
      - node.name=wazuh-indexer
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - OPENSEARCH_JAVA_OPTS=-Xms${WAZUH_INDEXER_JVM_HEAP:-2g} -Xmx${WAZUH_INDEXER_JVM_HEAP:-2g}
      - INDEXER_PASSWORD=${WAZUH_INDEXER_ADMIN_PASSWORD}
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ${DOCK_DATA}/wazuh/indexer:/var/lib/wazuh-indexer
      - ${DOCK_CONF}/wazuh/indexer:/usr/share/wazuh-indexer/opensearch.yml.d:ro
      - ${DOCK_CONF}/wazuh/certs:/usr/share/wazuh-indexer/certs:ro
    networks:
      observability:
        ipv4_address: 10.0.13.31
    mem_limit: ${WAZUH_INDEXER_MEM_LIMIT:-4g}
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u admin:${WAZUH_INDEXER_ADMIN_PASSWORD} https://localhost:9200/_cluster/health | grep -q green\\|yellow"]
      interval: 20s
      timeout: 10s
      retries: 10
      start_period: 120s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 2: Add `wazuh-manager`**

Append:
```yaml
  wazuh-manager:
    image: wazuh/wazuh-manager:${WAZUH_VERSION}
    container_name: wazuh-manager
    depends_on:
      wazuh-indexer:
        condition: service_healthy
    environment:
      INDEXER_URL: https://wazuh-indexer:9200
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: ${WAZUH_INDEXER_ADMIN_PASSWORD}
      API_USERNAME: wazuh-wui
      API_PASSWORD: ${WAZUH_API_PASSWORD}
    volumes:
      - ${DOCK_DATA}/wazuh/manager:/var/ossec/data
      - ${DOCK_CONF}/wazuh/manager:/wazuh-config-mount/etc:ro
      - ${DOCK_CONF}/wazuh/certs:/etc/ssl/wazuh:ro
      - ${DOCK_CONF}/wazuh/decoders:/var/ossec/etc/decoders/custom:ro
      - ${DOCK_CONF}/wazuh/rules:/var/ossec/etc/rules/custom:ro
    networks:
      observability:
        ipv4_address: 10.0.13.30
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    mem_limit: ${WAZUH_MANAGER_MEM_LIMIT:-2g}
    cap_add:
      - SYS_RESOURCE
      - SYS_PTRACE
    healthcheck:
      test: ["CMD", "/var/ossec/bin/wazuh-control", "status"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 3: Add `wazuh-dashboard`**

Append:
```yaml
  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:${WAZUH_VERSION}
    container_name: wazuh-dashboard
    depends_on:
      wazuh-indexer:
        condition: service_healthy
      wazuh-manager:
        condition: service_healthy
    environment:
      INDEXER_URL: https://wazuh-indexer:9200
      INDEXER_USERNAME: kibanaserver
      INDEXER_PASSWORD: ${WAZUH_INDEXER_KIBANASERVER_PASSWORD}
      WAZUH_API_URL: https://wazuh-manager
      DASHBOARD_USERNAME: kibanaserver
      DASHBOARD_PASSWORD: ${WAZUH_INDEXER_KIBANASERVER_PASSWORD}
    volumes:
      - ${DOCK_CONF}/wazuh/dashboard:/usr/share/wazuh-dashboard/config:ro
      - ${DOCK_CONF}/wazuh/certs:/usr/share/wazuh-dashboard/certs:ro
    networks:
      observability:
        ipv4_address: 10.0.13.32
    mem_limit: ${WAZUH_DASHBOARD_MEM_LIMIT:-1g}
    healthcheck:
      test: ["CMD", "curl", "-f", "-k", "https://localhost:5601/status"]
      interval: 20s
      timeout: 10s
      retries: 10
      start_period: 90s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 4: Add `falco`**

Append:
```yaml
  falco:
    image: falcosecurity/falco:latest
    container_name: falco
    privileged: true
    pid: host
    environment:
      FALCO_BPF_PROBE: ""
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
      - /dev:/host/dev:ro
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - /usr:/host/usr:ro
      - /etc:/host/etc:ro
      - ${DOCK_CONF}/falco/falco.yaml:/etc/falco/falco.yaml:ro
      - ${DOCK_CONF}/falco/falco_rules.local.yaml:/etc/falco/falco_rules.local.yaml:ro
      - ${DOCK_CONF}/falco/rules.d:/etc/falco/rules.d:ro
      - ${DOCK_CONF}/falco:/var/log/falco
    networks:
      observability:
        ipv4_address: 10.0.13.24
    mem_limit: ${FALCO_MEM_LIMIT:-512m}
    healthcheck:
      test: ["CMD-SHELL", "pgrep -x falco >/dev/null"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 5: Add `zeek`**

Append:
```yaml
  zeek:
    image: zeek/zeek:latest
    container_name: zeek
    network_mode: host
    environment:
      ZEEK_WORKER_COUNT: ${ZEEK_WORKER_COUNT:-2}
    volumes:
      - ${DOCK_CONF}/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro
      - ${DOCK_CONF}/zeek/node.cfg:/usr/local/zeek/etc/node.cfg:ro
      - ${DOCK_CONF}/zeek/networks.cfg:/usr/local/zeek/etc/networks.cfg:ro
      - ${DOCK_CONF}/zeek/intel:/usr/local/zeek/intel:ro
      - ${DOCK_CONF}/zeek/logs:/usr/local/zeek/logs
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
      - DAC_OVERRIDE
    command:
      - /bin/sh
      - -c
      - "zeekctl deploy && tail -f /usr/local/zeek/logs/current/stderr.log"
    mem_limit: ${ZEEK_MEM_LIMIT:-1g}
    healthcheck:
      test: ["CMD-SHELL", "zeekctl status 2>/dev/null | grep -q running"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 6: Validate**

```bash
cd unified-stack && docker compose config --quiet && cd ..
```
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add unified-stack/docker-compose.yml
git commit -m "Compose: add wazuh trio, falco, zeek observability stack"
```

---

## Task 15: Compose — Authentik pilot

**File:** Modify `unified-stack/docker-compose.yml`

- [ ] **Step 1: Add `authentik-migration`, `authentik-server`, `authentik-worker`**

Append:
```yaml
  authentik-migration:
    image: ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}
    container_name: authentik-migration
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: migrate
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgres
      AUTHENTIK_POSTGRESQL__USER: ${AUTHENTIK_DB_USER}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${AUTHENTIK_DB_PASSWORD}
      AUTHENTIK_POSTGRESQL__NAME: ${AUTHENTIK_DB_NAME}
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_REDIS__PASSWORD: ${REDIS_PASSWORD}
      AUTHENTIK_REDIS__DB: ${AUTHENTIK_REDIS_DB}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
      AUTHENTIK_DISABLE_UPDATE_CHECK: "true"
    networks:
      - auth
      - data
    restart: "no"
    logging: *default-logging

  authentik-server:
    image: ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}
    container_name: authentik-server
    depends_on:
      authentik-migration:
        condition: service_completed_successfully
    command: server
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
    volumes:
      - ${DOCK_CONF}/authentik/media:/media
      - ${DOCK_CONF}/authentik/custom-templates:/templates:ro
    networks:
      auth:
        ipv4_address: 10.0.11.20
      data:
    mem_limit: ${AUTHENTIK_SERVER_MEM_LIMIT:-2g}
    healthcheck:
      test: ["CMD", "ak", "healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging

  authentik-worker:
    image: ghcr.io/goauthentik/server:${AUTHENTIK_VERSION}
    container_name: authentik-worker
    depends_on:
      authentik-server:
        condition: service_healthy
    command: worker
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgres
      AUTHENTIK_POSTGRESQL__USER: ${AUTHENTIK_DB_USER}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${AUTHENTIK_DB_PASSWORD}
      AUTHENTIK_POSTGRESQL__NAME: ${AUTHENTIK_DB_NAME}
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_REDIS__PASSWORD: ${REDIS_PASSWORD}
      AUTHENTIK_REDIS__DB: ${AUTHENTIK_REDIS_DB}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
      AUTHENTIK_DISABLE_UPDATE_CHECK: "true"
    volumes:
      - ${DOCK_CONF}/authentik/media:/media
      - ${DOCK_CONF}/authentik/custom-templates:/templates:ro
    networks:
      auth:
        ipv4_address: 10.0.11.21
      data:
    mem_limit: ${AUTHENTIK_WORKER_MEM_LIMIT:-2g}
    healthcheck:
      test: ["CMD", "ak", "healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped
    labels:
      - autoheal=true
    logging: *default-logging
```

- [ ] **Step 2: Validate**

```bash
cd unified-stack && docker compose config --quiet && cd ..
```
Expected: exit 0.

- [ ] **Step 3: Verify service count**

```bash
cd unified-stack && docker compose config --services | sort | uniq -c | wc -l
```
Expected: `17` services (tailscale-ingress, caddy, crowdsec, socket-proxy-ro, socket-proxy-rw, autoheal, postgres, redis, wazuh-indexer, wazuh-manager, wazuh-dashboard, falco, zeek, authentik-migration, authentik-server, authentik-worker — 16 actually; spec mentioned 18 including one-shot wazuh-init which we deferred to the host-config script).

Update the spec's acceptance criterion #2 during the README task (Task 18): "brings all 16 pilot containers to healthy state".

- [ ] **Step 4: Commit**

```bash
git add unified-stack/docker-compose.yml
git commit -m "Compose: add Authentik pilot (migration + server + worker)"
```

---

## Task 16: Utility scripts (pg-backup, health-recommend, zeek-intel-refresh, wazuh-agent-ingest)

**Files:** Create four scripts in `unified-stack/scripts/`.

- [ ] **Step 1: Write `pg-backup.sh`**

File: `unified-stack/scripts/pg-backup.sh`
```bash
#!/usr/bin/env bash
# Nightly Postgres backup. Prunes old backups only after a successful new backup.
# Emits a Wazuh-pipeline alert on failure.
set -euo pipefail

# Source env for retention days + paths.
source /dock/conf/.env

BACKUP_DIR=/dock/backups/postgres
RETENTION_DAYS="${POSTGRES_BACKUP_RETENTION_DAYS:-14}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
NEW="$BACKUP_DIR/dump-${TIMESTAMP}.sql.zst"

mkdir -p "$BACKUP_DIR"

if docker exec postgres pg_dumpall -U "${POSTGRES_SUPERUSER}" 2>>/var/log/pg-backup.err \
    | zstd -T0 -19 > "${NEW}.tmp"; then
    mv "${NEW}.tmp" "${NEW}"
    find "$BACKUP_DIR" -name 'dump-*.sql.zst' -type f -mtime "+${RETENTION_DAYS}" -delete
    echo "$(date -Iseconds) pg_backup ok: $NEW (pruned >${RETENTION_DAYS}d)"
    exit 0
else
    rm -f "${NEW}.tmp"
    # Emit alert to Crowdsec decisions log — Wazuh agent picks it up as Channel B.
    printf '{"ts":"%s","source":"pg_backup","type":"pg_backup_failed","level":"CRITICAL","message":"pg_dumpall failed or zstd encoding failed","scenario":"ops:backup:failed","decisions":[]}\n' \
        "$(date -Iseconds)" >> /dock/conf/crowdsec/notifications/decisions.log
    echo "$(date -Iseconds) pg_backup FAILED" >&2
    exit 1
fi
```

- [ ] **Step 2: Write `health-recommend.sh`**

File: `unified-stack/scripts/health-recommend.sh`
```bash
#!/usr/bin/env bash
# Inspect host CPU + RAM and print a recommended tier block.
set -euo pipefail

CPUS=$(nproc)
MEM_GB=$(awk '/MemTotal/ {printf "%d\n", $2/1024/1024}' /proc/meminfo)

TIER="UNKNOWN"
if [ "$MEM_GB" -ge 48 ] && [ "$CPUS" -ge 12 ]; then
    TIER="HIGH"
elif [ "$MEM_GB" -ge 14 ] && [ "$CPUS" -ge 6 ]; then
    TIER="MED"
else
    TIER="LOW"
fi

cat <<EOF
Host inspection:
    CPUs: $CPUS
    RAM:  ${MEM_GB} GB

Recommended tier: ${TIER}

Edit /dock/conf/.env: uncomment the ${TIER} tier block, comment the others.
EOF
```

- [ ] **Step 3: Write `zeek-intel-refresh.sh`**

File: `unified-stack/scripts/zeek-intel-refresh.sh`
```bash
#!/usr/bin/env bash
# Refresh Zeek Intel framework feeds. If a feed fails to download, keep the
# previous version in place. Run from cron nightly.
set -euo pipefail

INTEL_DIR=/dock/conf/zeek/intel
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$INTEL_DIR"

refresh() {
    local name="$1" url="$2" converter="$3"
    if curl --fail --silent --show-error --max-time 120 --output "$TMP/${name}.raw" "$url"; then
        if $converter "$TMP/${name}.raw" > "$TMP/${name}.tsv"; then
            mv "$TMP/${name}.tsv" "$INTEL_DIR/${name}.tsv"
            echo "$(date -Iseconds) refreshed: $name"
        else
            echo "$(date -Iseconds) convert failed: $name (kept previous)" >&2
        fi
    else
        echo "$(date -Iseconds) download failed: $name (kept previous)" >&2
    fi
}

# Converter: URLhaus CSV -> Zeek Intel TSV (domains only, simple form).
urlhaus_to_intel() {
    # URLhaus lines: "id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"
    awk -F'","' 'NR>1 && $1 !~ /^#/ {
        # Extract the URL field ($3), strip leading quote, extract host.
        sub(/^"/, "", $3)
        u=$3; sub(/^https?:\/\//, "", u); sub(/\/.*/, "", u); sub(/:.*/, "", u);
        if (u != "") printf "%s\tIntel::DOMAIN\turlhaus\t-\tT\t-\n", u
    }' "$1"
}
feodo_to_intel() {
    awk -F',' 'NR>1 && $1 !~ /^#/ && $2 != "" {
        printf "%s\tIntel::ADDR\tfeodo\t-\tT\t-\n", $2
    }' "$1"
}
crowdstrike_to_intel() {
    awk 'NF && $1 !~ /^#/ {
        printf "%s\tIntel::DOMAIN\tcrowdstrike\t-\tT\t-\n", $1
    }' "$1"
}

# Prepend Zeek Intel header to each file.
write_header() {
    printf "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.do_notice\tmeta.if_in\n" > "$1"
}

for base in urlhaus feodo crowdstrike-domains; do
    tmp_out="$TMP/${base}.tsv"
    write_header "$tmp_out"
done

refresh urlhaus     "https://urlhaus.abuse.ch/downloads/csv_recent/" "urlhaus_to_intel"
refresh feodo       "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" "feodo_to_intel"
refresh crowdstrike-domains "https://raw.githubusercontent.com/CrowdStrike/tickeys-io/main/badlist.txt" "crowdstrike_to_intel"

# Nudge Zeek to reload (cluster management framework).
docker exec zeek zeekctl deploy >/dev/null 2>&1 || echo "$(date -Iseconds) zeek reload failed" >&2
```

Note: the CrowdStrike URL is a placeholder — if it 404s in your environment, substitute any nightly-refreshed domain feed. The script handles download failures gracefully (keeps the previous file).

- [ ] **Step 4: Write `wazuh-agent-ingest.sh`**

File: `unified-stack/scripts/wazuh-agent-ingest.sh`
```bash
#!/usr/bin/env bash
# Install custom Wazuh decoders/rules into the host-level Wazuh Agent.
# Idempotent: safe to re-run; copies files and reloads agent only if they changed.
set -euo pipefail

SRC_DIR=/dock/conf/wazuh
AGENT_ETC=/var/ossec/etc
OSSEC_CONF="$AGENT_ETC/ossec.conf"

command -v wazuh-control >/dev/null 2>&1 || {
    echo "wazuh-control not found. Install wazuh-agent first." >&2
    exit 1
}

changed=0

# Copy decoders
if ! diff -r "$SRC_DIR/decoders" "$AGENT_ETC/decoders" >/dev/null 2>&1; then
    install -d "$AGENT_ETC/decoders"
    cp -r "$SRC_DIR/decoders/"*.xml "$AGENT_ETC/decoders/"
    chown -R root:ossec "$AGENT_ETC/decoders"
    chmod 640 "$AGENT_ETC/decoders/"*.xml
    changed=1
fi

# Copy rules
if ! diff -r "$SRC_DIR/rules" "$AGENT_ETC/rules" >/dev/null 2>&1; then
    install -d "$AGENT_ETC/rules"
    cp -r "$SRC_DIR/rules/"*.xml "$AGENT_ETC/rules/"
    chown -R root:ossec "$AGENT_ETC/rules"
    chmod 640 "$AGENT_ETC/rules/"*.xml
    changed=1
fi

# Merge agent-host.conf into ossec.conf (replace the block if present).
if ! grep -q "@source.*caddy" "$OSSEC_CONF" 2>/dev/null; then
    # Insert our localfile blocks before the closing </ossec_config>.
    sed -i '/<\/ossec_config>/i <!-- BEGIN unified-stack localfiles -->' "$OSSEC_CONF"
    sed -i "/<\/ossec_config>/i $(sed -n '/<ossec_config>/,/<\/ossec_config>/p' "$SRC_DIR/agent-host.conf" | sed -e 's/<ossec_config>//' -e 's/<\/ossec_config>//' | tr '\n' '\n')" "$OSSEC_CONF"
    sed -i '/<\/ossec_config>/i <!-- END unified-stack localfiles -->' "$OSSEC_CONF"
    changed=1
fi

if [ "$changed" -eq 1 ]; then
    systemctl restart wazuh-agent
    echo "wazuh-agent restarted with updated decoders/rules/localfiles"
else
    echo "no wazuh-agent changes"
fi
```

- [ ] **Step 5: Validate all four scripts with shellcheck**

Run:
```bash
for s in unified-stack/scripts/*.sh; do
  docker run --rm -v "${PWD}:/mnt" -w /mnt koalaman/shellcheck:stable "$s"
done
```
Expected: no errors. A few `SC2016` warnings on the Intel scripts are acceptable (awk script literals).

- [ ] **Step 6: Set exec bit on all**

```bash
for s in unified-stack/scripts/*.sh; do
  git update-index --chmod=+x "$s"
done
```

- [ ] **Step 7: Commit**

```bash
git add unified-stack/scripts/
git commit -m "Add utility scripts: pg-backup, health-recommend, zeek-intel-refresh, wazuh-agent-ingest"
```

---

## Task 17: `docker-host-config.sh` — full host bootstrap

**File:** Create `unified-stack/docker-host-config.sh`

- [ ] **Step 1: Write the script**

File: `unified-stack/docker-host-config.sh`
```bash
#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 22.04+ host for the unified-stack compose.
# Idempotent: safe to re-run. Never overwrites existing user data or .env values.
set -euo pipefail

# Colour output helpers.
c_red()  { printf "\033[31m%s\033[0m\n" "$*"; }
c_grn()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_blu()  { printf "\033[34m%s\033[0m\n" "$*"; }
step()   { printf "\n\033[36m==> %s\033[0m\n" "$*"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/dock/conf/.env"
CRS_VERSION="v4.7.0"

require_root() {
    if [ "$EUID" -ne 0 ]; then
        c_red "Run as root: sudo $0"
        exit 1
    fi
}

detect_ubuntu() {
    step "Detecting OS..."
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        c_red "Unsupported OS: $ID. Ubuntu only."
        exit 1
    fi
    local major=${VERSION_ID%%.*}
    if [ "$major" -lt 22 ]; then
        c_red "Ubuntu $VERSION_ID is too old; require 22.04+."
        exit 1
    fi
    c_grn "Ubuntu $VERSION_ID OK"
}

apt_upgrade() {
    step "apt update + full-upgrade..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get full-upgrade -y -qq
    apt-get autoremove -y -qq
}

install_base_packages() {
    step "Installing base packages..."
    apt-get install -y -qq \
        curl wget jq zstd unzip \
        ca-certificates gnupg lsb-release \
        ufw fail2ban cron \
        bash-completion \
        libxml2-utils \
        openssl
}

install_docker() {
    step "Installing Docker Engine..."
    if command -v docker >/dev/null 2>&1; then
        c_grn "Docker already installed: $(docker --version)"
        return
    fi
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

install_tailscale() {
    step "Installing Tailscale..."
    if command -v tailscale >/dev/null 2>&1; then
        c_grn "Tailscale already installed: $(tailscale --version | head -1)"
        return
    fi
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(. /etc/os-release; echo "$VERSION_CODENAME").noarmor.gpg \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(. /etc/os-release; echo "$VERSION_CODENAME").tailscale-keyring.list \
        -o /etc/apt/sources.list.d/tailscale.list
    apt-get update -qq
    apt-get install -y -qq tailscale
    systemctl enable --now tailscaled
}

create_user_and_groups() {
    step "Creating docktaetor:media (1010:1010)..."
    if ! getent group media >/dev/null; then
        groupadd -g 1010 media
    fi
    if ! id docktaetor >/dev/null 2>&1; then
        useradd -m -u 1010 -g 1010 -s /bin/bash docktaetor
    fi
    usermod -aG docker docktaetor || true
}

create_dock_tree() {
    step "Creating /dock tree..."
    local dirs=(
        /dock/conf/caddy/{snippets,coraza/rules,data,logs,souin}
        /dock/conf/crowdsec/{notifications,db}
        /dock/conf/socket-proxy-ro
        /dock/conf/socket-proxy-rw
        /dock/conf/authentik/{media,custom-templates,certs}
        /dock/conf/wazuh/{manager,indexer,dashboard,certs,decoders,rules}
        /dock/conf/falco/rules.d
        /dock/conf/zeek/{intel,logs}
        /dock/data/authentik
        /dock/data/wazuh/{indexer,manager}
        /dock/db/postgres/{data,init.d}
        /dock/db/redis
        /dock/tail/ingress
        /dock/backups/postgres
        /dock/backups/redis
    )
    for d in "${dirs[@]}"; do
        install -d -o 1010 -g 1010 -m 770 "$d"
    done
    # Tighter perms on DB dirs
    chmod 700 /dock/db/postgres/data /dock/db/redis
}

copy_templates() {
    step "Copying templates to /dock/conf/..."
    local src="$REPO_DIR/templates"
    [ -d "$src" ] || { c_red "Missing $src"; exit 1; }
    # Rsync-style: copy only if target absent, never overwrite local edits.
    find "$src" -type f | while read -r f; do
        local rel="${f#"$src"/}"
        local dst="/dock/conf/${rel}"
        if [ ! -f "$dst" ]; then
            install -D -o 1010 -g 1010 -m 640 "$f" "$dst"
        fi
    done
    # Postgres init scripts go under /dock/db/postgres/init.d/
    if [ -f "$src/postgres/init.d/00-create-app-dbs.sh" ]; then
        install -D -o 1010 -g 1010 -m 750 \
            "$src/postgres/init.d/00-create-app-dbs.sh" \
            /dock/db/postgres/init.d/00-create-app-dbs.sh
    fi
}

fetch_owasp_crs() {
    step "Fetching OWASP CRS ${CRS_VERSION}..."
    local target=/dock/conf/caddy/coraza/rules
    if [ -n "$(ls "$target" 2>/dev/null | grep -E '^REQUEST-.*\.conf$' || true)" ]; then
        c_grn "CRS rules already present."
        return
    fi
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
        | tar -xz --strip-components=2 -C "$tmp" "coreruleset-${CRS_VERSION#v}/rules"
    cp -n "$tmp"/*.conf "$target/" || true
    # crs-setup example stays under the repo template; users may override.
    chown -R 1010:1010 "$target"
}

ensure_env_file() {
    step "Ensuring .env file..."
    if [ ! -f "$ENV_FILE" ]; then
        install -D -o 1010 -g 1010 -m 600 "$REPO_DIR/.env.example" "$ENV_FILE"
        c_grn "Created $ENV_FILE from .env.example"
    fi
}

generate_missing_secrets() {
    step "Generating missing secrets..."
    local key val
    # Keys that look like secrets — generate only if currently empty.
    grep -E '^[A-Z0-9_]+_(PASSWORD|KEY|TOKEN|SECRET|AUTHKEY)=$' "$ENV_FILE" | while IFS='=' read -r key _; do
        val=$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 50)
        sed -i "s|^${key}=$|${key}=${val}|" "$ENV_FILE"
        c_grn "Generated: $key"
    done
    chmod 600 "$ENV_FILE"
    chown docktaetor:media "$ENV_FILE"
}

install_wazuh_agent() {
    step "Installing Wazuh Agent..."
    if dpkg -s wazuh-agent >/dev/null 2>&1; then
        c_grn "Wazuh agent already installed."
    else
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update -qq
        WAZUH_MANAGER="127.0.0.1" apt-get install -y -qq wazuh-agent
        systemctl enable wazuh-agent
    fi
    # Install our custom decoders/rules and localfile config.
    bash "$REPO_DIR/scripts/wazuh-agent-ingest.sh"
}

install_cron_jobs() {
    step "Installing cron jobs..."
    install -m 755 "$REPO_DIR/scripts/pg-backup.sh"           /usr/local/bin/pg-backup.sh
    install -m 755 "$REPO_DIR/scripts/zeek-intel-refresh.sh"  /usr/local/bin/zeek-intel-refresh.sh
    cat > /etc/cron.d/unified-stack <<'EOF'
# Unified-stack scheduled jobs
MAILTO=""
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

0 2 * * * root /usr/local/bin/pg-backup.sh           >> /var/log/pg-backup.log 2>&1
0 3 * * * root /usr/local/bin/zeek-intel-refresh.sh  >> /var/log/zeek-intel.log 2>&1
EOF
    chmod 644 /etc/cron.d/unified-stack
}

install_systemd_units() {
    step "Installing compose-stack.service..."
    cat > /etc/systemd/system/compose-stack.service <<EOF
[Unit]
Description=Unified stack docker compose
After=docker.service tailscaled.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
User=docktaetor
Group=media
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable compose-stack.service
}

harden_ufw() {
    step "Configuring UFW..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow in on tailscale0
    ufw --force enable
}

kernel_tuning() {
    step "Applying kernel tuning..."
    cat > /etc/sysctl.d/99-unified-stack.conf <<'EOF'
net.ipv4.ip_forward = 1
vm.max_map_count = 262144
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
EOF
    sysctl -p /etc/sysctl.d/99-unified-stack.conf >/dev/null
}

health_tier_recommend() {
    step "Host-tier recommendation..."
    bash "$REPO_DIR/scripts/health-recommend.sh"
}

validate_env() {
    step "Validating docker compose config..."
    (cd "$REPO_DIR" && docker compose --env-file "$ENV_FILE" config --quiet) \
        && c_grn "compose config OK" \
        || { c_red "compose config FAILED"; exit 1; }
}

print_summary() {
    step "Summary"
    cat <<EOF

Host bootstrapped.

Next steps:
  1. Edit ${ENV_FILE}:
      - Set TAILSCALE_AUTHKEY (get one from https://login.tailscale.com/admin/settings/keys)
      - Set CLOUDFLARE_API_TOKEN (scope: Zone:read + DNS:edit on secop.dev)
      - Verify resource tier block (see the health-tier recommendation above).
  2. As the docktaetor user:
      sudo -u docktaetor bash -c 'cd ${REPO_DIR} && docker compose up --build -d'
  3. Wait ~2-3 min for all healthchecks, then:
      - https://auth.${PUBLIC_FQDN:-secop.dev}
      - https://wazuh.${PUBLIC_FQDN:-secop.dev}
      - https://auth.${TAILNET_FQDN:-neon-lenok.ts.net}

Boot persistence: systemctl status compose-stack.service
EOF
}

main() {
    require_root
    detect_ubuntu
    apt_upgrade
    install_base_packages
    install_docker
    install_tailscale
    create_user_and_groups
    create_dock_tree
    ensure_env_file
    copy_templates
    fetch_owasp_crs
    generate_missing_secrets
    install_wazuh_agent
    install_cron_jobs
    install_systemd_units
    harden_ufw
    kernel_tuning
    health_tier_recommend
    validate_env
    print_summary
}

main "$@"
```

- [ ] **Step 2: Mark executable**

```bash
git update-index --chmod=+x unified-stack/docker-host-config.sh
```

- [ ] **Step 3: Shellcheck**

Run:
```bash
docker run --rm -v "${PWD}:/mnt" -w /mnt koalaman/shellcheck:stable unified-stack/docker-host-config.sh
```
Expected: no errors. Some `SC1091` warnings (sourcing dynamic paths) are fine.

- [ ] **Step 4: Idempotence dry-check**

Since we can't run Ubuntu-only apt commands on Windows, the idempotence proof is deferred to the end-to-end acceptance test (Task 19) on the target host. Static check:

Run:
```bash
grep -c 'already' unified-stack/docker-host-config.sh
```
Expected: `>= 2` (guards on docker + tailscale + CRS).

- [ ] **Step 5: Commit**

```bash
git add unified-stack/docker-host-config.sh
git commit -m "Add idempotent docker-host-config.sh Ubuntu bootstrap script"
```

---

## Task 18: README with Mermaid diagrams, `/dock` tree, threat matrix

**File:** Modify `unified-stack/README.md`

- [ ] **Step 1: Replace the skeleton with the full README**

File: `unified-stack/README.md`
```markdown
# Unified Stack

Single-command self-hosted foundation: one `docker compose up --build` brings up Caddy (custom build with Crowdsec, Coraza WAF, forward-auth, Souin cache, Brotli, L4 proxy), a Tailscale ingress sidecar, shared Postgres + Redis, Wazuh SIEM, Crowdsec LAPI, Falco runtime-security monitoring, Zeek network-security monitoring, and Authentik SSO — all accessible on both `*.secop.dev` (public, via Cloudflare) and `*.neon-lenok.ts.net` (Tailnet).

**Priority order:** Functionality > Security > Efficiency > Stability.

**Pilot app:** Authentik. Later phases add Affine, Nextcloud, media (Jellyfin + *arr), smart-home (HASS), and productivity (Coder, n8n) on top of this foundation.

---

## Architectural diagrams

### Network topology

```mermaid
flowchart TB
    subgraph Internet
        CF[Cloudflare edge]
        TN[Tailnet peers]
    end
    subgraph host["Docker host (Ubuntu)"]
        subgraph ingress["ingress 10.0.10.0/24"]
            TS[tailscale-ingress<br/>10.0.10.200]
            CADDY[caddy<br/>shares netns]
            SPRO1[socket-proxy-ro<br/>10.0.10.21]
            CS1[crowdsec<br/>10.0.10.21 alias]
        end
        subgraph auth["auth 10.0.11.0/24"]
            AUTH_S[authentik-server<br/>.20]
            AUTH_W[authentik-worker<br/>.21]
        end
        subgraph data["data 10.0.12.0/24"]
            PG[postgres<br/>.30]
            RD[redis<br/>.31]
        end
        subgraph obs["observability 10.0.13.0/24"]
            CS2[crowdsec<br/>.20]
            SPRO2[socket-proxy-ro<br/>.21]
            SPRW[socket-proxy-rw<br/>.22]
            AH[autoheal<br/>.23]
            FL[falco<br/>.24]
            WM[wazuh-manager<br/>.30]
            WI[wazuh-indexer<br/>.31]
            WD[wazuh-dashboard<br/>.32]
        end
        ZK[zeek<br/>host netns]
    end
    CF --> TS
    TN --> TS
    TS --- CADDY
    CADDY --> AUTH_S
    CADDY --> WD
    AUTH_S --> PG
    AUTH_S --> RD
    AUTH_W --> PG
    AUTH_W --> RD
    CADDY --> CS1
    CS1 -.same process as.- CS2
    FL -.docker API.-> SPRO2
    AH --> SPRW
    ZK -.taps.-> ingress
    ZK -.taps.-> auth
    ZK -.taps.-> data
    ZK -.taps.-> obs
```

### Request flow (public)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant CF as Cloudflare edge
    participant UFW as Host UFW
    participant CAD as Caddy
    participant CS as Crowdsec
    participant CRZ as Coraza WAF
    participant AK as Authentik
    participant APP as Target app
    C->>CF: HTTPS request (app.secop.dev)
    CF->>UFW: forwarded (CF IP → 443)
    UFW->>CAD: ACCEPT (CF IP, 443)
    CAD->>CAD: CF allowlist check
    CAD->>CS: bouncer: is this IP banned?
    CS-->>CAD: allowed
    CAD->>CRZ: WAF inspection (CRS rules)
    CRZ-->>CAD: anomaly score under threshold
    CAD->>AK: forward-auth: session valid?
    AK-->>CAD: 200 + headers
    CAD->>APP: reverse_proxy
    APP-->>CAD: response
    CAD-->>C: HTTPS response
```

### Bootstrap order

```mermaid
flowchart LR
    subgraph init["Bootstrap (docker compose up --build)"]
        TS[tailscale-ingress] --> CAD
        PG[postgres + initdb hook<br/>provisions app DBs] --> AKM
        RD[redis] --> AKM
        AKM[authentik-migration] --> AKS
        AKS[authentik-server] --> AKW[authentik-worker]
        AKS --> CAD[caddy]
        WI[wazuh-indexer] --> WM[wazuh-manager]
        WM --> WDB[wazuh-dashboard]
        SPR[socket-proxy-rw] --> AH[autoheal]
        CSC[crowdsec] --> CAD
    end
```

### Logging pipeline

```mermaid
flowchart LR
    CAD[caddy<br/>access.log JSON] --> WA
    CS[crowdsec<br/>decisions.log JSONL] --> WA
    FL[falco<br/>events.log JSON] --> WA
    ZK[zeek<br/>conn/dns/ssl/notice .log JSON] --> WA
    WA[Wazuh Agent<br/>host-level, file tail] --> WM[wazuh-manager]
    WM --> WI[wazuh-indexer]
    WI --> WD[wazuh-dashboard<br/>UI @ wazuh.secop.dev]
```

---

## Host directory layout

```
/dock/
├── conf/                    # configuration (RO in most containers)
│   ├── caddy/{Caddyfile, snippets/, coraza/, data/, logs/, souin/}
│   ├── crowdsec/{config.yaml, acquis.yaml, profiles.yaml, notifications/, db/}
│   ├── authentik/{media/, custom-templates/, certs/}
│   ├── wazuh/{manager/, indexer/, dashboard/, certs/, decoders/, rules/}
│   ├── falco/{falco.yaml, rules.d/, events.log}
│   └── zeek/{local.zeek, node.cfg, networks.cfg, intel/, logs/current/}
├── data/                    # application data (non-DB)
│   ├── authentik/
│   └── wazuh/{indexer/, manager/}
├── db/                      # databases
│   ├── postgres/{data/, init.d/}
│   └── redis/
├── tail/
│   └── ingress/
└── backups/
    ├── postgres/            # pg-backup.sh output
    └── redis/
```

All paths owned `docktaetor:media (1010:1010)`, mode `770` (DB dirs `700`).

---

## Security model

### Ingress path

```
Internet → Cloudflare → Host UFW → Caddy (via Tailscale netns)
       → @cloudflare matcher → Crowdsec bouncer → Coraza WAF
       → Authentik forward-auth → App container
Parallel observation: Falco (runtime) + Zeek (network)
```

### Threat × mitigation matrix

| Threat | Primary mitigation | Backup |
|---|---|---|
| Public DDoS | Cloudflare edge | CF allowlist drops non-CF traffic |
| Credential stuffing | Authentik rate-limit + MFA | Crowdsec auth-brute scenarios |
| Zero-day web exploit | Coraza OWASP CRS | Egress isolation (data + app layers separate) |
| Container escape (unknown) | Falco: terminal-shell, write-below-root, unexpected-privileged | Host UFW + kernel hardening |
| Malicious DNS exfiltration | Zeek dns.log + Intel hits → Wazuh correlation | Crowdsec egress blocklist scenarios |
| TLS-fingerprint C2 beaconing | Zeek ssl.log JA3/JA4 anomalies | Cloudflare WAF on ingress |
| Supply-chain (post-install) | Falco: execution from /tmp, unexpected outbound | Image pinning, review updates |
| Socket-proxy abuse | Falco: unauthorized Docker API; RO/RW proxy split | Proxy permission env vars |
| Leaked .env in git | .gitignore .env + CI secret scanning | Keys regenerable by docker-host-config.sh |
| Container escape (generic) | user:1010:1010, read_only, cap_drop ALL, no-new-privileges, seccomp | Falco + host UFW |
| DB exfiltration | data layer isolation, per-app DB/role, no published ports | Wazuh rule on external :5432 |
| Lateral movement | Apps never share layers; only Caddy multi-homes | Crowdsec intra-network + Zeek conn.log |
| Log tampering | Logs bind-mounted to host, Wazuh Agent reads outside Docker | Append-only from host |
| Silent backup failure | pg-backup.sh level-12 alert; skips pruning on fail | Retention floor = manual delete only |
| Tailscale key leak | Ephemeral + reusable-disabled keys | Re-issue + bounce sidecar |
| Authentik outage locks out admins | AUTHENTIK_BOOTSTRAP_TOKEN via API | Direct psql reset procedure |

---

## Quickstart

1. Prereqs on a freshly-imaged Ubuntu 22.04+ host (2+ cores, 8+ GB RAM):
   - A Cloudflare account managing `secop.dev` (or your own `PUBLIC_FQDN`).
   - A Tailscale account with your host enrolled.
   - Cloudflare API token with `Zone:read` + `DNS:edit` on the zone.
2. Clone this repo to a writable path: `git clone <url> /home/docktaetor/unified-stack`.
3. Run the bootstrap as root: `sudo /home/docktaetor/unified-stack/docker-host-config.sh`.
4. Fill in `/dock/conf/.env`:
   - `TAILSCALE_AUTHKEY=<from tailscale admin>`
   - `CLOUDFLARE_API_TOKEN=<from CF dash>`
   - Verify the tier block matches your host (see `scripts/health-recommend.sh` output).
5. Start the stack as `docktaetor`:
   ```bash
   sudo -u docktaetor bash -c 'cd /home/docktaetor/unified-stack && docker compose up --build -d'
   ```
6. Visit:
   - `https://auth.secop.dev` — Authentik
   - `https://wazuh.secop.dev` — Wazuh (gated by Authentik)

Boot persistence is via `systemctl status compose-stack.service`.

---

## Per-layer service index

| Layer | Service | Role |
|---|---|---|
| ingress | tailscale-ingress | Tailnet presence |
| ingress | caddy | TLS, WAF, bouncer, forward-auth |
| auth | authentik-server | SSO UI + API + outpost |
| auth | authentik-worker | Background jobs |
| auth | authentik-migration | One-shot DB migration |
| data | postgres | Shared Postgres cluster (pgvector) |
| data | redis | Shared Redis (logical DBs) |
| observability | crowdsec | Behavioral bans + blocklist |
| observability | socket-proxy-ro | Read-only Docker API |
| observability | socket-proxy-rw | R/W Docker API (Autoheal only) |
| observability | autoheal | Restart unhealthy containers |
| observability | falco | Runtime container security |
| observability | wazuh-manager | SIEM event ingest |
| observability | wazuh-indexer | OpenSearch index |
| observability | wazuh-dashboard | Web UI |
| host-net | zeek | Network security monitoring |

---

## Troubleshooting

- **Caddy stuck on ACME**: check `docker logs caddy`; verify Cloudflare token has `Zone:read + DNS:edit` on the zone.
- **Wazuh indexer OOM**: check tier block; MED/LOW tiers halve JVM heap; or add swap.
- **Falco eBPF driver fails to load**: set `FALCO_DRIVER=ebpf` in `.env` (legacy probe) and restart falco.
- **Authentik admin lockout**: `docker exec -it authentik-server ak shell` → `from authentik.core.models import User; u = User.objects.get(username='akadmin'); u.set_password('newpass'); u.save()`.
- **Postgres backup failed alert**: check `/var/log/pg-backup.log`; pruning is paused until next success.
- **Zeek not logging**: `docker exec zeek zeekctl status`; if `crashed`, check `/dock/conf/zeek/logs/current/stderr.log`.

---

## Adding a new app (Phase 3+)

1. Add a new section in `.env` with `<APP>_DB_NAME`, `<APP>_DB_USER`, `<APP>_DB_PASSWORD` (leave password empty — `docker-host-config.sh` fills it on next run).
2. Add a new handle block in `templates/caddy/Caddyfile` for both stanzas:
   ```caddyfile
   @newapp host newapp.{$PUBLIC_FQDN}
   handle @newapp {
       import authentik-forward-auth
       reverse_proxy newapp:<port>
   }
   ```
3. Add the app's service in `docker-compose.yml`. Join its own layer (create one if needed: `10.0.14.0/24` for media, `10.0.15.0/24` for productivity, etc.) + `data` for Postgres/Redis access.
4. Add tailscale-ingress multi-home: add the new layer to its `networks:` list.
5. Restart: `docker compose up -d --build`.
```

- [ ] **Step 2: Validate Markdown (optional — lenient)**

Run:
```bash
docker run --rm -v "${PWD}/unified-stack:/mnt" -w /mnt davidanson/markdownlint-cli2:latest "README.md" || true
```
Expected: may print style warnings; these are acceptable.

- [ ] **Step 3: Commit**

```bash
git add unified-stack/README.md
git commit -m "Write README with Mermaid diagrams, dock tree, threat matrix, troubleshooting"
```

---

## Task 19: End-to-end acceptance validation (on target Ubuntu host)

**Goal:** Execute the spec's acceptance criteria (spec §13). These steps are for the human operator (or a CI job on an Ubuntu runner), not the Windows dev host.

- [ ] **Step 1: Fresh-host bootstrap idempotence**

On a freshly-imaged Ubuntu 22.04 host with repo cloned to `/home/docktaetor/unified-stack/`:
```bash
sudo /home/docktaetor/unified-stack/docker-host-config.sh 2>&1 | tee /tmp/bootstrap-1.log
sudo /home/docktaetor/unified-stack/docker-host-config.sh 2>&1 | tee /tmp/bootstrap-2.log
diff /tmp/bootstrap-1.log /tmp/bootstrap-2.log | grep -E '^[><]' | head
```
Expected: second run makes no changes (only log lines reporting "already", "no changes", etc.).

- [ ] **Step 2: Cold-start timing**

```bash
cd /home/docktaetor/unified-stack
time docker compose up --build -d
```
Expected: all 16 services created. HIGH-tier host: full stack healthy within ~5 min (first run includes xcaddy build + Wazuh indexer init).

- [ ] **Step 3: All services healthy**

```bash
sleep 300
docker compose ps --format '{{.Name}}\t{{.Status}}'
```
Expected: every non-init service shows `running (healthy)`; `authentik-migration` shows `exited (0)`.

- [ ] **Step 4: Public ingress + CF allowlist**

From a machine outside CF (e.g., direct IP):
```bash
curl -k --connect-to auth.secop.dev:443:<HOST_IP>:443 https://auth.secop.dev/
```
Expected: HTTP 403 (CF allowlist deny).

From CF (normal DNS):
```bash
curl -s -o /dev/null -w "%{http_code}\n" https://auth.secop.dev/
```
Expected: `200` (Authentik login page).

- [ ] **Step 5: Tailnet ingress**

From any Tailnet peer:
```bash
curl -s -o /dev/null -w "%{http_code}\n" https://auth.neon-lenok.ts.net/
```
Expected: `200`.

- [ ] **Step 6: Authentik bootstrap admin login**

Browser: `https://auth.secop.dev` → `akadmin` / `AUTHENTIK_BOOTSTRAP_PASSWORD`. Expected: admin dashboard.

- [ ] **Step 7: Wazuh dashboard visible + all 4 channels**

Browser: `https://wazuh.secop.dev` → login via Authentik forward-auth. In the dashboard, filter by `_source` label; expect entries for: `caddy`, `crowdsec`, `falco`, `zeek-conn`.

- [ ] **Step 8: WAF test (Coraza block → Wazuh alert)**

```bash
curl "https://auth.secop.dev/?id=1%27%20OR%201=1--"
```
Expected: HTTP 403. Within 30 s, Wazuh dashboard shows a level-10 Coraza block alert.

- [ ] **Step 9: Falco test (shell in container → Wazuh alert)**

```bash
docker exec authentik-server sh -c 'bash -i </dev/null'
```
Expected: Falco emits a `Reverse shell in container` event. Wazuh dashboard shows level-15 alert within 30 s.

- [ ] **Step 10: pg-backup safety rule**

Normal success:
```bash
sudo /usr/local/bin/pg-backup.sh
ls -lh /dock/backups/postgres/
```
Expected: new `.sql.zst` file.

Simulate failure (stop postgres, run backup):
```bash
docker stop postgres
sudo /usr/local/bin/pg-backup.sh || true
ls -lh /dock/backups/postgres/
docker start postgres
```
Expected: the previous backup is still present; a level-12 alert shows in Wazuh `_source=crowdsec type=pg_backup_failed`.

- [ ] **Step 11: Restart-cycle idempotence**

```bash
docker compose down
time docker compose up --build -d
sleep 60
docker compose ps --format '{{.Name}}\t{{.Status}}'
```
Expected: warm-cache start < 60 s. All services healthy. No data loss (Authentik admin still logs in, Wazuh retains prior alerts).

- [ ] **Step 12: Record outcome**

Write a short run report to `docs/superpowers/plans/runs/2026-04-18-acceptance.md` with:
- Tier used
- Cold-start time
- Any failures + remediations
- Screenshot/curl log of each acceptance check.

Commit:
```bash
git add docs/superpowers/plans/runs/
git commit -m "Record unified-stack pilot acceptance run"
```

---

## Self-review notes

- **Spec §1 (Purpose)** → covered by whole plan.
- **Spec §2 (Scope, pilot containers)** → Tasks 11–15.
- **Spec §3 (Networks)** → Task 11.
- **Spec §4 (Foundation services + hardening + tiers)** → Tasks 11–15; tiers in Task 2.
- **Spec §5 (Authentik pilot)** → Task 15.
- **Spec §6 (Observability: 4 channels + retention + Intel)** → Tasks 6, 8, 9, 10, 16.
- **Spec §7 (.env convention + secret generation)** → Tasks 2, 17.
- **Spec §8 (Volume layout + backup safety rule)** → Tasks 11–17; safety rule in Task 16 `pg-backup.sh`.
- **Spec §9 (Bootstrap DAG + healthchecks + init containers)** → Tasks 11–15 (healthchecks), Task 13 (pgvector initdb hook replaces separate `postgres-init` container — noted as spec divergence), Task 17 (idempotence).
- **Spec §10 (Build artifacts + repo layout)** → Tasks 1, 3, 4, 5, 6, 7, 8, 9, 10, 16, 17, 18.
- **Spec §11 (Security model + threat matrix + ingress path)** → Task 18 (README).
- **Spec §12 (README content)** → Task 18.
- **Spec §13 (Acceptance criteria)** → Task 19.
- **Spec §14 (Deliverables)** → all tasks combined; verify via final `git ls-files unified-stack/` in Task 18.
- **Spec §15 (Open questions)** — carry into implementation; document any decisions in run report (Task 19 Step 12).

**Divergences from spec** (documented for reviewer):
- Spec §9 lists `postgres-init` and `wazuh-init` as one-shot containers. The `pgvector` image already runs `/docker-entrypoint-initdb.d/` on first boot — no separate container needed. Wazuh cert generation is handled by `docker-host-config.sh` `fetch_owasp_crs` + template copy step (certs go under `/dock/conf/wazuh/certs/` on host, not by a container). This drops container count from 18 → 16 operational + 1 one-shot (authentik-migration). README and Task 19 reflect the 16-service target.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-18-unified-stack-foundation-implementation.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
