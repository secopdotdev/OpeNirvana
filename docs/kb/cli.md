---
type: reference
title: "cli"
tags: [type/reference]
created: 2026-06-11
updated: 2026-06-11
---

# CLI Reference

All scripts are in `unified-stack/scripts/` and are invoked as `python3 scripts/<script>.py`. Every script is idempotent — re-running is safe and skips already-completed work. Existing values are never overwritten.

**Exit codes:** see [errors.md](errors.md)

---

## Commands

### `validate.py`

Risk-tiered validation gate for Python scripts. Discovers targets, runs configured runners and custom scanners, reports findings, and exits with a code indicating the highest finding severity.

**Usage:**
```
python3 scripts/validate.py [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--changed-only` | flag | false | Validate only files in the git diff vs `origin/main` |
| `--tier` | choice: `0\|1\|2` | — | Restrict validation to a single blast-radius tier |
| `--format` | choice: `human\|json\|sarif` | `human` (or `sarif` under `--ci`) | Output format |
| `--fail-on` | choice: `block\|warn` | `block` | Exit non-zero on `block`-level or `warn`-level findings |
| `--ci` | flag | false | CI mode: output defaults to SARIF unless `--format` is given |

---

### `gen-secrets.py`

Populate empty secret variables in `.env` with cryptographically secure random values. Writes to `.env` (default) or OpenBao KV v2. Only fills blank values; never overwrites human-set secrets.

**Usage:**
```
python3 scripts/gen-secrets.py [path/to/.env] [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--apply` | flag | false | Apply generated secrets: update Postgres passwords, re-seed Wazuh, restart dashboard |
| `--target` | choice: `env\|bao` | `env` | Write to `.env` (default) or OpenBao KV v2 |
| `--set KEY=VALUE` | string | — | Set a single key if currently empty (e.g., `--set HOST_PUBLIC_IP=1.2.3.4`) |

---

### `check-stack.py`

Service reachability and configuration audit. Checks DNS resolution, Caddyfile structure, auth gates, and container health. Supports live HTTP probes or config-only audit mode.

**Usage:**
```
python3 scripts/check-stack.py [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--env PATH` | string | `unified-stack/.env` | Path to live `.env` |
| `--caddyfile PATH` | string | `unified-stack/templates/caddy/Caddyfile` | Path to Caddyfile |
| `--compose PATH` | string | — | Path to `docker-compose.yml` |
| `--no-probe` | flag | false | Skip live HTTP checks (DNS + config audit only) |
| `--no-containers` | flag | false | Skip container health table |
| `--logs SERVICE` | string | — | Tail logs for the named container and exit |
| `--tail N` | int | `50` | Number of log lines to show with `--logs` |
| `--no-color` | flag | false | Plain text output (no ANSI escape codes) |

---

### `set-auth.py oidc`

Provision Authentik OIDC providers for all apps and write generated credentials to `.env`.

**Usage:**
```
python3 scripts/set-auth.py oidc
```

---

### `set-auth.py entra-setup`

Federate Authentik with Microsoft Entra ID and gate all logins on membership in a specified Entra group.

**Usage:**
```
python3 scripts/set-auth.py entra-setup .env
```

---

### `set-auth.py entra-sync`

Sync Entra group membership into Authentik users and groups.

**Usage:**
```
python3 scripts/set-auth.py entra-sync .env
```

---

### `maintain.py backup`

Dump all Postgres databases with `pg_dumpall`, compress with `zstd`, and write to `/dock/backups/postgres/`. Prunes old backups; skips pruning on failure to preserve existing backups.

**Usage:**
```
python3 scripts/maintain.py backup
```

---

### `maintain.py intel`

Download URLhaus, Feodo Tracker, and CrowdStrike threat-intel feeds, convert to Zeek Intel TSV format, and deploy to the Zeek intel directory.

**Usage:**
```
python3 scripts/maintain.py intel
```

---

### `maintain.py wazuh`

Diff repo decoders and rules against the host's `/var/ossec/etc/` directory and sync any changes. Restarts the Wazuh agent only if files changed.

**Usage:**
```
python3 scripts/maintain.py wazuh
```

---

### `maintain.py all`

Run `backup` → `intel` → `wazuh` in sequence.

**Usage:**
```
python3 scripts/maintain.py all
```

---

### `profiles.py`

Resolve and dependency-check stack profiles. Prints the service catalog organized by Docker Compose profile.

**Usage:**
```
python3 scripts/profiles.py [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--list` | flag | false | Print catalog and exit |

---

### `undo-entra.py`

Restore local Authentik logins and disable Microsoft Entra ID federation. Use after an Entra lockout or when removing Entra integration.

**Usage:**
```
python3 scripts/undo-entra.py .env
```

---

### `add-service.py`

Scaffold and auto-provision a new service: generates a Caddyfile snippet, `.env` entries, DNS record, Authentik OIDC application, and (optionally) host SSH provisioning. Seven idempotent steps; supports `--dry-run` to preview all changes before writing.

**Usage:**
```
python3 scripts/add-service.py <name> [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port PORT` | int | `80` | Internal container port |
| `--image IMAGE` | string | — | Docker image to use |
| `--type` | choice: `standalone\|unified` | `standalone` | `standalone` = Tailscale sidecar; `unified` = Caddy + Authentik |
| `--auth` | choice: `authentik\|native-oidc\|none` | `authentik` | Auth gate (unified type only) |
| `--db` | choice: `none\|postgres\|redis\|both` | `none` | Local DB sidecars (standalone type only) |
| `--subdomain SLUG` | string | — | External subdomain slug |
| `--out DIR` | string | — | Output base directory |
| `--dry-run` | flag | false | Preview without writing files or calling external APIs |
| `--no-host-setup` | flag | false | Skip SSH host provisioning step |

---

### `check-stack.py --logs SERVICE` (log tail shorthand)

Tail logs for a specific container and exit. Combines `--logs` with optional `--tail` override.

**Usage:**
```
python3 scripts/check-stack.py --logs <SERVICE> [--tail N]
```

**Flags:**

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tail N` | int | `50` | Override the number of log lines to display |
