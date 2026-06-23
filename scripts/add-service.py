#!/usr/bin/env python3
"""
new-service.py - Scaffold a new service for the openirvana stack.

Usage:
    python3 new-service.py <service_name> [options]

Options:
    --port PORT           Internal container port the app listens on (default: 80)
    --image IMAGE         Docker image (default: placeholder comment)
    --type {standalone,unified}
                          standalone  dev/-style: Tailscale sidecar owns routing  [default]
                          unified     unified-stack: Caddy + Authentik gate
    --auth {authentik,native-oidc,none}
                          authentik    Authentik forward-auth gate (default for unified)
                          native-oidc  Service handles OIDC itself; excluded from gate
                          none         No auth gate (API / mobile clients)
    --db {none,postgres,redis,both}
                          Add local postgres/redis containers (standalone only, default: none)
    --subdomain SUBDOMAIN
                          External subdomain slug (default: service name)
    --out DIR             Output base directory
                          standalone default: ./dev/<name>
                          unified default:    ./unified-stack/services/<name>
    --dry-run             Print generated files; do not write to disk
"""

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

# -- Config -----------------------------------------------------------------------

class ServiceConfig:
    def __init__(
        self,
        name: str,
        port: int,
        image: str,
        service_type: str,
        auth: str,
        db: str,
        subdomain: str,
        out: Path,
    ) -> None:
        self.name      = name
        self.NAME      = name.upper().replace("-", "_")
        self.port      = port
        self.image     = image
        self.type      = service_type
        self.auth      = auth
        self.db        = db
        self.subdomain = subdomain
        self.out       = out


# -- Standalone templates --------------------------------------------------------

def _compose_standalone(cfg: ServiceConfig) -> str:
    name_upper = cfg.name.upper().replace("-", "_")

    # depends_on entries at correct YAML indent (6/8 spaces under application:)
    depends_on = ""
    if cfg.db in ("redis", "both"):
        depends_on += "      redis:\n        condition: service_healthy\n"
    if cfg.db in ("postgres", "both"):
        depends_on += "      postgres:\n        condition: service_healthy\n"
    depends_on += "      tailscale:\n        condition: service_healthy\n"

    # extra env vars at correct YAML indent (6 spaces under environment:)
    env_extras = ""
    if cfg.db in ("redis", "both"):
        env_extras += "      - REDIS_SERVER_HOST=localhost\n"
    if cfg.db in ("postgres", "both"):
        env_extras += (
            f"      - DATABASE_URL=postgresql://${{DB_USERNAME}}:${{DB_PASSWORD}}"
            f"@localhost:5432/${{DB_DATABASE:-{cfg.name}}}\n"
        )

    # extra services at correct YAML indent (2 spaces under services:)
    extra_services = ""
    if cfg.db in ("redis", "both"):
        extra_services += (
            f"\n  redis:\n"
            f"    image: redis:7-alpine\n"
            f"    container_name: app-{name_upper}-redis\n"
            f"    healthcheck:\n"
            f'      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]\n'
            f"      interval: 10s\n"
            f"      timeout: 5s\n"
            f"      retries: 5\n"
            f"    restart: unless-stopped\n"
            f"    network_mode: service:tailscale\n"
            f"    depends_on:\n"
            f"      tailscale:\n"
            f"        condition: service_healthy\n"
            f"    volumes:\n"
            f"      - ${{DOCKER_DATA}}/{cfg.name}/redis:/data\n"
        )
    if cfg.db in ("postgres", "both"):
        extra_services += (
            f"\n  postgres:\n"
            f"    image: postgres:16-alpine\n"
            f"    container_name: app-{name_upper}-db\n"
            f"    volumes:\n"
            f"      - ${{DOCKER_DATA}}/{cfg.name}/db:/var/lib/postgresql/data\n"
            f"    environment:\n"
            f"      POSTGRES_USER: ${{DB_USERNAME}}\n"
            f"      POSTGRES_PASSWORD: ${{DB_PASSWORD}}\n"
            f"      POSTGRES_DB: ${{DB_DATABASE:-{cfg.name}}}\n"
            f'      POSTGRES_INITDB_ARGS: "--data-checksums"\n'
            f"    healthcheck:\n"
            f'      test: ["CMD", "pg_isready", "-U", "${{DB_USERNAME}}", "-d", "${{DB_DATABASE:-{cfg.name}}}"]\n'
            f"      interval: 10s\n"
            f"      timeout: 5s\n"
            f"      retries: 5\n"
            f"    restart: unless-stopped\n"
            f"    network_mode: service:tailscale\n"
            f"    depends_on:\n"
            f"      tailscale:\n"
            f"        condition: service_healthy\n"
        )

    # Main template uses <<<DEPENDS_ON>>> and <<<ENV_EXTRAS>>> as line-level
    # placeholders at the 8-space template base indent so they land at column 0
    # after dedent, then we replace them with correctly-indented YAML.
    main = dedent(f"""\
        services:
          tailscale:
            image: tailscale/tailscale:latest
            container_name: tailscale-${{SERVICE}}
            hostname: ${{SERVICE}}
            environment:
              - TS_AUTHKEY=${{TS_AUTHKEY}}
              - TS_STATE_DIR=/var/lib/tailscale
              - TS_SERVE_CONFIG=/config/serve.json
              - TS_USERSPACE=false
              - TS_ENABLE_HEALTH_CHECK=true
              - TS_LOCAL_ADDR_PORT=127.0.0.1:41234
              - TS_ACCEPT_DNS=true
            volumes:
              - ./config:/config
              - ${{TAIL_CONF}}/${{SERVICE}}:/var/lib/tailscale
            devices:
              - /dev/net/tun:/dev/net/tun
            cap_add:
              - NET_ADMIN
            healthcheck:
              test: ["CMD", "wget", "--spider", "-q", "http://127.0.0.1:41234/healthz"]
              interval: 1m
              timeout: 10s
              retries: 3
              start_period: 10s
            restart: always

          application:
            image: {cfg.image}
            container_name: app-${{SERVICE}}
            depends_on:
        <<<DEPENDS_ON>>>
            environment:
              - PUID=${{PUID}}
              - PGID=${{PGID}}
              - TZ=${{TZ}}
        <<<ENV_EXTRAS>>>
            volumes:
              - ${{DOCKER_CONF}}/${{SERVICE}}:/config
              - ${{DOCKER_DATA}}/${{SERVICE}}:/data
            healthcheck:
              test: ["CMD", "wget", "--spider", "-q", "http://localhost:{cfg.port}/"]
              interval: 30s
              timeout: 10s
              retries: 5
              start_period: 60s
            restart: unless-stopped
            network_mode: service:tailscale
        """)
    main = main.replace("<<<DEPENDS_ON>>>\n", depends_on)
    main = main.replace("<<<ENV_EXTRAS>>>\n", env_extras)
    return main + extra_services


def _env_standalone(cfg: ServiceConfig) -> str:
    db_block = ""
    if cfg.db in ("postgres", "both"):
        import secrets
        pw = secrets.token_urlsafe(24)
        db_block = dedent(f"""
            # Database credentials
            DB_USERNAME={cfg.name}
            DB_PASSWORD={pw}
            DB_DATABASE={cfg.name}
        """)
    if cfg.db in ("redis", "both"):
        db_block += "\n# Redis (no password for local-only instance)\n"

    return dedent(f"""\
        SERVICE={cfg.name}
        SERVICEPORT={cfg.port}
        TS_AUTHKEY=             # tskey-auth-...
        IMAGE_URL={cfg.image}

        # Host paths - must match docker-host-config.sh
        PUID=1010
        PGID=1010
        TZ=America/Chicago
        DOCKER_DATA=/dock/data
        DOCKER_CONF=/dock/conf
        TAIL_CONF=/dock/conf/tail
        """) + db_block


def _serve_json(cfg: ServiceConfig) -> str:
    return dedent(f"""\
        {{
          "TCP": {{
            "443": {{
              "HTTPS": true
            }}
          }},
          "Web": {{
            "${{TS_CERT_DOMAIN}}:443": {{
              "Handlers": {{
                "/": {{
                  "Proxy": "http://127.0.0.1:{cfg.port}"
                }}
              }}
            }}
          }}
        }}
        """)


# -- Unified-stack templates ------------------------------------------------------

def _caddyfile_snippet(cfg: ServiceConfig) -> str:
    suf_pub = f"-pub" if cfg.auth in ("native-oidc", "none") else ""
    suf_ts  = f"-ts"  if cfg.auth in ("native-oidc", "none") else ""
    name    = cfg.name

    auth_note = ""
    if cfg.auth == "native-oidc":
        auth_note = (
            f"\n# NOTE: Add the following to @requires-auth-pub and @requires-auth-ts\n"
            f"#   not host ${{{cfg.NAME}_SUBDOMAIN}}.{{$PUBLIC_FQDN}}\n"
            f"#   not host ${{{cfg.NAME}_SUBDOMAIN}}.{{$TAILNET_FQDN}}\n"
        )
    elif cfg.auth == "none":
        auth_note = (
            f"\n# NOTE: Add the following to @requires-auth-pub and @requires-auth-ts\n"
            f"#   not host ${{{cfg.NAME}_SUBDOMAIN}}.{{$PUBLIC_FQDN}}\n"
            f"#   not host ${{{cfg.NAME}_SUBDOMAIN}}.{{$TAILNET_FQDN}}\n"
        )

    return dedent(f"""\
        # -- {name} ------------------------------------------------------------------
        # Add this backend snippet to the backend-snippets section of the Caddyfile:
        (backend-{name}) {{
            reverse_proxy {name}:{cfg.port}
        }}

        # -- Public site block  (*.{{$PUBLIC_FQDN}}) ------------------------------
        # Add these lines inside the *.{{$PUBLIC_FQDN}} {{ ... }} block:

            @{name}{suf_pub} host ${{{cfg.NAME}_SUBDOMAIN}}.{{$PUBLIC_FQDN}}
            handle @{name}{suf_pub} {{
                import backend-{name}
            }}

        # -- Tailnet site block  (http://*.{{$TAILNET_FQDN}}) --------------------
        # Add these lines inside the http://*.{{$TAILNET_FQDN}} {{ ... }} block:

            @{name}{suf_ts} host ${{{cfg.NAME}_SUBDOMAIN}}.{{$TAILNET_FQDN}}
            handle @{name}{suf_ts} {{
                import backend-{name}
            }}
        """) + auth_note


def _env_example_snippet(cfg: ServiceConfig) -> str:
    return dedent(f"""\
        # {cfg.name}
        {cfg.NAME}_SUBDOMAIN={cfg.subdomain}
        # {cfg.NAME}_MEM_LIMIT=512m
        # {cfg.NAME}_CPUS=1
        """)


# -- Shared templates ------------------------------------------------------------

def _readme(cfg: ServiceConfig) -> str:
    auth_note = {
        "authentik":   "Authentik forward-auth (session required).",
        "native-oidc": "Native OIDC via Authentik - service handles its own login page.",
        "none":        "No authentication gate - API/mobile clients connect directly.",
    }[cfg.auth]

    return dedent(f"""\
        # {cfg.name}

        <!-- TODO: one-line description -->

        ## Access

        | URL | Auth |
        |-----|------|
        | `https://{cfg.subdomain}.{{PUBLIC_FQDN}}` | {auth_note} |
        | `http://{cfg.subdomain}.{{TAILNET_FQDN}}` | {auth_note} |

        ## Environment variables

        | Variable | Description |
        |----------|-------------|
        | `{cfg.NAME}_SUBDOMAIN` | External subdomain slug (default: `{cfg.subdomain}`) |

        ## Initial setup

        1. Update `.env` / `unified-stack/.env` with required values.
        2. Bring up the service:
           ```bash
           docker compose up -d {cfg.name}
           ```
        3. <!-- TODO: first-run steps (create admin user, run migrations, etc.) -->

        ## Notes

        - Internal port: `{cfg.port}`
        - Data persisted to `/dock/data/{cfg.name}`, config to `/dock/conf/{cfg.name}`.
        """)


# -- Scaffolding ------------------------------------------------------------------

def scaffold(cfg: ServiceConfig, dry_run: bool) -> None:
    def write(rel: str, content: str) -> None:
        path = cfg.out / rel
        if dry_run:
            sep = "=" * 72
            print(f"\n{sep}")
            print(f"  FILE: {path}")
            print(sep)
            print(content)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(f"  wrote  {path}")

    def announce(title: str, content: str) -> None:
        """Print instructions that require manual edits to existing files."""
        sep = "=" * 72
        print(f"\n{sep}")
        print(f"  ACTION: {title}")
        print(sep)
        print(content)

    if cfg.type == "standalone":
        write("docker-compose.yml", _compose_standalone(cfg))
        write(".env",               _env_standalone(cfg))
        write("config/serve.json",  _serve_json(cfg))
        write("README.md",          _readme(cfg))

        if not dry_run:
            print(f"\nStandalone scaffold created at {cfg.out}")
            print("\nNext steps:")
            print(f"  1. Fill in TS_AUTHKEY in {cfg.out}/.env")
            print(f"  2. Set IMAGE_URL in {cfg.out}/.env (and docker-compose.yml)")
            print(f"  3. docker compose --env-file {cfg.out}/.env -f {cfg.out}/docker-compose.yml up -d")

    else:  # unified
        write("README.md", _readme(cfg))

        announce(
            "Add to unified-stack/templates/caddy/Caddyfile",
            _caddyfile_snippet(cfg),
        )
        announce(
            "Add to unified-stack/.env.example  (and live .env)",
            _env_example_snippet(cfg),
        )
        announce(
            "Add to unified-stack/docker-compose.yml  (docker service block)",
            dedent(f"""\
                  {cfg.name}:
                    image: {cfg.image}
                    container_name: {cfg.name}
                    environment:
                      - PUID=${{PUID}}
                      - PGID=${{PGID}}
                      - TZ=${{TZ}}
                    volumes:
                      - ${{DOCK_CONF}}/{cfg.name}:/config
                      - ${{DOCK_DATA}}/{cfg.name}:/data
                    networks:
                      apps: {{}}         # change to the appropriate network
                    healthcheck:
                      test: ["CMD", "wget", "--spider", "-q", "http://localhost:{cfg.port}/"]
                      interval: 30s
                      timeout: 10s
                      retries: 5
                      start_period: 60s
                    restart: unless-stopped
                    security_opt:
                      - no-new-privileges:true
                    cap_drop:
                      - ALL
                    logging: *default-logging
                """),
        )

        if not dry_run:
            print(f"\nREADME written to {cfg.out}/README.md")
            print("\nPaste the blocks above into the indicated files, then:")
            print(f"  1. Set {cfg.NAME}_SUBDOMAIN in .env")
            print(f"  2. docker compose up -d {cfg.name} caddy")


# -- Host provisioning -----------------------------------------------------------

_DEFAULT_SSH_HOST = "admin@prod-host"
_DEFAULT_SSH_KEY  = "~/.ssh/prod-host"
_DEFAULT_REPO_PATH = "/home/admin/openirvana"


def _ssh(host: str, key: str, cmd: str) -> None:
    """Run a command on the Docker host via SSH, streaming output."""
    key_path = os.path.expanduser(key)
    result = subprocess.run(
        ["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=accept-new", host, cmd],
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SSH command exited {result.returncode}: {cmd}")


def _provision_host(cfg: "ServiceConfig", ssh_host: str, ssh_key: str, repo_path: str) -> None:
    """Create service dirs on the Docker host and fix ownership via fix-permissions.sh."""
    fix_sh = f"{repo_path}/unified-stack/scripts/fix-permissions.sh"
    tail_flag = "--tailscale" if cfg.type == "standalone" else ""

    print(f"\nProvisioning host via SSH ({ssh_host})...")
    _ssh(ssh_host, ssh_key,
         f"sudo bash {fix_sh} --service {cfg.name} {tail_flag}".strip())


def _print_manual_host_steps(cfg: "ServiceConfig") -> None:
    """Print the equivalent manual commands when SSH provisioning is skipped."""
    dirs = f"/dock/conf/{cfg.name} /dock/data/{cfg.name}"
    if cfg.type == "standalone":
        dirs += f" /dock/conf/tail/{cfg.name}"
    print("\nCreate host directories manually (run on prod-host as root):")
    print(f"  sudo bash unified-stack/scripts/fix-permissions.sh --service {cfg.name}"
          + (" --tailscale" if cfg.type == "standalone" else ""))
    print(f"  # (creates {dirs} as svc-user:media 770)")


# -- Unified-stack auto-provisioning --------------------------------------------

_CADDY_CATCHALL = (
    "\n    # Catch-all: reject any subdomain not explicitly matched above.\n"
    "    handle {\n"
    "        abort\n"
    "    }\n"
    "}"
)
_CADDY_BACKEND_ANCHOR = (
    "\n# ==============================================================\n"
    "# Reusable security policy blocks."
)


def _edit_caddyfile(cfg: "ServiceConfig", caddyfile: Path, dry_run: bool) -> bool:
    """Insert backend snippet and site handlers into the Caddyfile. Idempotent."""
    if not caddyfile.exists():
        print(f"  Caddyfile: {caddyfile} not found — skipping")
        return False

    text = caddyfile.read_text()

    if f"(backend-{cfg.name})" in text:
        print(f"  Caddyfile: backend-{cfg.name} already present — skipping")
        return False

    parts = text.split(_CADDY_CATCHALL)
    if len(parts) != 3:
        print(f"  Caddyfile: unexpected catch-all count ({len(parts) - 1}) — skipping")
        return False
    if _CADDY_BACKEND_ANCHOR not in text:
        print(f"  Caddyfile: backend anchor not found — skipping")
        return False

    suf_pub = "-pub" if cfg.auth in ("native-oidc", "none") else ""
    name, NAME = cfg.name, cfg.NAME

    backend_block = (
        f"\n(backend-{name}) {{\n"
        f"    reverse_proxy {name}:{cfg.port}\n"
        f"}}\n"
    )
    pub_handle = (
        f"\n    @{name}{suf_pub} host ${{{NAME}_SUBDOMAIN}}.{{$PUBLIC_FQDN}}\n"
        f"    handle @{name}{suf_pub} {{\n"
        f"        import backend-{name}\n"
        f"    }}\n"
    )
    ts_handle = (
        f"\n    @{name}-ts host ${{{NAME}_SUBDOMAIN}}.{{$TAILNET_FQDN}}\n"
        f"    handle @{name}-ts {{\n"
        f"        import backend-{name}\n"
        f"    }}\n"
    )

    if dry_run:
        print(f"  Caddyfile: would insert (backend-{name}) + pub + tailnet handlers")
        return False

    new_text = text.replace(_CADDY_BACKEND_ANCHOR, backend_block + _CADDY_BACKEND_ANCHOR, 1)
    parts = new_text.split(_CADDY_CATCHALL)
    new_text = parts[0] + pub_handle + _CADDY_CATCHALL + parts[1] + ts_handle + _CADDY_CATCHALL + parts[2]
    caddyfile.write_text(new_text)
    print(f"  Caddyfile: inserted (backend-{name}) + pub + tailnet handlers")
    return True


def _edit_env_files(cfg: "ServiceConfig", repo_root: Path, dry_run: bool, utils_mod) -> None:
    """Add {NAME}_SUBDOMAIN to .env and .env.example. Idempotent."""
    key = f"{cfg.NAME}_SUBDOMAIN"

    # Live .env
    env_path = repo_root / "unified-stack" / ".env"
    if env_path.exists():
        env = utils_mod.EnvFile(env_path)
        if env.get(key):
            print(f"  .env: {key} already set — skipping")
        elif dry_run:
            print(f"  .env: would add {key}={cfg.subdomain}")
        else:
            env.set_if_blank(key, cfg.subdomain)

    # .env.example
    example_path = repo_root / "unified-stack" / ".env.example"
    if example_path.exists():
        text = example_path.read_text()
        if f"{key}=" in text:
            print(f"  .env.example: {key} already present — skipping")
        elif dry_run:
            print(f"  .env.example: would add {key}={cfg.subdomain}")
        else:
            lines = text.splitlines(keepends=True)
            last_sub = max(
                (i for i, ln in enumerate(lines)
                 if "_SUBDOMAIN=" in ln and not ln.strip().startswith("#")),
                default=-1,
            )
            if last_sub >= 0:
                lines.insert(last_sub + 1, f"{key}={cfg.subdomain}\n")
                example_path.write_text("".join(lines))
            else:
                example_path.write_text(text.rstrip("\n") + f"\n{key}={cfg.subdomain}\n")
            print(f"  .env.example: added {key}={cfg.subdomain}")


def _import_utils():
    """Load unified-stack/scripts/utils.py and return the module."""
    scripts_dir = Path(__file__).resolve().parent / "unified-stack" / "scripts"
    spec = importlib.util.spec_from_file_location("utils", scripts_dir / "utils.py")
    assert spec is not None and spec.loader is not None, "Could not locate utils.py"
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _provision_authentik_proxy(ak, cfg: "ServiceConfig", domain: str, dry_run: bool) -> None:
    """Create proxy provider + application + assign to embedded outpost. Idempotent."""
    app_slug = cfg.subdomain
    app_name = cfg.name.replace("-", " ").title()

    existing = ak.get("core/applications/", slug=app_slug).get("results", [])
    if existing:
        print(f"  Authentik: application '{app_slug}' already exists — skipping")
        return

    if dry_run:
        print(f"  Authentik: would create proxy provider + app for '{app_slug}'")
        return

    flows = ak.get("flows/instances/", designation="authentication").get("results", [])
    if not flows:
        raise RuntimeError("No authentication flows found in Authentik")
    auth_flow_pk = flows[0]["pk"]

    inv_flows = ak.get("flows/instances/", designation="invalidation").get("results", [])
    if not inv_flows:
        raise RuntimeError("No invalidation flows found in Authentik")
    inv_flow_pk = inv_flows[0]["pk"]

    provider = ak.post("providers/proxy/", {
        "name":               f"{cfg.name}-proxy-provider",
        "authorization_flow": auth_flow_pk,
        "invalidation_flow":  inv_flow_pk,
        "external_host":      f"https://{cfg.subdomain}.{domain}",
        "mode":               "forward_single",
    })
    provider_pk = provider["pk"]
    print(f"  Authentik: created proxy provider pk={provider_pk}")

    try:
        ak.post("core/applications/", {
            "name":     app_name,
            "slug":     app_slug,
            "provider": provider_pk,
        })
        print(f"  Authentik: created application '{app_slug}'")
    except RuntimeError as exc:
        if "already exists" not in str(exc):
            raise

    outposts = ak.get("outposts/instances/", type="proxy").get("results", [])
    embedded = next(
        (o for o in outposts if o.get("service_connection") is None),
        outposts[0] if outposts else None,
    )
    if not embedded:
        print(f"  Authentik: no proxy outpost found — assign provider {provider_pk} manually")
        return

    outpost_pk        = embedded["pk"]
    current_providers = list(embedded.get("providers", []))
    if provider_pk not in current_providers:
        ak.patch(f"outposts/instances/{outpost_pk}/", {
            "providers": current_providers + [provider_pk],
        })
        print(f"  Authentik: added to outpost {outpost_pk}")
    else:
        print(f"  Authentik: provider already in outpost")


def _check_and_provision_unified(cfg: "ServiceConfig", dry_run: bool) -> None:
    """
    For unified+authentik services: detect missing DNS/Authentik components
    and provision them. Calls check-stack.py for a final health report.
    """
    repo_root = Path(__file__).resolve().parent
    env_path  = repo_root / "unified-stack" / ".env"

    if not env_path.exists():
        print(f"  skip auto-provision: {env_path} not found")
        return

    try:
        utils = _import_utils()
    except Exception as exc:
        print(f"  skip auto-provision: cannot load utils ({exc})")
        return

    env      = utils.EnvFile(env_path)
    domain   = env.get("PUBLIC_FQDN")
    cf_token = env.get("CLOUDFLARE_API_TOKEN")
    ak_token = utils.resolve_admin_token(env)
    ak_sub   = env.get("AUTHENTIK_SUBDOMAIN") or "auth"

    if not domain:
        print("  skip auto-provision: PUBLIC_FQDN not set in .env")
        return

    subdomain = cfg.subdomain
    fqdn      = f"{subdomain}.{domain}"

    print(f"\nAuto-provisioning cloud resources for {fqdn}...")

    # ── Caddyfile ───────────────────────────────────────────────────────────
    caddyfile = repo_root / "unified-stack" / "templates" / "caddy" / "Caddyfile"
    caddy_changed = _edit_caddyfile(cfg, caddyfile, dry_run)

    # ── .env + .env.example ─────────────────────────────────────────────────
    _edit_env_files(cfg, repo_root, dry_run, utils)

    # ── Cloudflare DNS ──────────────────────────────────────────────────────
    if cf_token:
        cf = utils.CloudflareClient(cf_token)
        try:
            zone_id = cf.get_zone_id(domain)
            records = cf.get_dns_records(zone_id, domain)
            if subdomain in records:
                print(f"  DNS: {fqdn} already exists ({','.join(records[subdomain])})")
            elif dry_run:
                print(f"  DNS: would create CNAME {fqdn} (using auth.{domain} as target reference)")
            else:
                target = cf.get_cname_target(zone_id, f"{ak_sub}.{domain}")
                if not target:
                    print(f"  DNS: could not resolve CNAME target via {ak_sub}.{domain} — create manually")
                else:
                    cf.create_cname(zone_id, fqdn, target)
                    print(f"  DNS: created CNAME {fqdn} → {target}")
        except Exception as exc:
            print(f"  DNS: {exc}")
    else:
        print("  DNS: CLOUDFLARE_API_TOKEN not set — skipping")

    # ── Authentik proxy provider + application ──────────────────────────────
    if ak_token:
        ak = utils.AuthentikClient(f"https://{ak_sub}.{domain}", ak_token)
        try:
            _provision_authentik_proxy(ak, cfg, domain, dry_run)
        except Exception as exc:
            print(f"  Authentik: {exc}")
    else:
        print("  Authentik: AUTHENTIK_BOOTSTRAP_TOKEN not set — skipping")

    # ── Reload Caddy if Caddyfile was changed ───────────────────────────────
    if not dry_run and caddy_changed:
        print("  Caddy: reloading config...")
        reload_result = subprocess.run(
            ["docker", "exec", "caddy", "caddy", "reload",
             "--config", "/etc/caddy/Caddyfile"],
        )
        if reload_result.returncode == 0:
            print("  Caddy: reloaded OK")
        else:
            print("  Caddy: reload failed — run 'docker exec caddy caddy reload --config /etc/caddy/Caddyfile' manually")

    # ── Final health check via check-stack.py ───────────────────────────────
    if not dry_run:
        check_script = repo_root / "unified-stack" / "scripts" / "check-stack.py"
        if check_script.exists():
            print("\nRunning stack health check (check-stack.py)...")
            subprocess.run(
                [sys.executable, str(check_script)],
                cwd=str(repo_root / "unified-stack"),
            )


# -- CLI --------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scaffold a new service for the openirvana stack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("name", help="Service name (e.g. paperless, mealie)")
    p.add_argument("--port",      type=int, default=80,          metavar="PORT",
                   help="Internal container port (default: 80)")
    p.add_argument("--image",     default="",                     metavar="IMAGE",
                   help="Docker image (default: empty placeholder)")
    p.add_argument("--type",      choices=["standalone", "unified"], default="standalone",
                   help="standalone=dev/ Tailscale-sidecar; unified=Caddy+Authentik (default: standalone)")
    p.add_argument("--auth",      choices=["authentik", "native-oidc", "none"], default="authentik",
                   help="Auth mode for unified type (default: authentik)")
    p.add_argument("--db",        choices=["none", "postgres", "redis", "both"], default="none",
                   help="Add local DB containers - standalone only (default: none)")
    p.add_argument("--subdomain", default="",                     metavar="SLUG",
                   help="External subdomain (default: service name)")
    p.add_argument("--out",       default="",                     metavar="DIR",
                   help="Output directory (default: ./dev/<name> or ./unified-stack/services/<name>)")
    p.add_argument("--dry-run",   action="store_true",
                   help="Print generated content without writing files")
    p.add_argument("--no-host-setup", action="store_true",
                   help="Skip SSH provisioning of host directories")
    p.add_argument("--ssh-host",  default=_DEFAULT_SSH_HOST,     metavar="USER@HOST",
                   help=f"SSH target for host provisioning (default: {_DEFAULT_SSH_HOST})")
    p.add_argument("--ssh-key",   default=_DEFAULT_SSH_KEY,      metavar="PATH",
                   help=f"SSH identity file (default: {_DEFAULT_SSH_KEY})")
    p.add_argument("--repo-path", default=_DEFAULT_REPO_PATH,    metavar="PATH",
                   help=f"Repo path on the Docker host (default: {_DEFAULT_REPO_PATH})")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    name      = args.name.lower().replace(" ", "-")
    subdomain = args.subdomain or name
    image     = args.image or f"# TODO: set image for {name}"

    repo_root = Path(__file__).resolve().parent
    if args.out:
        out = Path(args.out).resolve()
    elif args.type == "standalone":
        out = repo_root / "dev" / name
    else:
        out = repo_root / "unified-stack" / "services" / name

    cfg = ServiceConfig(
        name=name,
        port=args.port,
        image=image,
        service_type=args.type,
        auth=args.auth,
        db=args.db,
        subdomain=subdomain,
        out=out,
    )

    if not args.dry_run and out.exists():
        if cfg.type == "standalone":
            print(f"error: {out} already exists - remove it first or use --out to redirect", file=sys.stderr)
            sys.exit(1)
        # unified: dir exists — skip scaffold, run provisioning only
        print(f"  {cfg.name}: {out} already exists — skipping scaffold, running provisioning only")
        if cfg.auth == "authentik":
            _check_and_provision_unified(cfg, dry_run=False)
        sys.exit(0)

    scaffold(cfg, dry_run=args.dry_run)

    if not args.dry_run:
        if args.no_host_setup:
            _print_manual_host_steps(cfg)
        else:
            try:
                _provision_host(cfg, args.ssh_host, args.ssh_key, args.repo_path)
            except Exception as exc:
                print(f"\nHost provisioning failed: {exc}", file=sys.stderr)
                _print_manual_host_steps(cfg)

    if cfg.type == "unified" and cfg.auth == "authentik":
        _check_and_provision_unified(cfg, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
