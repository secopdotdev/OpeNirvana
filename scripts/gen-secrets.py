#!/usr/bin/env python3
"""
gen-secrets.py — populate empty secret vars in .env with cryptographically
secure random values. Safe character set: A-Za-z0-9 plus - and _
(excludes = + / $ \\ ' " ` # & | ; < > ! % @ space — all known to break env
parsing or application password validators).

Usage:
    python3 scripts/gen-secrets.py [path/to/.env] [--apply]

    --apply   After generating secrets, apply them to the running stack:
                - Updates Postgres user passwords (ALTER ROLE)
                - Deletes the wazuh-security-init flag so it re-seeds OpenSearch
                - Restarts wazuh-dashboard to rebuild its keystore
              Requires the stack to already be running.

Existing non-empty values are NEVER overwritten. Run again safely at any time.
"""

import argparse
import re
import secrets
import string
import subprocess
import sys
import time
from pathlib import Path

# ── Secret generation ──────────────────────────────────────────────────────────

_ALPHABET = string.ascii_letters + string.digits + "-_"
_HEX      = string.digits + "abcdef"


def gen_secret(n: int = 30) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def gen_hex(n: int = 64) -> str:
    return "".join(secrets.choice(_HEX) for _ in range(n))


def wazuh_secret(n: int = 28) -> str:
    # Wazuh requires upper + lower + digit + special (>=8 chars total).
    # Our alphabet satisfies upper/lower/digit; _W suffix guarantees a special char.
    return gen_secret(n) + "_W"


# ── .env file helpers ──────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _get_value(content: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}=(.*)$", content, re.MULTILINE)
    return m.group(1).strip().rstrip("\r") if m else ""


def set_if_empty(path: Path, key: str, value: str) -> None:
    content = _read(path)
    if _get_value(content, key):
        print(f"  SKIP {key} (already set)")
        return
    # Fill a blank KEY= line in-place, or append if the key is absent entirely.
    new = re.sub(
        rf"^({re.escape(key)}=)\s*$",
        lambda m: f"{m.group(1)}{value}",
        content,
        flags=re.MULTILINE,
    )
    if new == content:
        new = content.rstrip("\n") + f"\n{key}={value}\n"
    path.write_text(new, encoding="utf-8")
    print(f"  SET  {key}")


# ── Docker helpers ─────────────────────────────────────────────────────────────

def _container_state(name: str) -> str | None:
    r = subprocess.run(
        ["docker", "inspect", name, "--format", "{{.State.Status}}"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def _docker_exec(container: str, *cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True, text=True,
    )


# ── Container-issued keys ──────────────────────────────────────────────────────

def fetch_crowdsec_key(env_path: Path) -> None:
    key = "CROWDSEC_BOUNCER_KEY"
    if _get_value(_read(env_path), key):
        print(f"  SKIP {key} (already set)")
        return
    state = _container_state("crowdsec")
    if state is None:
        print(f"  SKIP {key} (container 'crowdsec' not found — run after first bring-up)")
        return
    if state != "running":
        print(f"  SKIP {key} (container 'crowdsec' is {state}, not running)")
        return
    bouncer_name = f"caddy-{int(time.time())}"
    r = _docker_exec("crowdsec", "cscli", "bouncers", "add", bouncer_name, "-o", "raw")
    value = r.stdout.strip()
    if not value:
        print(f"  SKIP {key} (cscli bouncers add returned empty — check CrowdSec logs)")
        return
    set_if_empty(env_path, key, value)


# Code run inside the authentik-server container to retrieve the proxy outpost token.
# Passed to python3 -c via docker exec; bootstrap token arrives as sys.argv[1].
_AUTHENTIK_SNIPPET = """\
import sys, urllib.request, json, urllib.error
admin_token = sys.argv[1]
base = "http://localhost:9000"
def api_get(path):
    req = urllib.request.Request(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {admin_token}"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())
try:
    data = api_get("/api/v3/outposts/instances/?page_size=100")
    outposts = [o for o in data.get("results", []) if o.get("type") == "proxy"]
    if not outposts:
        print("NO_OUTPOSTS", end=""); sys.exit(0)
    identifier = outposts[0]["token_identifier"]
    key_data = api_get(f"/api/v3/core/tokens/{identifier}/view_key/")
    print(key_data["key"], end="")
except urllib.error.HTTPError as e:
    print(f"HTTP_ERROR_{e.code}", end="")
except Exception as e:
    print(f"ERROR_{str(e)[:40]}", end="")
"""


def fetch_authentik_outpost_token(env_path: Path) -> None:
    key = "AUTHENTIK_OUTPOST_TOKEN"
    content = _read(env_path)
    if _get_value(content, key):
        print(f"  SKIP {key} (already set)")
        return
    state = _container_state("authentik-server")
    if state is None:
        print(f"  SKIP {key} (container 'authentik-server' not found — run after first bring-up)")
        return
    if state != "running":
        print(f"  SKIP {key} (container 'authentik-server' is {state}, not running)")
        return
    bootstrap_token = _get_value(content, "AUTHENTIK_BOOTSTRAP_TOKEN")
    if not bootstrap_token:
        print(f"  SKIP {key} (AUTHENTIK_BOOTSTRAP_TOKEN not set — set it first)")
        return

    r = _docker_exec("authentik-server", "python3", "-c", _AUTHENTIK_SNIPPET, bootstrap_token)
    token = r.stdout.strip()
    if not token or token == "NO_OUTPOSTS":
        print(f"  SKIP {key} (no proxy outpost configured in Authentik)")
        return
    if token.startswith(("HTTP_ERROR_", "ERROR_")):
        print(f"  SKIP {key} (API error: {token})")
        return
    set_if_empty(env_path, key, token)


# ── --apply: sync secrets into the running stack ───────────────────────────────

def apply_secrets(env_path: Path) -> None:
    content = _read(env_path)

    def val(k: str) -> str:
        return _get_value(content, k)

    print("--- Applying secrets to running stack ---")
    print()

    # Postgres password sync.
    if _container_state("postgres") == "running":
        pg_user = val("POSTGRES_SUPERUSER") or "postgres"
        pg_pass = val("POSTGRES_SUPERUSER_PASSWORD")

        def alter_role(role: str, password: str) -> None:
            if not password:
                return
            sql = (
                f"DO $$ BEGIN "
                f"IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN "
                f"ALTER USER {role} PASSWORD '{password}'; "
                f"END IF; END $$;"
            )
            subprocess.run(
                ["docker", "exec", "postgres", "psql", "-U", pg_user, "-c", sql],
                capture_output=True,
            )

        subprocess.run(
            ["docker", "exec", "postgres", "psql", "-U", pg_user,
             "-c", f"ALTER USER {pg_user} PASSWORD '{pg_pass}';"],
            capture_output=True,
        )
        for role, env_key in [
            ("authentik", "AUTHENTIK_DB_PASSWORD"),
            ("nextcloud", "NEXTCLOUD_DB_PASSWORD"),
            ("tandoor",   "TANDOOR_DB_PASSWORD"),
            ("vikunja",   "VIKUNJA_DB_PASSWORD"),
            ("affine",    "AFFINE_DB_PASSWORD"),
            ("immich",    "IMMICH_DB_PASSWORD"),
            ("n8n",       "N8N_DB_PASSWORD"),
        ]:
            alter_role(role, val(env_key))
        print("  APPLIED  Postgres user passwords")
    else:
        print("  SKIP     Postgres not running — start stack first, then re-run with --apply")

    # Wazuh: delete the security-init flag so the next bring-up re-seeds OpenSearch.
    dock_conf = val("DOCK_CONF")
    if dock_conf:
        flag = Path(dock_conf) / "wazuh/certs/.security-initialized"
        if flag.exists():
            flag.unlink()
            print(f"  REMOVED  {flag} (wazuh-security-init will re-seed on next up)")
        else:
            print("  SKIP     wazuh-security-init flag not present (already clean)")

    # Re-run wazuh-security-init, then restart wazuh-dashboard to rebuild its keystore.
    compose_file = env_path.parent / "docker-compose.yml"
    print("  RUNNING  wazuh-security-init ...")
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "--env-file", str(env_path),
         "up", "-d", "wazuh-security-init"],
        capture_output=True,
    )
    for _ in range(300):  # wait up to 15 minutes
        time.sleep(3)
        if _container_state("wazuh-security-init") in ("exited", "dead"):
            break

    r = subprocess.run(
        ["docker", "inspect", "wazuh-security-init", "--format", "{{.State.ExitCode}}"],
        capture_output=True, text=True,
    )
    exit_code = r.stdout.strip()
    if exit_code == "0":
        print("  DONE     wazuh-security-init exited 0")
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "--env-file", str(env_path),
             "up", "-d", "wazuh-dashboard"],
            capture_output=True,
        )
        print("  RESTARTED wazuh-dashboard (rebuilding keystore)")
    else:
        print(f"  ERROR    wazuh-security-init exited {exit_code} — check: docker logs wazuh-security-init")

    print()
    print("Apply complete. Run 'docker compose ps' to verify stack health.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    default_env = Path(__file__).resolve().parent.parent / ".env"

    parser = argparse.ArgumentParser(
        description="Populate empty secret vars in .env with secure random values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Existing non-empty values are NEVER overwritten.\n"
            "Run again safely at any time.\n\n"
            "Examples:\n"
            "  python3 scripts/gen-secrets.py\n"
            "  python3 scripts/gen-secrets.py --apply\n"
            "  python3 scripts/gen-secrets.py /custom/.env --apply"
        ),
    )
    parser.add_argument("env_file", nargs="?", default=str(default_env),
                        metavar="PATH", help="Path to .env (default: <unified-stack>/.env)")
    parser.add_argument("--apply", action="store_true",
                        help="Apply new secrets to the running stack after generating")
    parser.add_argument("--set", metavar="KEY=VALUE",
                        help="Set a single key if currently empty; skip full secret generation")
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if not env_path.exists():
        sys.exit(f"ERROR: .env not found at {env_path}")

    if args.set:
        key, _, value = args.set.partition("=")
        set_if_empty(env_path, key.strip(), value)
        return

    print(f"Generating secrets for: {env_path}")
    print()

    # Postgres
    set_if_empty(env_path, "POSTGRES_SUPERUSER_PASSWORD", gen_secret(30))

    # Redis
    set_if_empty(env_path, "REDIS_PASSWORD", gen_secret(30))

    # Wazuh — requires upper + lower + digit + special; _W suffix covers special.
    set_if_empty(env_path, "WAZUH_API_PASSWORD",                  wazuh_secret(28))
    set_if_empty(env_path, "WAZUH_INDEXER_ADMIN_PASSWORD",        wazuh_secret(28))
    set_if_empty(env_path, "WAZUH_INDEXER_KIBANASERVER_PASSWORD", wazuh_secret(28))

    # Authentik — 50-char secret key is the Authentik recommendation.
    set_if_empty(env_path, "AUTHENTIK_SECRET_KEY",         gen_secret(50))
    set_if_empty(env_path, "AUTHENTIK_BOOTSTRAP_PASSWORD", gen_secret(30))
    set_if_empty(env_path, "AUTHENTIK_BOOTSTRAP_TOKEN",    gen_secret(30))
    set_if_empty(env_path, "AUTHENTIK_DB_PASSWORD",        gen_secret(30))

    # Nextcloud
    set_if_empty(env_path, "NEXTCLOUD_DB_PASSWORD",    gen_secret(30))
    set_if_empty(env_path, "NEXTCLOUD_ADMIN_PASSWORD", gen_secret(30))

    # Coturn
    set_if_empty(env_path, "COTURN_SECRET", gen_secret(30))

    # HPB (Nextcloud Talk High-Performance Backend)
    # NC_HPB_SHARED_SECRET must not change after configuring Nextcloud Talk —
    # it is entered manually in the Talk admin settings and cannot be auto-updated.
    set_if_empty(env_path, "NC_HPB_SHARED_SECRET", gen_secret(30))
    set_if_empty(env_path, "NC_HPB_HASH_KEY",      gen_hex(64))    # HMAC-SHA256; any length
    set_if_empty(env_path, "NC_HPB_BLOCK_KEY",     gen_secret(32)) # AES-256; exactly 32 bytes
    set_if_empty(env_path, "JANUS_API_SECRET",     gen_secret(30))
    set_if_empty(env_path, "JANUS_ADMIN_SECRET",   gen_secret(30))

    # Tandoor — SECRET_KEY must not change after first run (encrypts sessions).
    set_if_empty(env_path, "TANDOOR_DB_PASSWORD", gen_secret(30))
    set_if_empty(env_path, "TANDOOR_SECRET_KEY",  gen_secret(50))

    # Vikunja — JWT_SECRET must not change after first run (signs user tokens).
    set_if_empty(env_path, "VIKUNJA_DB_PASSWORD", gen_secret(30))
    set_if_empty(env_path, "VIKUNJA_JWT_SECRET",  gen_secret(50))

    # AFFiNE
    set_if_empty(env_path, "AFFINE_DB_PASSWORD", gen_secret(30))

    # Dockhand
    set_if_empty(env_path, "DOCKHAND_ENCRYPTION_KEY", gen_secret(32))

    # Immich
    set_if_empty(env_path, "IMMICH_DB_PASSWORD", gen_secret(30))

    # n8n — ENCRYPTION_KEY must not change after first run (encrypts stored credentials).
    set_if_empty(env_path, "N8N_DB_PASSWORD",    gen_secret(30))
    set_if_empty(env_path, "N8N_ENCRYPTION_KEY", gen_secret(32))

    # Container-issued keys — require the stack to be running.
    # CrowdSec bouncer key: issued by cscli; timestamped name avoids collisions on re-runs.
    fetch_crowdsec_key(env_path)

    # Authentik proxy outpost token: issued by the running Authentik server.
    # The embedded outpost's token_identifier is stable across restarts.
    fetch_authentik_outpost_token(env_path)

    print()

    if args.apply:
        apply_secrets(env_path)
    else:
        print(f"Done. Review {env_path}, then bring up the stack:")
        print("  docker compose up -d")
        print()
        print("To also apply secrets to a running stack in one step:")
        print(f"  python3 scripts/gen-secrets.py {env_path} --apply")


if __name__ == "__main__":
    main()
