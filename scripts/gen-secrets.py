#!/usr/bin/env python3
"""
gen-secrets.py — populate empty secret vars in .env with cryptographically
secure random values. Safe character set: A-Za-z0-9 plus - and _
(excludes = + / $ \\ ' " ` # & | ; < > ! % @ space — all known to break env
parsing or application password validators).

Usage:
    python3 scripts/gen-secrets.py [path/to/.env] [--apply] [--target {env,bao}]

    --apply   After generating secrets, apply them to the running stack:
                - Updates Postgres user passwords (ALTER ROLE)
              Requires the stack to already be running.

    --target env  (default) Write generated secrets into .env (existing behaviour).
    --target bao  Seed generated secrets into OpenBao KV v2, write-if-absent.
                  Reads BAO_ADDR from the environment; root token from
                  ${DOCK_CONF}/openbao/init.json or the BAO_TOKEN env var.
                  Container-issued keys (CrowdSec bouncer, Authentik outpost token)
                  are always written to .env only — they require the running stack
                  and cannot be seeded into KV at bootstrap time.

Existing non-empty values are NEVER overwritten. Run again safely at any time.
"""

import argparse
import json
import os
import re
import secrets
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

# grp is Linux/macOS only; guard so the module can be imported on Windows (tests, dev).
try:
    import grp as _grp_module  # type: ignore[import-not-found]
    _GRP_AVAILABLE = True
except ImportError:
    _grp_module = None  # type: ignore[assignment]
    _GRP_AVAILABLE = False

if TYPE_CHECKING:
    from bao_client import BaoClient as _BaoClientType

from secrets_provider import BaoProvider, EnvFileProvider, SecretsProvider

# ── Immutability guard ─────────────────────────────────────────────────────────
# Ensure the sibling module is importable when gen-secrets.py is run directly
# (scripts/ may not be on sys.path in all invocation contexts).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from immutable_keys import assert_immutable  # noqa: E402
from utils import _replace_with_retry  # noqa: E402

# ── Secret generation ──────────────────────────────────────────────────────────

_ALPHABET = string.ascii_letters + string.digits + "-_"
_HEX      = string.digits + "abcdef"


def gen_secret(n: int = 30) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def gen_hex(n: int = 64) -> str:
    return "".join(secrets.choice(_HEX) for _ in range(n))


def docker_gid() -> str:
    """Return the GID of the host 'docker' group as a string.

    Alloy needs this GID in group_add so it can read /var/run/docker.sock.
    Docker's installer assigns the GID dynamically; it varies across distros
    and installation scenarios, so we detect it at gen-secrets time and pin
    the result in .env rather than hard-coding in docker-compose.yml.
    """
    if not _GRP_AVAILABLE:
        return ""  # Not on Linux/macOS; leave blank so compose uses its default.
    try:
        import grp  # noqa: PLC0415 — imported here because it's Linux-only
        return str(grp.getgrnam("docker").gr_gid)  # type: ignore[attr-defined]
    except KeyError:
        return ""   # docker not installed yet; leave blank so compose uses its default


# ── .env file helpers ──────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _atomic_write(path: Path, text: str) -> None:
    """Crash-safe write: temp file in the same dir + os.replace (never partial-write)."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        _replace_with_retry(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _get_value(content: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}=(.*)$", content, re.MULTILINE)
    if not m:
        return ""
    raw = m.group(1).rstrip("\r")
    # Strip inline comments the same way Docker Compose does: ' #' or '\t#' starts a comment.
    raw = re.sub(r"\s+#.*$", "", raw)
    return raw.strip()


def set_if_empty(path: Path, key: str, value: str) -> None:
    content = _read(path)
    if _get_value(content, key):
        print(f"  SKIP {key} (already set)")
        return
    # Fill a blank KEY= line in-place — tolerate a trailing inline comment on the
    # blank line (e.g. `KEY=   # hint`), matching utils.EnvFile.set_if_blank. Without
    # the optional `(#...)?` group, a commented-blank line is not matched and the
    # value is wrongly *appended* as a duplicate; env_get (awk, first-match) then
    # reads the original empty+commented line, silently losing the value
    # (the HOST_PUBLIC_IP → empty nat_1_1_mapping / broken-WebRTC bug).
    new, count = re.subn(
        rf"^({re.escape(key)}=)\s*(#[^\n]*)?\s*$",
        lambda m: f"{m.group(1)}{value}",
        content,
        flags=re.MULTILINE,
    )
    if not count:
        new = content.rstrip("\n") + f"\n{key}={value}\n"
    _atomic_write(path, new)
    print(f"  SET  {key}")


# ── OpenBao target helpers ─────────────────────────────────────────────────────

def _resolve_bao_token(env_path: Path) -> str:
    """Return a root token for OpenBao.

    Preference order:
      1. BAO_TOKEN environment variable (explicit override).
      2. ${DOCK_CONF}/openbao/init.json next to the .env (standard escrow location).
      3. init.json in the same directory as the .env (fallback for non-standard layouts).

    Raises RuntimeError if no token can be found.
    """
    # 1. Explicit env override.
    token_env = os.environ.get("BAO_TOKEN", "")
    if token_env:
        return token_env

    # 2. Derive path from DOCK_CONF entry in the .env file itself.
    try:
        content = _read(env_path)
        dock_conf = _get_value(content, "DOCK_CONF")
        if dock_conf:
            candidate = Path(dock_conf) / "openbao" / "init.json"
            if candidate.exists():
                data = json.loads(candidate.read_text(encoding="utf-8"))
                token = data.get("root_token", "")
                if token:
                    return token
    except Exception:  # noqa: BLE001  — best-effort; fall through
        pass

    # 3. Sibling init.json (non-standard / dev layout).
    candidate2 = env_path.parent / "openbao" / "init.json"
    if candidate2.exists():
        data2 = json.loads(candidate2.read_text(encoding="utf-8"))
        token2 = data2.get("root_token", "")
        if token2:
            return token2

    raise RuntimeError(
        "Cannot resolve OpenBao root token. "
        "Set BAO_TOKEN env var or ensure init.json exists at "
        "${DOCK_CONF}/openbao/init.json (run bao-bootstrap.py first)."
    )


def _make_provider(target: str, env_path: Path) -> "SecretsProvider":
    """Return the appropriate SecretsProvider for the given --target value."""
    if target == "bao":
        return BaoProvider(_build_bao_client(env_path))
    return EnvFileProvider(env_path)


def _build_bao_client(env_path: Path) -> "_BaoClientType":
    """Import BaoClient (hvac-backed adapter) and return an authenticated instance."""
    # Defer import so that --target env (the default) never requires hvac to be installed.
    try:
        from bao_client import BaoClient  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "bao_client / hvac not importable. Ensure host bootstrap ran "
            "(install_python_packages installs hvac) or run `pip install hvac`."
        ) from exc

    addr = os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")
    token = _resolve_bao_token(env_path)
    return BaoClient(addr, token=token)


def _emit(
    spec: "list[tuple[str, str]]",
    target: str,
    env_path: Path,
    bao: "object | None" = None,
) -> None:
    """Dispatch a secrets spec to either the .env file or OpenBao KV v2.

    Args:
        spec:     List of (KEY, generated_value) pairs.
        target:   ``"env"`` (write .env) or ``"bao"`` (seed KV write-if-absent).
        env_path: Path to the .env file.
        bao:      BaoClient instance; required when *target* is ``"bao"``.
    """
    if target == "bao":
        if bao is None:
            raise ValueError("_emit called with target='bao' but no BaoClient provided")
        # bao_client is imported at this point; access kv_get/kv_put via the object.
        for key, value in spec:
            path = key.lower()  # KV path is the lower-cased key name
            existing = bao.kv_get(path)  # type: ignore[union-attr]
            if existing:
                print(f"  SKIP {key} (already in bao:{path})")
                continue
            bao.kv_put(path, {"value": value})  # type: ignore[union-attr]
            print(f"  SET  bao:{path}")
    else:
        for key, value in spec:
            set_if_empty(env_path, key, value)


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
    key = "CROWDSEC_BOUNCER_API_KEY"
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
            if not role or not password:
                return
            subprocess.run(
                ["docker", "exec", "postgres", "psql", "-U", pg_user,
                 "-v", f"ar={role}", "-v", f"apw={password}",
                 "-c", ("DO $body$ BEGIN "
                        "IF EXISTS (SELECT FROM pg_roles WHERE rolname = :'ar') THEN "
                        "EXECUTE format('ALTER USER %I PASSWORD %L', :'ar', :'apw'); "
                        "END IF; END $body$;")],
                capture_output=True,
            )

        subprocess.run(
            ["docker", "exec", "postgres", "psql", "-U", pg_user,
             "-v", f"su={pg_user}", "-v", f"spw={pg_pass}",
             "-c", 'ALTER USER :"su" PASSWORD :\'spw\';'],
            capture_output=True,
        )
        # Auto-discover app roles from *_DB_USER vars in .env
        for m in re.finditer(r'^([A-Z][A-Z0-9_]*)_DB_USER=(\S+)', content, re.MULTILINE):
            alter_role(m.group(2).strip(), val(f"{m.group(1)}_DB_PASSWORD"))
        print("  APPLIED  Postgres user passwords")
    else:
        print("  SKIP     Postgres not running — start stack first, then re-run with --apply")

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
    parser.add_argument(
        "--target",
        choices=["env", "bao"],
        default="env",
        help=(
            "Where to write generated secrets. "
            "'env' (default): write into .env (existing behaviour). "
            "'bao': seed into OpenBao KV v2, write-if-absent. "
            "Container-issued keys are always .env-only regardless of --target."
        ),
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    if not env_path.exists():
        sys.exit(f"ERROR: .env not found at {env_path}")

    if args.set:
        key, _, value = args.set.partition("=")
        key = key.strip()
        # --set is the only path where a caller could supply a NEW value for an
        # already-populated immutable key. Guard it via the shared registry so
        # rotation procedures must go through the documented runbook.
        current = _get_value(_read(env_path), key)
        try:
            assert_immutable(key, current, value)
        except ValueError as exc:
            sys.exit(f"ERROR: {exc}")
        set_if_empty(env_path, key, value)
        return

    target: str = args.target

    # Build the provider eagerly so we fail fast before generating any secrets
    # (avoids generating values we can't store if the backend is unreachable).
    try:
        provider = _make_provider(target, env_path)
    except RuntimeError as exc:
        # KV seeding is never boot-critical: the generated secrets are already
        # written to .env by the earlier `--target env` pass and the running
        # stack reads them from .env. A token/auth failure here must degrade to
        # a clean one-line warning, never a Python traceback in the deploy log.
        if target == "bao":
            print(f"WARNING: OpenBao KV seeding skipped — {exc}", file=sys.stderr)
            print("  (non-fatal: generated secrets remain in .env via --target env)",
                  file=sys.stderr)
            return
        raise

    print(f"Generating secrets for: {env_path}  [target={target}]")
    print()

    # ── Build the secrets spec ─────────────────────────────────────────────────
    # Each entry is (KEY, generated_value). Order is preserved for display.
    # All entries go through _emit() which handles both .env and bao targets.
    secrets_spec: list[tuple[str, str]] = [
        # Postgres
        ("POSTGRES_SUPERUSER_PASSWORD", gen_secret(30)),

        # Redis
        ("REDIS_PASSWORD", gen_secret(30)),

        # Caddy — m2m JWT shared secret for the security app's crypto key
        # (`crypto key verify from env CADDY_JWT_SHARED_SECRET` in the Caddyfile).
        # Required at boot: an empty value makes caddy fail provisioning and
        # crashloop, taking the whole ingress down. Was wired into compose +
        # Caddyfile but never added here, so it was perpetually empty.
        ("CADDY_JWT_SHARED_SECRET", gen_secret(50)),

        # Authentik — 50-char secret key is the Authentik recommendation.
        ("AUTHENTIK_SECRET_KEY",         gen_secret(50)),
        ("AUTHENTIK_BOOTSTRAP_PASSWORD", gen_secret(30)),
        ("AUTHENTIK_BOOTSTRAP_TOKEN",    gen_secret(30)),
        ("AUTHENTIK_DB_PASSWORD",        gen_secret(30)),

        # Nextcloud
        ("NEXTCLOUD_DB_PASSWORD",    gen_secret(30)),
        ("NEXTCLOUD_ADMIN_PASSWORD", gen_secret(30)),

        # Coturn
        ("COTURN_SECRET", gen_secret(30)),

        # HPB (Nextcloud Talk High-Performance Backend)
        # NC_HPB_SHARED_SECRET must not change after configuring Nextcloud Talk —
        # it is entered manually in the Talk admin settings and cannot be auto-updated.
        ("NC_HPB_SHARED_SECRET", gen_secret(30)),
        ("NC_HPB_HASH_KEY",      gen_hex(64)),    # HMAC-SHA256; any length
        ("NC_HPB_BLOCK_KEY",     gen_secret(32)), # AES-256; exactly 32 bytes
        ("JANUS_API_SECRET",     gen_secret(30)),
        ("JANUS_ADMIN_SECRET",   gen_secret(30)),

        # Tandoor — SECRET_KEY must not change after first run (encrypts sessions).
        ("TANDOOR_DB_PASSWORD", gen_secret(30)),
        ("TANDOOR_SECRET_KEY",  gen_secret(50)),

        # Vikunja — JWT_SECRET must not change after first run (signs user tokens).
        ("VIKUNJA_DB_PASSWORD", gen_secret(30)),
        ("VIKUNJA_JWT_SECRET",  gen_secret(50)),

        # CouchDB — Obsidian livesync sync server (replaces AFFiNE).
        # COUCHDB_SECRET is the single-node erlang cookie + session secret; it
        # must not change after first run (immutable_keys), so livesync sessions
        # and stored docs stay valid.
        ("COUCHDB_PASSWORD", gen_secret(30)),
        ("COUCHDB_SECRET",   gen_hex(32)),

        # Grafana — admin password is break-glass only; all logins go through Authentik SSO.
        ("GRAFANA_ADMIN_PASSWORD", gen_secret(24)),

        # Docker socket GID — varies by distro/installer; detected at setup time so
        # docker-compose.yml can reference ${DOCKER_GID} without hard-coding a GID.
        ("DOCKER_GID", docker_gid()),

        # Immich
        ("IMMICH_DB_PASSWORD", gen_secret(30)),

        # n8n — ENCRYPTION_KEY must not change after first run (encrypts stored credentials).
        ("N8N_DB_PASSWORD",    gen_secret(30)),
        ("N8N_ENCRYPTION_KEY", gen_secret(32)),

        # Falco Sidekick UI — credentials enforced at the application level.
        # DISABLEAUTH was removed (M006); these are generated once and stored.
        ("FALCOSIDEKICK_UI_USER",     "falcoadmin"),
        ("FALCOSIDEKICK_UI_PASSWORD", gen_secret(24)),

        # Komodo — passkey shared between komodo-core and komodo-periphery.
        # OIDC client ID/secret are provisioned by set-auth.py oidc, not here.
        ("KOMODO_PASSKEY", gen_secret(40)),
    ]

    # Read the revocation marker directly from the .env file rather than from
    # the provider — the marker is machine-written state, not a vault secret,
    # and must be authoritative regardless of --target (env or bao).
    _bootstrap_revoked = (
        _get_value(_read(env_path), "AUTHENTIK_BOOTSTRAP_TOKEN_REVOKED").lower() == "true"
    )

    # Dispatch the spec through the provider (write-if-blank semantics).
    for key, value in secrets_spec:
        if key == "AUTHENTIK_BOOTSTRAP_TOKEN" and _bootstrap_revoked:
            print("  SKIP AUTHENTIK_BOOTSTRAP_TOKEN (revoked; first-run-and-revoke is permanent)")
            continue
        provider.set_if_blank(key, value)

    # Container-issued keys — require the running stack; always .env-only.
    # These keys are issued by containers at runtime (cscli, Authentik server) and
    # cannot be generated offline. They are excluded from --target bao deliberately:
    # seeding would require the stack to already be up, which defeats the bootstrap
    # order (bootstrap → seed → compose up). They are written to .env regardless of
    # --target so the stack can start correctly.
    #
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
