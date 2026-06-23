#!/usr/bin/env python3
"""
preflight.py — Pre-deploy safety checks for the unified-stack.

Validates required env vars, DNS resolution, free ports, disk space,
and Docker availability before docker compose up runs. Exits non-zero
on any failure so run.sh can abort before touching running containers.

Usage:
    python3 preflight.py [--env PATH]   (default: ../.env)
"""

import argparse
import shutil
import socket
import subprocess
import sys
from pathlib import Path

_STACK_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_ENV = _STACK_DIR / ".env"

# Required env vars that must be non-blank before deploy.
_REQUIRED_VARS = [
    "PUBLIC_FQDN",
    "ADMIN_EMAIL",
    "CLOUDFLARE_API_TOKEN",
    "TZ",
]

# Ports that must be free on the host before Caddy binds them.
_REQUIRED_FREE_PORTS = [80, 443]

# Minimum free disk space in GB on the data volume.
_MIN_DISK_GB = 20

_ok = True


def _fail(msg: str) -> None:
    global _ok
    _ok = False
    print(f"  FAIL {msg}", file=sys.stderr)


def _pass(msg: str) -> None:
    print(f"  OK   {msg}")


def _warn(msg: str) -> None:
    print(f"  WARN {msg}")


def _read_env(env_path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        # Strip inline comments (only when preceded by whitespace).
        val = val.split(" #")[0].strip().strip('"').strip("'")
        result[key.strip()] = val
    return result


def check_required_vars(env: dict[str, str]) -> None:
    for key in _REQUIRED_VARS:
        val = env.get(key, "")
        if val:
            _pass(f"{key} is set")
        else:
            _fail(f"{key} is blank — required before deploy")


def check_dns(fqdn: str) -> None:
    if not fqdn:
        _warn("PUBLIC_FQDN blank — skipping DNS check")
        return
    try:
        socket.getaddrinfo(fqdn, None)
        _pass(f"DNS resolves: {fqdn}")
    except socket.gaierror as exc:
        # WARN, not FAIL: the host resolving the public apex is NOT on any stack
        # functional path. Caddy gets certs via DNS-01 against api.cloudflare.com,
        # inter-service traffic uses Docker's embedded DNS (127.0.0.11), and users
        # reach the apex through public resolvers + the Cloudflare proxy — never via
        # the host's resolver. A split-horizon homelab resolver that returns NODATA
        # for the public FQDN (observed on this host) must not hard-block the deploy.
        _warn(f"PUBLIC_FQDN does not resolve from this host ({fqdn} — {exc}); "
              "non-fatal — not on any stack path (Caddy DNS-01 + Docker DNS + CF proxy)")


def _port_published_by_container(port: int) -> bool:
    """True if a running Docker container publishes *port* on the host.

    On this single-host stack, 80/443 are published by `tailscale-ingress`
    (Caddy shares its netns), surfacing as `0.0.0.0:80->80/tcp` in `docker ps`.
    `admin` is in the `docker` group, so this needs no sudo. More robust than
    parsing `ss`, whose process field is empty for root-owned docker-proxy
    sockets when queried as a non-root user.
    """
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Ports}}\t{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for line in out.splitlines():
        ports_field = line.split("\t", 1)[0]
        if f":{port}->" in ports_field:
            return True
    return False


def check_ports() -> None:
    for port in _REQUIRED_FREE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            in_use = s.connect_ex(("127.0.0.1", port)) == 0
        if not in_use:
            _pass(f"Port {port} is free")
        elif _port_published_by_container(port):
            _pass(f"Port {port} held by a running stack container (redeploy)")
        else:
            _fail(f"Port {port} is in use by a non-stack process — free it before deploying")


def check_disk() -> None:
    usage = shutil.disk_usage("/")
    free_gb = usage.free / (1024 ** 3)
    if free_gb >= _MIN_DISK_GB:
        _pass(f"Disk free: {free_gb:.1f} GB (minimum {_MIN_DISK_GB} GB)")
    else:
        _fail(f"Disk free: {free_gb:.1f} GB — minimum {_MIN_DISK_GB} GB required")


def check_docker() -> None:
    # Docker daemon
    r = subprocess.run(["docker", "info"], capture_output=True)
    if r.returncode == 0:
        _pass("Docker daemon is running")
    else:
        _fail("Docker daemon is not reachable — start it first")
        return

    # Compose v2 (plugin form)
    r = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if r.returncode == 0:
        ver = r.stdout.strip().split()[-1]
        _pass(f"Docker Compose v2: {ver}")
    else:
        _fail("Docker Compose v2 not found — install docker-compose-plugin")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env", default=str(_DEFAULT_ENV), metavar="PATH",
                        help=f"Path to .env (default: {_DEFAULT_ENV})")
    args = parser.parse_args()

    env_path = Path(args.env)
    if not env_path.exists():
        print(f"preflight: .env not found at {env_path}", file=sys.stderr)
        return 1

    env = _read_env(env_path)

    print("\n==> Preflight checks")
    check_required_vars(env)
    check_dns(env.get("PUBLIC_FQDN", ""))
    check_ports()
    check_disk()
    check_docker()

    if _ok:
        print("\n  All preflight checks passed.\n")
        return 0
    else:
        print("\n  One or more preflight checks failed — fix the issues above before deploying.\n",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
