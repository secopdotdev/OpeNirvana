#!/usr/bin/env python3
"""
check-stack.py — Service reachability and configuration audit.

Reads .env, parses the Caddyfile, queries Cloudflare DNS, and tests each
service's HTTP availability using the Authentik bearer token.  Also queries
the local Docker daemon for container health status.

Usage (from unified-stack/ directory, or any directory):
    python3 scripts/check-stack.py [options]

Options:
    --env PATH              Path to live .env  (default: <unified-stack>/.env)
    --caddyfile PATH        Path to Caddyfile  (default: <unified-stack>/templates/caddy/Caddyfile)
    --compose PATH          Path to docker-compose.yml (default: <unified-stack>/docker-compose.yml)
    --no-probe              Skip live HTTP checks (DNS + config audit only)
    --no-containers         Skip container health table
    --logs SERVICE          Tail logs for SERVICE container and exit
    --tail N                Number of log lines to show with --logs (default: 50)
    --no-color              Plain text output (no ANSI)

Checks per subdomain:
  - Caddyfile backend mapping (handler + upstream)
  - Cloudflare DNS record presence
  - Auth mode (forward-auth / native-OIDC / identity-provider)
  - Unauthenticated response (should be 302→auth for forward-auth services)
  - Authenticated response via Authentik Bearer token (should be 200/302)

Also reports DNS records that have no matching *_SUBDOMAIN env var, but only
for subdomains that have a Caddyfile backend defined on this host — external
services, infrastructure anchors, and undeployed planned services are ignored.
Container health table shows status for every container in the compose project.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

# Resolve unified-stack/ regardless of CWD (script lives in unified-stack/scripts/).
_STACK_DIR = Path(__file__).resolve().parent.parent

# Shared discovery primitives (single source of truth, also used by gen-dashy).
from utils_discovery import (  # noqa: E402
    load_env,
    _brace_content,
    parse_caddyfile,
    parse_compose_containers,
)

# ── ANSI colours ──────────────────────────────────────────────────────────────

_USE_COLOR = True  # set by main() after parsing args

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def ok(s: str) -> str:
    return f"{GREEN}{s}{RESET}" if _USE_COLOR else str(s)

def warn(s: str) -> str:
    return f"{YELLOW}{s}{RESET}" if _USE_COLOR else str(s)

def bad(s: str) -> str:
    return f"{RED}{BOLD}{s}{RESET}" if _USE_COLOR else f"!! {s}"

def info(s: str) -> str:
    return f"{CYAN}{s}{RESET}" if _USE_COLOR else str(s)

def dim(s: str) -> str:
    return f"{DIM}{s}{RESET}" if _USE_COLOR else str(s)

def bold(s: str) -> str:
    return f"{BOLD}{s}{RESET}" if _USE_COLOR else str(s)

def visible_len(s: str) -> int:
    """String length ignoring ANSI escape codes."""
    return len(re.sub(r"\033\[[^m]*m", "", s))


# ── Caddyfile parser ─────────────────────────────────────────────────────────
# load_env / _brace_content / parse_caddyfile / parse_compose_containers now live
# in utils_discovery (imported above) — single source of truth shared with gen-dashy.



# ── Cloudflare DNS ────────────────────────────────────────────────────────────

def get_dns_records(token: str, domain: str) -> dict[str, list[str]]:
    """
    Returns {subdomain: [record_types]} for every DNS record in the zone.
    '@' means the apex record.  Returns {} on any error.

    Delegates to the vendored cloudflare-toolkit `dns.CloudflareClient`
    (canonical: github.com/your-org/cloudflare-toolkit) — the toolkit raises
    on a missing zone or transient API/network error, which we map back to the
    fail-soft {} this audit expects so a DNS blip never aborts the stack check.
    """
    from dns import CloudflareClient  # vendored sibling module

    try:
        cf = CloudflareClient(token)
        zone_id = cf.get_zone_id(domain)
        return cf.get_dns_records(zone_id, domain)
    except (RuntimeError, OSError) as exc:
        print(warn(f"  Cloudflare zone/DNS lookup failed: {exc}"), file=sys.stderr)
        return {}


# ── HTTP probes ───────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following 3xx — we want the raw redirect code."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # returning None causes HTTPError to be raised with the 3xx code


_opener = urllib.request.build_opener(_NoRedirect())


def _http_head(url: str, headers: dict | None = None, timeout: int = 10) -> tuple[int, str, bool]:
    """Returns (status_code, Location_header, cf_proxied).  0/False on network error."""
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            cf_proxied = "cf-ray" in {k.lower() for k in resp.headers}
            return resp.status, resp.headers.get("Location", ""), cf_proxied
    except urllib.error.HTTPError as e:
        cf_proxied = "cf-ray" in {k.lower() for k in e.headers}
        return e.code, e.headers.get("Location", ""), cf_proxied
    except Exception:
        return 0, "", False


def _http_get_follow(
    url: str,
    headers: dict | None = None,
    max_hops: int = 8,
    timeout: int = 12,
) -> tuple[int, str, str, str]:
    """
    Follow HTTP redirects (up to max_hops) using the no-redirect opener, then
    return (final_status, final_url, content_type, content_disposition).
    Returns (0, url, '', '') on network/TLS error.
    """
    from urllib.parse import urljoin
    current = url
    last_code = 0
    for _ in range(max_hops):
        code, loc, _ = _http_head(current, headers=headers, timeout=timeout)
        last_code = code
        if code in (301, 302, 303, 307, 308) and loc:
            current = loc if loc.startswith("http") else urljoin(current, loc)
        else:
            break
    req = urllib.request.Request(current, headers=headers or {})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            cd = resp.headers.get("Content-Disposition", "")
            return resp.status, current, ct, cd
    except urllib.error.HTTPError as e:
        ct = e.headers.get("Content-Type", "")
        cd = e.headers.get("Content-Disposition", "")
        return e.code, current, ct, cd
    except Exception:
        return last_code, current, "", ""


def probe_service(
    subdomain: str,
    domain: str,
    token: str,
    auth_mode: str = "forward-auth",
    oidc_cb_path: str = "",
) -> dict:
    """
    Two standard probes + optional native-OIDC chain + callback ping.
      unauth     — no credentials (forward-auth: expect 302→auth; native-OIDC: expect 302→login)
      authed     — Bearer token (forward-auth: expect 200/302; native-OIDC: expect 401)
      oidc_chain — native-OIDC only: follow redirect chain; detect file-download responses
      oidc_cb    — native-OIDC only: hit callback URL with fake code/state;
                   healthy: 400/401 (allauth rejects bad state); broken Redis: 500
    """
    url = f"https://{subdomain}.{domain}/"
    unauth_code, unauth_loc, unauth_cf = _http_head(url)
    auth_code, _, _                    = _http_head(url, headers={"Authorization": f"Bearer {token}"})
    result = {
        "unauth_code":          unauth_code,
        "unauth_loc":           unauth_loc,
        "unauth_cf":            unauth_cf,
        "auth_code":            auth_code,
        "oidc_chain_code":      0,
        "oidc_chain_final_url": "",
        "oidc_chain_ct":        "",
        "oidc_chain_cd":        "",
        "oidc_cb_code":         0,
    }
    if auth_mode == "native-OIDC":
        fc, fu, ct, cd = _http_get_follow(url)
        result["oidc_chain_code"]      = fc
        result["oidc_chain_final_url"] = fu
        result["oidc_chain_ct"]        = ct
        result["oidc_chain_cd"]        = cd
    if auth_mode == "native-OIDC" and oidc_cb_path:
        cb_url = f"https://{subdomain}.{domain}{oidc_cb_path}?code=x&state=x"
        cb_code, _, _ = _http_head(cb_url)
        result["oidc_cb_code"] = cb_code
    return result


# ── Table renderer ────────────────────────────────────────────────────────────

COLS = [
    ("SUBDOMAIN",    "subdomain",  28),
    ("CONTAINER",    "container",  26),
    ("UPTIME",       "uptime",     14),
    ("ISSUES",       "issues",     40),
    ("ENV VAR",      "env_var",    24),
    ("CADDY BACKEND","backend",    36),
    ("DNS",          "dns",         9),
    ("AUTH MODE",    "auth_mode",  15),
    ("UNAUTH",       "unauth",     11),
    ("AUTHED",       "authed",      8),
]


def _pad(s: str, width: int) -> str:
    pad = max(0, width - visible_len(s))
    return s + " " * pad


def render_table(rows: list[dict]) -> None:
    total_width = sum(w + 3 for _, _, w in COLS) + 1
    bar = "─" * total_width

    def header_row() -> str:
        cells = [_pad(bold(h), w + (visible_len(bold(h)) - len(h))) for h, _, w in COLS]
        return "│ " + " │ ".join(cells) + " │"

    print(bar)
    print(header_row())
    print(bar)
    for row in rows:
        cells = [_pad(str(row.get(k, "")), w) for _, k, w in COLS]
        print("│ " + " │ ".join(cells) + " │")
    print(bar)


# ── Upstream host helper ──────────────────────────────────────────────────────

def _upstream_host(upstream: str) -> str:
    """Extract the hostname from an upstream string (strips scheme and port)."""
    if "://" in upstream:
        upstream = upstream.split("://", 1)[1]
    return upstream.split(":")[0].split("/")[0]


# ── Auth mode helper ─────────────────────────────────────────────────────────

def _get_auth_mode(sub_value: str, caddy: dict, env: dict[str, str]) -> str:
    authentik_sub = env.get("AUTHENTIK_SUBDOMAIN", "")
    if sub_value == authentik_sub:
        return "identity-provider"
    if sub_value in caddy["auth_exempt"]:
        return "native-OIDC"
    return "forward-auth"


# ── Row builder ───────────────────────────────────────────────────────────────

def build_row(
    env_var: str,
    sub_value: str,
    env: dict[str, str],
    caddy: dict,
    dns_records: dict[str, list[str]] | None,
    probe_result: dict | None,
    auth_token: str,
    compose_containers: dict[str, str] | None = None,
    container_uptime: dict[str, str] | None = None,
) -> dict:
    issues: list[str] = []
    public_fqdn = env.get("PUBLIC_FQDN", "")
    if compose_containers is None:
        compose_containers = {}

    # ── Caddy backend ─────────────────────────────────────────────────────
    backend_service = caddy["matchers"].get(sub_value)
    if backend_service:
        upstream = caddy["backends"].get(backend_service, "")
        if upstream:
            backend_cell = f"{backend_service} → {upstream}"
        else:
            backend_cell = warn(f"{backend_service} (no upstream)")
            issues.append("backend snippet missing upstream")
        uhost = _upstream_host(upstream) if upstream else ""
        if uhost:
            raw_container = (compose_containers or {}).get(uhost, uhost)
            container_cell = raw_container
            uptime_cell = (container_uptime or {}).get(raw_container, dim("—"))
        else:
            container_cell = dim("—")
            uptime_cell = dim("—")
    else:
        backend_cell = bad("NOT IN CADDYFILE")
        issues.append("no Caddy handler defined")
        container_cell = dim("—")
        uptime_cell = dim("—")

    # ── DNS ───────────────────────────────────────────────────────────────
    if dns_records is None:
        dns_cell = dim("skipped")
    else:
        types = dns_records.get(sub_value, [])
        if types:
            dns_cell = ok(",".join(sorted(set(types))))
        else:
            dns_cell = bad("MISSING")
            issues.append("no DNS record in Cloudflare")

    # ── Auth mode ─────────────────────────────────────────────────────────
    auth_mode     = _get_auth_mode(sub_value, caddy, env)
    authentik_sub = env.get("AUTHENTIK_SUBDOMAIN", "")

    # ── HTTP probe cells ──────────────────────────────────────────────────
    if probe_result is None:
        unauth_cell = dim("skipped")
        authed_cell = dim("skipped")
        if not auth_token:
            issues.append("no Authentik token — probe skipped")
    else:
        uc = probe_result["unauth_code"]
        ul = probe_result["unauth_loc"]
        ac = probe_result["auth_code"]

        # Unauthed response
        if uc == 0:
            unauth_cell = bad("unreachable")
            issues.append("unreachable (network/TLS error)")
        elif uc == 200 and auth_mode == "forward-auth":
            unauth_cell = bad("200 OPEN")
            issues.append("auth gate not firing — 200 without credentials")
        elif uc in (301, 302):
            is_auth_redirect = (
                "goauthentik" in ul
                or (authentik_sub and f"{authentik_sub}." in ul)
            )
            if auth_mode == "forward-auth" and is_auth_redirect:
                unauth_cell = ok(f"{uc}→auth")
            else:
                unauth_cell = ok(str(uc))
        elif uc >= 500:
            unauth_cell = bad(str(uc))
            issues.append(f"server error {uc} (unauthenticated probe)")
        else:
            unauth_cell = warn(str(uc))

        if uc > 0 and not probe_result.get("unauth_cf", True):
            issues.append("bypassed Cloudflare (no CF-RAY header)")

        # Authed response
        if ac == 0:
            authed_cell = bad("unreachable")
            issues.append("unreachable with Bearer token")
        elif ac in (200, 201, 301, 302):
            authed_cell = ok(str(ac))
        elif ac == 401:
            if auth_mode == "forward-auth":
                authed_cell = bad("401")
                issues.append("token rejected (401)")
            else:
                authed_cell = ok("401 ✓")  # native-OIDC: Bearer rejected by design; OIDC chain probe is the real check
        elif ac == 502:
            authed_cell = bad("502")
            issues.append("service container down (502)")
        elif ac >= 500:
            authed_cell = bad(str(ac))
            issues.append(f"backend error {ac}")
        else:
            authed_cell = warn(str(ac))

        # ── OIDC chain (native-OIDC only) ─────────────────────────────────
        if auth_mode == "native-OIDC":
            fc  = probe_result.get("oidc_chain_code", 0)
            fu  = probe_result.get("oidc_chain_final_url", "")
            ct  = probe_result.get("oidc_chain_ct", "")
            cd  = probe_result.get("oidc_chain_cd", "")
            if cd and "attachment" in cd.lower():
                issues.append(f"OIDC chain: file-download (Content-Disposition: {cd[:60]})")
            elif ct and "text/html" not in ct.lower() and "application/json" not in ct.lower() and fc in (200, 201):
                issues.append(f"OIDC chain: unexpected Content-Type '{ct[:60]}'")
            elif fc == 0:
                issues.append("OIDC chain: unreachable after following redirects")
            elif fc >= 500:
                issues.append(f"OIDC chain: server error {fc} at {fu[:60]}")

            # ── OIDC callback ping ─────────────────────────────────────────
            # Probe callback URL with invalid code/state: 400/401 = cache healthy;
            # 500 = cache/Redis failure (verify_jti crashes before state check).
            cb_code = probe_result.get("oidc_cb_code", 0)
            if cb_code == 500:
                issues.append("OIDC callback 500 (cache/Redis failure — check: docker logs <svc> | grep -i redis)")
            elif cb_code not in (0, 400, 401, 403):
                issues.append(f"OIDC callback unexpected {cb_code} (expected 400/401)")

    # ── Issues summary ────────────────────────────────────────────────────
    if issues:
        issues_cell = bad("; ".join(issues))
    else:
        issues_cell = ok("OK")

    return {
        "subdomain": f"{sub_value}.{public_fqdn}",
        "env_var":   env_var,
        "container": container_cell,
        "uptime":    uptime_cell,
        "backend":   backend_cell,
        "dns":       dns_cell,
        "auth_mode": auth_mode,
        "unauth":    unauth_cell,
        "authed":    authed_cell,
        "issues":    issues_cell,
    }


# ── Container health ──────────────────────────────────────────────────────────

def _parse_uptime(status: str, state: str) -> str:
    """Extract uptime from a docker compose ps Status string; truncated to 14 chars."""
    if state not in ("running", "paused"):
        return dim("—")
    m = re.search(r"Up\s+(.+?)(?:\s+\(|$)", status)
    return m.group(1)[:14] if m else dim("—")




def get_container_health(compose_file: Path | None, env_file: Path | None) -> list[dict]:
    """
    Run `docker compose ps --format json` and return a list of container dicts.
    Output is NDJSON (one JSON object per line).  Returns [] on any error.
    """
    cmd = ["docker", "compose"]
    if compose_file:
        cmd += ["-f", str(compose_file)]
    if env_file:
        cmd += ["--env-file", str(env_file)]
    cmd += ["ps", "--format", "json", "--all"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return containers
    except Exception:
        return []


def render_container_table(containers: list[dict]) -> None:
    """Print a compact container health table."""
    if not containers:
        print(warn("  (no containers found — is the stack running?)"))
        return

    COL_WIDTHS = [("CONTAINER", "Name", 34), ("STATE", "State", 10), ("HEALTH", "Health", 12), ("STATUS", "Status", 38)]
    total_width = sum(w + 3 for _, _, w in COL_WIDTHS) + 1
    bar = "─" * total_width

    def header() -> str:
        cells = [_pad(bold(h), w + (visible_len(bold(h)) - len(h))) for h, _, w in COL_WIDTHS]
        return "│ " + " │ ".join(cells) + " │"

    print(bar)
    print(header())
    print(bar)

    for c in sorted(containers, key=lambda x: x.get("Name", "")):
        name   = c.get("Name", "?")
        state  = c.get("State", "?")
        health = c.get("Health", "") or "—"
        status = c.get("Status", "")

        exit_code = c.get("ExitCode", -1)

        # Colour state — exit 0 is an expected termination (init/migration containers)
        if state == "running":
            state_cell = ok(state)
        elif state == "exited" and exit_code == 0:
            state_cell = dim("exited(0)")
        elif state in ("exited", "dead"):
            state_cell = bad(state)
        else:
            state_cell = warn(state)

        # Colour health
        if health in ("healthy", "—"):
            health_cell = ok(health)
        elif health == "starting":
            health_cell = warn(health)
        elif health == "unhealthy":
            health_cell = bad(health)
        else:
            health_cell = dim(health)

        # Colour status — highlight restarting / unhealthy; dim expected exits
        if "Restarting" in status or "unhealthy" in status:
            status_cell = bad(status[:38])
        elif state == "exited" and exit_code == 0:
            status_cell = dim(status[:38])
        elif state == "created":
            status_cell = warn(status[:38])
        elif state != "running":
            status_cell = warn(status[:38])
        else:
            status_cell = dim(status[:38])

        cells = [
            _pad(name[:34], 34),
            _pad(state_cell, 10 + (len(state_cell) - visible_len(state_cell))),
            _pad(health_cell, 12 + (len(health_cell) - visible_len(health_cell))),
            _pad(status_cell, 38 + (len(status_cell) - visible_len(status_cell))),
        ]
        print("│ " + " │ ".join(cells) + " │")

    print(bar)


def show_logs(service: str, compose_file: Path | None, env_file: Path | None, tail: int) -> None:
    """Stream the last `tail` lines of logs for `service` then exit."""
    cmd = ["docker", "compose"]
    if compose_file:
        cmd += ["-f", str(compose_file)]
    if env_file:
        cmd += ["--env-file", str(env_file)]
    cmd += ["logs", "--tail", str(tail), service]
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(bad("docker compose not found"), file=sys.stderr)
        sys.exit(1)


def _wz_exec(container: str, shell_cmd: str, secrets: dict | None = None,
             timeout: int = 15) -> tuple[int, str]:
    """Run `sh -c shell_cmd` inside a container. Secrets are passed via the
    container environment (docker exec -e) and referenced as $VARS inside
    shell_cmd, so they are never interpolated into the command text (no shell
    injection, no secret in the host process list)."""
    cmd = ["docker", "exec"]
    for k, v in (secrets or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [container, "sh", "-c", shell_cmd]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "").strip()


# ── Gluetun VPN tunnel health ─────────────────────────────────────────────────────
# Apps with `network_mode: service:gluetun` (the *arr stack, qbittorrent,
# flaresolverr) MUST egress through gluetun's WireGuard tunnel, never the host's
# WAN. If the tunnel drops and gluetun's firewall fails open — or an app is
# mis-wired onto the default network — those apps would leak the real WAN IP
# (and torrent/download traffic with it). This proves egress is tunnelled by
# comparing each routed app's public IP against Caddy's (the host WAN baseline):
# they MUST differ.

_IP_ECHO = ("curl -s --max-time 8 https://api.ipify.org "
            "|| wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null "
            "|| curl -s --max-time 8 https://icanhazip.com")


def _egress_ip(container: str) -> str:
    """Public IP a container egresses as, or '' if unreachable."""
    rc, out = _wz_exec(container, _IP_ECHO, timeout=20)
    ip = (out or "").strip().splitlines()[-1].strip() if out else ""
    # crude IPv4/IPv6 sanity: must contain a dot or colon and no spaces
    return ip if ip and (("." in ip or ":" in ip) and " " not in ip) else ""


def _gluetun_routed_containers() -> list[str]:
    """Running containers whose network namespace is gluetun's (dynamic — no
    hardcoded app list, so new gluetun-routed services are covered too)."""
    rc = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", "gluetun"],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        return []
    gid = rc.stdout.strip()
    names = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                          capture_output=True, text=True).stdout.split()
    routed = []
    for n in names:
        nm = subprocess.run(["docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", n],
                           capture_output=True, text=True).stdout.strip()
        if nm in ("service:gluetun", "container:gluetun", f"container:{gid}"):
            routed.append(n)
    return routed


def gluetun_tunnel_health(env: dict[str, str]) -> list[dict]:
    """Verify gluetun-routed apps egress via the VPN, not the host WAN.

    Returns [] when gluetun isn't deployed. Each result: {check, ok, detail}.
    """
    rc = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", "gluetun"],
                       capture_output=True, text=True)
    if rc.returncode != 0:
        return []  # gluetun not on this host

    results: list[dict] = []
    wan = _egress_ip("caddy")        # host WAN baseline (caddy shares tailscale-ingress netns, no exit node)
    vpn = _egress_ip("gluetun")      # VPN exit IP

    results.append({"check": "caddy WAN baseline", "ok": bool(wan),
                    "detail": wan or "could not determine"})
    if not vpn:
        # No egress from gluetun: tunnel down. With gluetun's killswitch this is
        # fail-safe (no leak) but the apps are offline — still a FAIL to surface.
        results.append({"check": "gluetun VPN exit", "ok": False,
                        "detail": "no egress — tunnel down or killswitch blocking"})
        return results
    tunnel_ok = bool(wan) and vpn != wan
    results.append({"check": "gluetun VPN exit", "ok": tunnel_ok,
                    "detail": f"{vpn}" + ("" if tunnel_ok else "  == WAN (LEAK!)")})

    # Per-app: every routed container must egress via the VPN IP, not the WAN.
    for app in sorted(_gluetun_routed_containers()):
        if app == "gluetun":
            continue
        aip = _egress_ip(app)
        if not aip:
            results.append({"check": f"app {app}", "ok": None, "detail": "no IP tool / unreachable"})
        elif wan and aip == wan:
            results.append({"check": f"app {app}", "ok": False, "detail": f"{aip}  LEAKING via WAN!"})
        elif aip == vpn:
            results.append({"check": f"app {app}", "ok": True, "detail": f"{aip} (via VPN)"})
        else:
            results.append({"check": f"app {app}", "ok": False,
                            "detail": f"{aip}  != VPN exit (unexpected route)"})
    return results


def render_gluetun_tunnel(results: list[dict]) -> int:
    """Print gluetun tunnel rows; return count of failed (ok is False) checks."""
    if not results:
        return 0
    print(f"\n{bold('Gluetun VPN tunnel (egress leak check)')}\n")
    failed = 0
    for r in results:
        if r["ok"] is True:
            cell = ok("PASS")
        elif r["ok"] is False:
            cell = bad("FAIL"); failed += 1
        else:
            cell = warn("UNKNOWN")
        print(f"  {cell}  {r['check']:<26} {dim(r['detail'])}")
    return failed


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    global _USE_COLOR

    parser = argparse.ArgumentParser(
        description="Audit subdomains: Caddyfile mapping, DNS, live reachability, and container health.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env",
        default=str(_STACK_DIR / ".env"),
        metavar="PATH",
        help="Live .env file (default: <unified-stack>/.env)",
    )
    parser.add_argument(
        "--caddyfile",
        default=str(_STACK_DIR / "templates/caddy/Caddyfile"),
        metavar="PATH",
        help="Caddyfile to parse (default: <unified-stack>/templates/caddy/Caddyfile)",
    )
    parser.add_argument(
        "--compose",
        default=str(_STACK_DIR / "docker-compose.yml"),
        metavar="PATH",
        help="docker-compose.yml to use for container queries (default: <unified-stack>/docker-compose.yml)",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip live HTTP probes; check config only",
    )
    parser.add_argument(
        "--no-containers",
        action="store_true",
        help="Skip container health table",
    )
    parser.add_argument(
        "--logs",
        metavar="SERVICE",
        help="Print logs for SERVICE and exit (uses docker compose logs)",
    )
    parser.add_argument(
        "--tail",
        type=int,
        default=50,
        metavar="N",
        help="Number of log lines to show with --logs (default: 50)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output",
    )
    parser.add_argument(
        "--subdomain",
        metavar="SUBDOMAIN",
        help="Probe only services with this subdomain value (e.g. food, graph)",
    )
    args = parser.parse_args()

    _USE_COLOR = not args.no_color and sys.stdout.isatty()

    env_path       = Path(args.env)
    caddyfile_path = Path(args.caddyfile)
    compose_path   = Path(args.compose)

    # --logs shortcut: print container logs and exit immediately
    if args.logs:
        ep = env_path if env_path.exists() else None
        cp = compose_path if compose_path.exists() else None
        show_logs(args.logs, cp, ep, args.tail)
        sys.exit(0)

    for p in (env_path, caddyfile_path):
        if not p.exists():
            print(bad(f"File not found: {p}"), file=sys.stderr)
            sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────────
    print(f"Reading {env_path} …")
    env = load_env(env_path)

    domain             = env.get("PUBLIC_FQDN", "")
    cf_token           = env.get("CLOUDFLARE_API_TOKEN", "")
    ak_user_token      = env.get("AUTHENTIK_USER_ACCESS_TOKEN", "")
    ak_bootstrap_token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN", "")
    ak_token           = ak_user_token or ak_bootstrap_token
    _using_user_token  = bool(ak_user_token)

    if not domain:
        print(bad("PUBLIC_FQDN not set in .env"), file=sys.stderr)
        sys.exit(1)

    print(f"Parsing Caddyfile …")
    caddy = parse_caddyfile(caddyfile_path, env)

    # ── Cloudflare DNS ────────────────────────────────────────────────────
    dns_records: dict[str, list[str]] | None = None
    if cf_token:
        print(f"Querying Cloudflare DNS for {domain} …")
        dns_records = get_dns_records(cf_token, domain)
    else:
        print(warn("  CLOUDFLARE_API_TOKEN not set — DNS check skipped"))

    # ── Load compose service → container name mapping ─────────────────────
    cp = compose_path if compose_path.exists() else None
    ep = env_path if env_path.exists() else None
    compose_containers, compose_caddy_env = parse_compose_containers(cp, ep)

    # Pre-fetch container health once; reused for uptime in audit table and health section
    _all_containers = get_container_health(cp, ep)
    container_uptime: dict[str, str] = {
        c["Name"]: _parse_uptime(c.get("Status", ""), c.get("State", ""))
        for c in _all_containers
        if c.get("Name")
    }

    # ── Collect all *_SUBDOMAIN vars ──────────────────────────────────────
    subdomain_vars: dict[str, str] = {
        k: v for k, v in env.items()
        if k.endswith("_SUBDOMAIN") and v.strip()
    }
    # Merge compose-default *_SUBDOMAIN values (services absent from .env use docker-compose defaults)
    for k, v in compose_caddy_env.items():
        if k.endswith("_SUBDOMAIN") and v and k not in subdomain_vars:
            subdomain_vars[k] = v

    if args.subdomain:
        subdomain_vars = {k: v for k, v in subdomain_vars.items() if v == args.subdomain}

    if not args.no_probe:
        if not ak_token:
            print(warn("  AUTHENTIK_USER_ACCESS_TOKEN and AUTHENTIK_BOOTSTRAP_TOKEN both unset — HTTP probes skipped"))
        elif not _using_user_token:
            print(warn("  AUTHENTIK_USER_ACCESS_TOKEN not set — falling back to BOOTSTRAP token (probes won't mirror real-user auth)"))
        else:
            print(f"  Using AUTHENTIK_USER_ACCESS_TOKEN for probes (per-user end-to-end check)")

    # ── OIDC callback paths for django-allauth services only ──────────────
    # Probe ?code=x&state=x exercises verify_jti() → cache.add() → Redis.
    # Only meaningful for services using django-allauth (Tandoor).
    # Nextcloud (user_oidc PHP app) uses a different auth stack — the probe
    # produces false positives for it.
    _oidc_cb_paths: dict[str, str] = {
        env.get("TANDOOR_SUBDOMAIN", "food"): "/accounts/oidc/authentik/login/callback/",
    }

    # ── Build one row per unique subdomain value ──────────────────────────
    rows: list[dict] = []
    seen_values: set[str] = set()
    n_probed = 0

    # ── Apex domain: example.com (Dashy) ────────────────────────────────────
    # The apex has no *_SUBDOMAIN var; probe it as a fixed special-case row.
    apex_issues: list[str] = []
    if not args.no_probe and ak_token:
        apex_url = f"https://{domain}/"
        apex_unauth_code, apex_unauth_loc, _ = _http_head(apex_url)
        apex_auth_code, _, _ = _http_head(apex_url, headers={"Authorization": f"Bearer {ak_token}"})
        apex_ping_code, _, _ = _http_head(f"https://{domain}/outpost.goauthentik.io/ping")

        if apex_unauth_code == 0:
            apex_unauth_cell = bad("unreachable")
            apex_issues.append("apex unreachable (network/TLS error)")
        elif apex_unauth_code == 200:
            apex_unauth_cell = bad("200 OPEN")
            apex_issues.append("auth gate not firing — 200 without credentials")
        elif apex_unauth_code in (301, 302):
            is_auth = "goauthentik" in apex_unauth_loc or f"{env.get('AUTHENTIK_SUBDOMAIN', 'auth')}." in apex_unauth_loc
            apex_unauth_cell = ok(f"{apex_unauth_code}→auth") if is_auth else warn(str(apex_unauth_code))
        elif apex_unauth_code >= 500:
            apex_unauth_cell = bad(str(apex_unauth_code))
            apex_issues.append(f"apex server error {apex_unauth_code}")
        else:
            apex_unauth_cell = warn(str(apex_unauth_code))

        apex_auth_cell = ok(str(apex_auth_code)) if apex_auth_code in (200, 301, 302) else bad(str(apex_auth_code) or "unreachable")
        if apex_auth_code not in (200, 301, 302):
            apex_issues.append(f"apex authenticated probe returned {apex_auth_code or 'unreachable'}")

        if apex_ping_code not in (200, 204):
            apex_issues.append(f"outpost ping returned {apex_ping_code} (expected 200/204)")

        # Check DNS: apex '@' record
        if dns_records is not None:
            apex_dns_types = dns_records.get("@", [])
            apex_dns_cell = ok(",".join(sorted(set(apex_dns_types)))) if apex_dns_types else bad("MISSING")
            if not apex_dns_types:
                apex_issues.append("no apex DNS record in Cloudflare")
        else:
            apex_dns_cell = dim("skipped")

        _apex_uhost = _upstream_host("dashy:8080")
        _apex_container = compose_containers.get(_apex_uhost, _apex_uhost)
        rows.append({
            "subdomain": f"(apex) {domain}",
            "env_var":   dim("—"),
            "container": _apex_container,
            "uptime":    container_uptime.get(_apex_container, dim("—")),
            "backend":   "dashy → dashy:8080",
            "dns":       apex_dns_cell,
            "auth_mode": "forward-auth",
            "unauth":    apex_unauth_cell,
            "authed":    apex_auth_cell,
            "issues":    bad("; ".join(apex_issues)) if apex_issues else ok("OK"),
        })

    for env_var, sub_value in sorted(subdomain_vars.items(), key=lambda x: x[1]):
        if sub_value in seen_values:
            continue
        seen_values.add(sub_value)

        # HTTP probe
        probe_result: dict | None = None
        if not args.no_probe and ak_token:
            _mode = _get_auth_mode(sub_value, caddy, env)
            _cb_path = _oidc_cb_paths.get(sub_value, "") if _mode == "native-OIDC" else ""
            probe_result = probe_service(sub_value, domain, ak_token, auth_mode=_mode, oidc_cb_path=_cb_path)
            n_probed += 1
            # Brief pause to avoid hammering Authentik
            if n_probed % 5 == 0:
                time.sleep(0.5)

        rows.append(
            build_row(env_var, sub_value, env, caddy, dns_records, probe_result, ak_token, compose_containers, container_uptime)
        )

    # ── DNS orphans: records with no matching _SUBDOMAIN var ─────────────
    # Only flag subdomains that have a Caddyfile backend defined on this host.
    # DNS records for external services, infrastructure anchors, and services
    # not yet wired into Caddy are silently ignored — Caddy aborts them
    # regardless, so they are not currently hosted here.
    if dns_records:
        infra_types = {"MX", "TXT", "NS", "SOA", "CAA", "SRV", "LOC"}
        caddy_subs = set(caddy["matchers"].keys())
        for dns_sub, types in sorted(dns_records.items()):
            if dns_sub in ("@", "*") or dns_sub in seen_values:
                continue
            if set(types).issubset(infra_types):
                continue
            if dns_sub not in caddy_subs:
                continue
            rows.append({
                "subdomain": f"{dns_sub}.{domain}",
                "env_var":   warn("(no env var)"),
                "container": dim("—"),
                "uptime":    dim("—"),
                "backend":   dim("unknown"),
                "dns":       ok(",".join(sorted(set(types)))),
                "auth_mode": dim("unknown"),
                "unauth":    dim("skipped"),
                "authed":    dim("skipped"),
                "issues":    warn("DNS record exists but no _SUBDOMAIN var"),
            })

    # ── Caddyfile backends with no _SUBDOMAIN var (orphan backends) ───────
    for service in sorted(caddy["matchers"].values()):
        # Check if this service's subdomain is covered by any env var
        sub = next((s for s, svc in caddy["matchers"].items() if svc == service and s in seen_values), None)
        if sub is None:
            # Find the subdomain value from matchers
            orphan_sub = next((s for s, svc in caddy["matchers"].items() if svc == service), None)
            if orphan_sub and orphan_sub not in seen_values:
                seen_values.add(orphan_sub)
                orphan_upstream = caddy["backends"].get(service, "")
                orphan_uhost = _upstream_host(orphan_upstream) if orphan_upstream else ""
                orphan_container = compose_containers.get(orphan_uhost, orphan_uhost) if orphan_uhost else dim("—")
                rows.append({
                    "subdomain": f"{orphan_sub}.{domain}",
                    "env_var":   warn("(no env var)"),
                    "container": orphan_container,
                    "uptime":    container_uptime.get(orphan_container, dim("—")),
                    "backend":   f"{service} → {orphan_upstream or '?'}",
                    "dns":       dim("?") if dns_records is None else (
                        ok(",".join(sorted(set(dns_records.get(orphan_sub, []))))) if dns_records.get(orphan_sub) else warn("?")
                    ),
                    "auth_mode": dim("unknown"),
                    "unauth":    dim("skipped"),
                    "authed":    dim("skipped"),
                    "issues":    warn("Caddyfile backend has no _SUBDOMAIN env var"),
                })

    # ── Output ────────────────────────────────────────────────────────────
    print(f"\n{bold('Stack audit')} — {bold(domain)}\n")
    render_table(rows)

    # Count rows where issues cell contains a problem marker
    def row_has_issue(r: dict) -> bool:
        raw = re.sub(r"\033\[[^m]*m", "", str(r.get("issues", "")))
        return raw not in ("OK",) and not raw.startswith("skipped")

    n_issues = sum(1 for r in rows if row_has_issue(r))
    total = len(rows)

    print()
    if n_issues:
        print(bad(f"{n_issues}/{total} service(s) need attention"))
    else:
        print(ok(f"All {total} services OK"))

    # Legend
    if _USE_COLOR:
        print(
            f"\n{dim('Legend:')}  "
            f"{ok('green')}=OK  "
            f"{warn('yellow')}=warning  "
            f"{bad('red')}=misconfiguration  "
            f"{dim('dim')}=skipped/unknown"
        )

    # ── Container health ──────────────────────────────────────────────────
    if not args.no_containers:
        print(f"\n{bold('Container health')}\n")
        render_container_table(_all_containers)

        def _container_needs_attention(c: dict) -> bool:
            state = c.get("State", "")
            if c.get("Health") == "unhealthy":
                return True
            if state == "running":
                return False
            if state == "exited" and c.get("ExitCode", -1) == 0:
                return False  # init/migration container — expected exit
            return True  # restarting, created, dead, non-zero exit

        n_bad = sum(1 for c in _all_containers if _container_needs_attention(c))
        print()
        if n_bad:
            print(bad(f"{n_bad}/{len(_all_containers)} container(s) need attention"))
            print(dim(f"  Tip: rerun with --logs <service> to inspect a specific container"))
        elif _all_containers:
            print(ok(f"All {len(_all_containers)} containers healthy"))

    # ── Gluetun VPN tunnel (egress leak check) ────────────────────────────
    # Confirms apps on gluetun's netns egress via WireGuard, not the host WAN.
    if not args.no_probe:
        try:
            _gt = gluetun_tunnel_health(env)
        except (subprocess.SubprocessError, OSError) as exc:
            _gt = []
            print(warn(f"\nGluetun tunnel check skipped: {exc}"))
        _gt_failed = render_gluetun_tunnel(_gt)
        if _gt:
            print()
            if _gt_failed:
                print(bad(f"Gluetun tunnel: {_gt_failed} check(s) FAILED — VPN leak or tunnel down"))
            else:
                print(ok("Gluetun tunnel: all routed apps egress via VPN (no leak)"))


if __name__ == "__main__":
    main()
