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

Also reports DNS records that have no matching *_SUBDOMAIN env var.
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


# ── .env parser ───────────────────────────────────────────────────────────────

def load_env(path: Path) -> dict[str, str]:
    """
    Parse a .env file.  Strips inline comments, surrounding quotes, and
    expands ${VAR} references using previously-seen values.
    """
    raw: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.split("#")[0].strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            raw[key] = val

    # One-pass ${VAR} expansion
    resolved: dict[str, str] = {}
    for k, v in raw.items():
        resolved[k] = re.sub(
            r"\$\{(\w+)\}", lambda m: raw.get(m.group(1), ""), v
        )
    return resolved


# ── Caddyfile parser ─────────────────────────────────────────────────────────

def _brace_content(text: str, start: int) -> str:
    """Return content between matched braces, starting at the char after '{'."""
    depth, pos = 1, start
    while pos < len(text) and depth:
        c = text[pos]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        pos += 1
    return text[start : pos - 1]


def parse_caddyfile(path: Path, env: dict[str, str]) -> dict:
    """
    Returns a dict with:
      backends:    {service_name: upstream_string}
      matchers:    {subdomain_value: service_name}   (from PUBLIC_FQDN site block)
      auth_exempt: {subdomain_value}                 (skip forward_auth; native OIDC)
    """
    text = path.read_text()

    # Expand {$VAR} → value; leave unresolved vars as literal "{VARNAME}" so
    # they remain visible in debug output rather than becoming empty strings.
    def expand(s: str) -> str:
        return re.sub(
            r"\{\$(\w+)\}",
            lambda m: env.get(m.group(1), f"{{{m.group(1)}}}"),
            s,
        )

    text_exp = expand(text)
    public_fqdn = env.get("PUBLIC_FQDN", "")

    # 1. Named snippets: (snippet-name) { ... }
    snippets: dict[str, str] = {}
    for m in re.finditer(r"\((\w[\w-]*)\)\s*\{", text_exp):
        snippets[m.group(1)] = _brace_content(text_exp, m.end())

    # 2. Backend upstreams from (backend-X) snippets
    backends: dict[str, str] = {}
    for name, body in snippets.items():
        if not name.startswith("backend-"):
            continue
        service = name[len("backend-"):]
        m = re.search(r"reverse_proxy\s+([\w.\[\]/:_-]+)", body)
        if m:
            backends[service] = m.group(1).strip()

    # 3. @name host HOST ...  →  matcher_name → first matching subdomain
    matcher_to_subdomain: dict[str, str] = {}
    for m in re.finditer(
        r"@(\w[\w-]*)\s+\{?host\s+((?:[^\s{}\n]+(?:\s+[^\s{}\n]+)*)?)",
        text_exp,
    ):
        name = m.group(1)
        hosts = m.group(2).split()
        for host in hosts:
            if public_fqdn and host.endswith(f".{public_fqdn}"):
                matcher_to_subdomain[name] = host[: -(len(public_fqdn) + 1)]
                break
    # Also match inline: @name host HOST (no surrounding braces, on same line)
    for m in re.finditer(r"^\s*@(\w[\w-]*)\s+host\s+([\S]+)", text_exp, re.MULTILINE):
        name = m.group(1)
        host = m.group(2).strip()
        if public_fqdn and host.endswith(f".{public_fqdn}") and name not in matcher_to_subdomain:
            matcher_to_subdomain[name] = host[: -(len(public_fqdn) + 1)]

    # 4. handle @name { import backend-X }  →  subdomain → service
    matchers: dict[str, str] = {}
    for m in re.finditer(r"handle\s+@(\w[\w-]*)\s*\{", text_exp):
        matcher_name = m.group(1)
        block = _brace_content(text_exp, m.end())
        imp = re.search(r"import\s+backend-([\w-]+)", block)
        if imp:
            subdomain = matcher_to_subdomain.get(matcher_name)
            if subdomain:
                matchers[subdomain] = imp.group(1)

    # 5. Auth-exempt subdomains from @requires-auth-pub
    auth_exempt: set[str] = set()
    m = re.search(r"@requires-auth-pub\s*\{", text_exp)
    if m:
        block = _brace_content(text_exp, m.end())
        for m2 in re.finditer(r"not\s+host\s+([^\s\n]+)", block):
            host = m2.group(1).strip()
            if public_fqdn and host.endswith(f".{public_fqdn}"):
                auth_exempt.add(host[: -(len(public_fqdn) + 1)])

    return {
        "backends": backends,
        "matchers": matchers,
        "auth_exempt": auth_exempt,
    }


# ── Cloudflare DNS ────────────────────────────────────────────────────────────

def _cf_get(token: str, path: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return {"success": False, "errors": [{"message": body}]}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}


def get_dns_records(token: str, domain: str) -> dict[str, list[str]]:
    """
    Returns {subdomain: [record_types]} for every DNS record in the zone.
    '@' means the apex record.  Returns {} on any error.
    """
    zones = _cf_get(token, f"/zones?name={domain}&status=active")
    if not zones.get("success") or not zones.get("result"):
        errors = zones.get("errors", [])
        msg = errors[0].get("message", "unknown") if errors else "unknown"
        print(warn(f"  Cloudflare zone lookup failed: {msg}"), file=sys.stderr)
        return {}
    zone_id = zones["result"][0]["id"]

    records: dict[str, list[str]] = {}
    page = 1
    while True:
        data = _cf_get(token, f"/zones/{zone_id}/dns_records?per_page=100&page={page}")
        if not data.get("success"):
            break
        for r in data.get("result", []):
            name: str = r["name"]
            rtype: str = r["type"]
            if name == domain:
                sub = "@"
            elif name.endswith(f".{domain}"):
                sub = name[: -(len(domain) + 1)]
            else:
                sub = name
            records.setdefault(sub, []).append(rtype)
        info_page = data.get("result_info", {})
        if page >= info_page.get("total_pages", 1):
            break
        page += 1
    return records


# ── HTTP probes ───────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following 3xx — we want the raw redirect code."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # returning None causes HTTPError to be raised with the 3xx code


_opener = urllib.request.build_opener(_NoRedirect())


def _http_head(url: str, headers: dict | None = None, timeout: int = 10) -> tuple[int, str]:
    """Returns (status_code, Location_header).  0 on network error."""
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")
    except Exception:
        return 0, ""


def probe_service(subdomain: str, domain: str, token: str) -> dict:
    """
    Two probes against https://<subdomain>.<domain>/:
      unauth  — no credentials; forward-auth services should return 302→auth
      authed  — Bearer token; should return 200 or service-own redirect
    """
    url = f"https://{subdomain}.{domain}/"
    unauth_code, unauth_loc = _http_head(url)
    auth_code, _            = _http_head(url, headers={"Authorization": f"Bearer {token}"})
    return {
        "unauth_code": unauth_code,
        "unauth_loc":  unauth_loc,
        "auth_code":   auth_code,
    }


# ── Table renderer ────────────────────────────────────────────────────────────

COLS = [
    ("SUBDOMAIN",    "subdomain",  28),
    ("ENV VAR",      "env_var",    24),
    ("CADDY BACKEND","backend",    36),
    ("DNS",          "dns",         9),
    ("AUTH MODE",    "auth_mode",  15),
    ("UNAUTH",       "unauth",     11),
    ("AUTHED",       "authed",      8),
    ("ISSUES",       "issues",     40),
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


# ── Row builder ───────────────────────────────────────────────────────────────

def build_row(
    env_var: str,
    sub_value: str,
    env: dict[str, str],
    caddy: dict,
    dns_records: dict[str, list[str]] | None,
    probe_result: dict | None,
    auth_token: str,
) -> dict:
    issues: list[str] = []
    public_fqdn = env.get("PUBLIC_FQDN", "")

    # ── Caddy backend ─────────────────────────────────────────────────────
    backend_service = caddy["matchers"].get(sub_value)
    if backend_service:
        upstream = caddy["backends"].get(backend_service, "")
        if upstream:
            backend_cell = f"{backend_service} → {upstream}"
        else:
            backend_cell = warn(f"{backend_service} (no upstream)")
            issues.append("backend snippet missing upstream")
    else:
        backend_cell = bad("NOT IN CADDYFILE")
        issues.append("no Caddy handler defined")

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
    authentik_sub = env.get("AUTHENTIK_SUBDOMAIN", "")
    if sub_value == authentik_sub:
        auth_mode = "identity-provider"
    elif sub_value in caddy["auth_exempt"]:
        auth_mode = "native-OIDC"
    else:
        auth_mode = "forward-auth"

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

        # Authed response
        if ac == 0:
            authed_cell = bad("unreachable")
            issues.append("unreachable with Bearer token")
        elif ac in (200, 201, 301, 302):
            authed_cell = ok(str(ac))
        elif ac == 401:
            authed_cell = bad("401")
            issues.append("token rejected (401)")
        elif ac == 502:
            authed_cell = bad("502")
            issues.append("service container down (502)")
        elif ac >= 500:
            authed_cell = bad(str(ac))
            issues.append(f"backend error {ac}")
        else:
            authed_cell = warn(str(ac))

    # ── Issues summary ────────────────────────────────────────────────────
    if issues:
        issues_cell = bad("; ".join(issues))
    else:
        issues_cell = ok("OK")

    return {
        "subdomain": f"{sub_value}.{public_fqdn}",
        "env_var":   env_var,
        "backend":   backend_cell,
        "dns":       dns_cell,
        "auth_mode": auth_mode,
        "unauth":    unauth_cell,
        "authed":    authed_cell,
        "issues":    issues_cell,
    }


# ── Container health ──────────────────────────────────────────────────────────

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

    domain   = env.get("PUBLIC_FQDN", "")
    cf_token = env.get("CLOUDFLARE_API_TOKEN", "")
    ak_token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN", "")

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

    # ── Collect all *_SUBDOMAIN vars ──────────────────────────────────────
    subdomain_vars: dict[str, str] = {
        k: v for k, v in env.items()
        if k.endswith("_SUBDOMAIN") and v.strip()
    }

    if not ak_token and not args.no_probe:
        print(warn("  AUTHENTIK_BOOTSTRAP_TOKEN not set — HTTP probes skipped"))

    # ── Build one row per unique subdomain value ──────────────────────────
    rows: list[dict] = []
    seen_values: set[str] = set()
    n_probed = 0

    for env_var, sub_value in sorted(subdomain_vars.items(), key=lambda x: x[1]):
        if sub_value in seen_values:
            continue
        seen_values.add(sub_value)

        # HTTP probe
        probe_result: dict | None = None
        if not args.no_probe and ak_token:
            probe_result = probe_service(sub_value, domain, ak_token)
            n_probed += 1
            # Brief pause to avoid hammering Authentik
            if n_probed % 5 == 0:
                time.sleep(0.5)

        rows.append(
            build_row(env_var, sub_value, env, caddy, dns_records, probe_result, ak_token)
        )

    # ── DNS orphans: records with no matching _SUBDOMAIN var ─────────────
    if dns_records:
        # Record types that are infrastructure, not services — skip them
        infra_types = {"MX", "TXT", "NS", "SOA", "CAA", "SRV", "LOC"}
        for dns_sub, types in sorted(dns_records.items()):
            if dns_sub in ("@", "*") or dns_sub in seen_values:
                continue
            if set(types).issubset(infra_types):
                continue
            rows.append({
                "subdomain": f"{dns_sub}.{domain}",
                "env_var":   warn("(no env var)"),
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
                rows.append({
                    "subdomain": f"{orphan_sub}.{domain}",
                    "env_var":   warn("(no env var)"),
                    "backend":   f"{service} → {caddy['backends'].get(service, '?')}",
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
        cp = compose_path if compose_path.exists() else None
        ep = env_path if env_path.exists() else None
        containers = get_container_health(cp, ep)
        render_container_table(containers)

        def _container_needs_attention(c: dict) -> bool:
            state = c.get("State", "")
            if c.get("Health") == "unhealthy":
                return True
            if state == "running":
                return False
            if state == "exited" and c.get("ExitCode", -1) == 0:
                return False  # init/migration container — expected exit
            return True  # restarting, created, dead, non-zero exit

        n_bad = sum(1 for c in containers if _container_needs_attention(c))
        print()
        if n_bad:
            print(bad(f"{n_bad}/{len(containers)} container(s) need attention"))
            print(dim(f"  Tip: rerun with --logs <service> to inspect a specific container"))
        elif containers:
            print(ok(f"All {len(containers)} containers healthy"))


if __name__ == "__main__":
    main()
