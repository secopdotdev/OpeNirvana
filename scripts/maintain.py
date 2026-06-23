#!/usr/bin/env python3
"""
maintain.py — Unified maintenance runner for the unified-stack.

Subcommands:
  backup       Dump all Postgres databases and prune old backups.
  intel        Refresh Zeek threat-intel feeds (URLhaus, Feodo, CrowdStrike).
  prune        Remove dangling Docker images, unused volumes, and stale builder cache.
  cloudflare   Poll Cloudflare security events API and write to firewall-events.log.
  entra-sync   Sync Entra group membership into Authentik (set-auth entra-* + oidc --sync).
  check-stack  Probe all services; send ntfy alert via n8n if any are unhealthy.
  all          Run backup → intel → prune → entra-sync → check-stack.

Usage:
  python3 scripts/maintain.py <backup|intel|prune|cloudflare|all>

Run from any directory; paths resolve relative to this script.
Cron example (daily at 02:00):
  docker-host-config.sh installs the cron job automatically (install_cron_jobs).
  To install manually, run from the unified-stack/ directory to print the entry:
    echo "0 2 * * * root python3 $(realpath scripts/maintain.py) all >> /var/log/maintain.log 2>&1"
"""

import argparse
import csv
import datetime
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

_STACK_DIR = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = Path(__file__).resolve().parent
# Make sibling vendored cloudflare-toolkit modules importable (firewall/hsts/dns →
# _http). Imports are done lazily inside the cloudflare commands so module load
# never hard-depends on them (the CIDR command and its tests stay independent).
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_CF_STATE    = Path("/dock/conf/cloudflare/state.json")
_CF_LOG      = Path("/dock/conf/cloudflare/firewall-events.log")

_CF_IPS_V4   = "https://www.cloudflare.com/ips-v4"
_CF_IPS_V6   = "https://www.cloudflare.com/ips-v6"
_CF_CIDR_FILE = Path("/dock/conf/cloudflare/cf-cidrs.txt")
_ENV_FILE    = _STACK_DIR / ".env"
_MIN_V4, _MIN_V6 = 10, 5  # sane floor; CF publishes ~15 v4 + ~7 v6


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            else:
                val = val.split("#")[0].strip()
            if key and key not in os.environ:
                os.environ[key] = val


_load_env(_STACK_DIR / ".env")


# ── Colour helpers ────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def step(msg: str) -> None:
    print(f"\n\033[36m==> {msg}\033[0m")


def ok(msg: str) -> None:
    print(f"\033[32m{msg}\033[0m")


def err(msg: str) -> None:
    print(f"\033[31m{msg}\033[0m", file=sys.stderr)


# Cloudflare API helpers (api_get/api_patch/api_graphql/resolve_zone_id) now live
# in the vendored _http.py — consumed via the firewall.py / hsts.py toolkit modules
# imported lazily inside cmd_cloudflare / cmd_cloudflare_hsts below.


# ── backup ────────────────────────────────────────────────────────────────────

def cmd_backup() -> None:
    step("pg-backup")

    backup_dir = Path("/dock/backups/postgres")
    retention_days = int(os.environ.get("POSTGRES_BACKUP_RETENTION_DAYS", "14"))
    pg_user = os.environ.get("POSTGRES_SUPERUSER", "postgres")
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    new = backup_dir / f"dump-{timestamp}.sql.zst"
    tmp = Path(str(new) + ".tmp")

    backup_dir.mkdir(parents=True, exist_ok=True)

    with open("/var/log/pg-backup.err", "a") as err_log, tmp.open("wb") as out:
        pg = subprocess.Popen(
            ["docker", "exec", "postgres", "pg_dumpall", "-U", pg_user],
            stdout=subprocess.PIPE,
            stderr=err_log,
        )
        zst = subprocess.Popen(
            ["zstd", "-T0", "-19"],
            stdin=pg.stdout,
            stdout=out,
        )
        if pg.stdout is not None:
            pg.stdout.close()
        zst_rc = zst.wait()
        pg_rc = pg.wait()

    if pg_rc == 0 and zst_rc == 0:
        tmp.rename(new)
        cutoff = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        for old in backup_dir.glob("dump-*.sql.zst"):
            if datetime.datetime.fromtimestamp(old.stat().st_mtime) < cutoff:
                old.unlink()
        ok(f"{ts()} pg_backup ok: {new} (pruned >{retention_days}d)")
    else:
        tmp.unlink(missing_ok=True)
        alert = {
            "ts": ts(),
            "source": "pg_backup",
            "type": "pg_backup_failed",
            "level": "CRITICAL",
            "message": "pg_dumpall failed or zstd encoding failed",
            "scenario": "ops:backup:failed",
            "decisions": [],
        }
        decisions_log = Path("/dock/conf/crowdsec/notifications/decisions.log")
        decisions_log.parent.mkdir(parents=True, exist_ok=True)
        with decisions_log.open("a") as f:
            f.write(json.dumps(alert) + "\n")
        err(f"{ts()} pg_backup FAILED")
        sys.exit(1)


# ── intel ─────────────────────────────────────────────────────────────────────

_ZEEK_HEADER = (
    "#fields\tindicator\tindicator_type\t"
    "meta.source\tmeta.desc\tmeta.do_notice\tmeta.if_in\n"
)

_INTEL_FEEDS = [
    ("urlhaus",             "https://urlhaus.abuse.ch/downloads/csv_recent/"),
    ("feodo",               "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"),
    ("crowdstrike-domains", "https://raw.githubusercontent.com/CrowdStrike/tickeys-io/main/badlist.txt"),
]


def _urlhaus_to_intel(raw: bytes) -> list[str]:
    rows = []
    reader = csv.reader(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="replace"))
    for i, row in enumerate(reader):
        if i == 0 or not row or row[0].startswith("#"):
            continue
        if len(row) < 3:
            continue
        url = row[2].strip().strip('"')
        host = url.removeprefix("https://").removeprefix("http://")
        host = host.split("/")[0].split(":")[0].strip()
        if host:
            rows.append(f"{host}\tIntel::DOMAIN\turlhaus\t-\tT\t-\n")
    return rows


def _feodo_to_intel(raw: bytes) -> list[str]:
    rows = []
    reader = csv.reader(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="replace"))
    for i, row in enumerate(reader):
        if i == 0 or not row or row[0].startswith("#"):
            continue
        if len(row) < 2 or not row[1].strip():
            continue
        rows.append(f"{row[1].strip()}\tIntel::ADDR\tfeodo\t-\tT\t-\n")
    return rows


def _crowdstrike_to_intel(raw: bytes) -> list[str]:
    rows = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.split()[0]
        rows.append(f"{domain}\tIntel::DOMAIN\tcrowdstrike\t-\tT\t-\n")
    return rows


_CONVERTERS = {
    "urlhaus":             _urlhaus_to_intel,
    "feodo":               _feodo_to_intel,
    "crowdstrike-domains": _crowdstrike_to_intel,
}


def cmd_intel() -> None:
    step("zeek-intel-refresh")

    intel_dir = Path("/dock/conf/zeek/intel")
    intel_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        for name, url in _INTEL_FEEDS:
            try:
                with urllib.request.urlopen(url, timeout=120) as resp:
                    raw = resp.read()
            except (urllib.error.URLError, OSError) as exc:
                err(f"{ts()} download failed: {name} ({exc}) — kept previous")
                continue

            try:
                rows = _CONVERTERS[name](raw)
            except Exception as exc:
                err(f"{ts()} convert failed: {name} ({exc}) — kept previous")
                continue

            tsv = tmp / f"{name}.tsv"
            tsv.write_text(_ZEEK_HEADER + "".join(rows), encoding="utf-8")
            shutil.move(str(tsv), str(intel_dir / f"{name}.tsv"))
            ok(f"{ts()} refreshed: {name} ({len(rows)} indicators)")

    r = subprocess.run(["docker", "exec", "zeek", "zeekctl", "deploy"], capture_output=True)
    if r.returncode == 0:
        ok(f"{ts()} zeekctl deploy OK")
    else:
        err(f"{ts()} zeek reload failed")


# ── prune ─────────────────────────────────────────────────────────────────────

def cmd_prune() -> None:
    step("docker-prune")

    subprocess.run(["docker", "image", "prune", "-f"], check=True)
    ok(f"{ts()} dangling images pruned")

    subprocess.run(
        ["docker", "volume", "prune", "-f", "--filter", "label!=keep"],
        check=True,
    )
    ok(f"{ts()} unused volumes pruned")

    subprocess.run(
        ["docker", "builder", "prune", "-f", "--keep-storage", "2GB"],
        check=True,
    )
    ok(f"{ts()} builder cache pruned (keeping 2 GB)")


# ── cloudflare ────────────────────────────────────────────────────────────────

def cmd_cloudflare() -> None:
    step("cloudflare-events")

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        err("CLOUDFLARE_API_TOKEN not set — skipping")
        return

    fqdn = os.environ.get("PUBLIC_FQDN", "")
    if not fqdn:
        err("PUBLIC_FQDN not set — cannot resolve zone ID")
        sys.exit(1)

    from firewall import fetch_events  # vendored cloudflare-toolkit module

    # Fail-soft: fetch_events raises BEFORE it writes the log or advances state, so a
    # caught error leaves the cursor unmoved and the weekly cron resumes from the same
    # point next run. URLError/HTTPError subclass OSError (transient network/HTTP);
    # RuntimeError covers GraphQL errors / null data. Catch both — a bare RuntimeError
    # clause would let a cron-time DNS blip crash the run where it used to fail soft.
    try:
        written = fetch_events(token, fqdn, _CF_LOG, _CF_STATE)
    except (RuntimeError, OSError) as exc:
        err(f"CF API error: {exc} — cursor not advanced")
        return

    ok(f"fetched {written} events")


def cmd_cloudflare_hsts() -> None:
    step("cloudflare-hsts")

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        err("CLOUDFLARE_API_TOKEN not set — skipping")
        return
    fqdn = os.environ.get("PUBLIC_FQDN", "")
    if not fqdn:
        err("PUBLIC_FQDN not set — cannot resolve zone ID")
        sys.exit(1)

    from hsts import apply_hsts  # vendored cloudflare-toolkit module

    # NOT fail-soft on transient errors (matches prior behavior: a resolve/GET blip
    # crashes the run rather than silently skipping HSTS). A 403 is the one tolerated
    # case — a missing Zone Settings:Edit scope is a config issue, not a deploy-blocker.
    # apply_hsts already prints the missing-scope guidance to stderr before re-raising,
    # so the wrapper stays silent on 403 to avoid a duplicate message.
    try:
        apply_hsts(token, fqdn)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return
        raise
    except RuntimeError as exc:
        err(f"CF HSTS update failed: {exc}")
        sys.exit(1)


# ── cloudflare CIDR allowlist refresh (WS1 Layers 2+3) ─────────────────────────

def _fetch_text(url: str) -> str:
    """Fetch a URL body as text. Raises on transport error (caller treats as bad).

    A User-Agent is required: www.cloudflare.com sits behind Cloudflare's own bot
    management, which 403s the default `Python-urllib/x.y` UA. Verified on the host —
    default UA → 403, browser UA → 200. Without this the WS1 CIDR refresh fails closed
    and docker-host-config's UFW step FATALs on a fresh deploy.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (openirvana maintain.py)"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed CF host)
        return resp.read().decode("utf-8")


def _parse_cidrs(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        ipaddress.ip_network(line)  # raises ValueError on garbage → fail-closed
        out.append(line)
    return out


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        # Preserve the existing file's owner + mode across the replace. mkstemp creates
        # the temp owned by the current (often root) user at 0600; without this, a
        # root-run rewrite — host-config's harden_ufw CIDR step, or the weekly CIDR
        # refresh cron — silently leaves .env root-owned, so the non-root deploy user
        # can no longer read it and run.sh aborts with PermissionError on the next deploy.
        if path.exists():
            st = path.stat()
            _chown = getattr(os, "chown", None)  # Unix-only; absent on Windows dev
            if _chown is not None:
                try:
                    _chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    pass  # non-root caller can't chown; ownership already matches anyway
            os.chmod(tmp, st.st_mode & 0o777)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _env_set_cidrs(env_path: Path, value: str) -> None:
    """Replace (or append) CLOUDFLARE_CIDRS="..." preserving all other lines."""
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    new = f'CLOUDFLARE_CIDRS="{value}"'
    replaced = False
    for i, ln in enumerate(lines):
        if ln.startswith("CLOUDFLARE_CIDRS="):
            lines[i] = new
            replaced = True
            break
    if not replaced:
        lines.append(new)
    _atomic_write(env_path, "\n".join(lines) + "\n")


def cmd_cloudflare_cidrs() -> None:
    step("cloudflare-cidrs")
    try:
        v4 = _parse_cidrs(_fetch_text(_CF_IPS_V4))
        v6 = _parse_cidrs(_fetch_text(_CF_IPS_V6))
    except (OSError, ValueError) as exc:
        print(f"  WARN: CF CIDR fetch/parse failed ({exc}); keeping prior allowlist (fail-closed)")
        return
    if len(v4) < _MIN_V4 or len(v6) < _MIN_V6:
        print(f"  WARN: CF CIDR count below floor (v4={len(v4)}, v6={len(v6)}); keeping prior (fail-closed)")
        return
    cidrs = v4 + v6
    _env_set_cidrs(_ENV_FILE, " ".join(cidrs))
    _atomic_write(_CF_CIDR_FILE, "\n".join(cidrs) + "\n")
    print(f"  wrote {len(cidrs)} CF CIDRs to .env (CLOUDFLARE_CIDRS) and {_CF_CIDR_FILE}")


# ── nextcloud housekeeping ──────────────────────────────────────────────────────

_NC_CONTAINER = "nextcloud"


def _nc_occ(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Run `php occ <args>` in the nextcloud container as www-data."""
    return subprocess.run(
        ["docker", "exec", "--user", "www-data", _NC_CONTAINER, "php", "occ", *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _nc_container_state() -> str | None:
    r = subprocess.run(
        ["docker", "inspect", _NC_CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def _nc_set_system(key: str, value: str, vtype: str = "integer") -> None:
    """Idempotently set an occ system config value; only writes when it differs."""
    cur = _nc_occ(["config:system:get", key])
    current = cur.stdout.strip() if cur.returncode == 0 else ""
    if current == value:
        ok(f"{key} already = {value}")
        return
    r = _nc_occ(["config:system:set", key, "--value", value, "--type", vtype])
    if r.returncode == 0:
        ok(f"{key} → {value}" + (f" (was {current!r})" if current else ""))
    else:
        err(f"set {key} failed: {r.stderr.strip() or r.stdout.strip()}")


def _nc_setup_notify_push() -> None:
    """Install the notify_push app and register the Client Push endpoint.

    Idempotent + self-skipping: once the app is enabled AND base_endpoint is
    set, this is a no-op (so it stays quiet on nightly `all` runs). On first
    run it installs the app — which makes the daemon binary appear in the
    shared volume, at which point the notify-push container (polling in its
    command loop) starts — then retries `notify_push:setup` until the daemon
    answers the self-test.
    """
    step("nextcloud: notify_push (Client Push)")

    chk = _nc_occ(["app:list", "--output=json"])
    enabled = False
    if chk.returncode == 0:
        try:
            enabled = "notify_push" in (json.loads(chk.stdout).get("enabled") or {})
        except json.JSONDecodeError:
            pass

    if enabled:
        ep = _nc_occ(["config:app:get", "notify_push", "base_endpoint"])
        if ep.returncode == 0 and ep.stdout.strip():
            ok(f"notify_push already configured: {ep.stdout.strip()}")
            return
    else:
        r = _nc_occ(["app:install", "notify_push"], timeout=300)
        if r.returncode != 0 and "already" not in (r.stderr + r.stdout).lower():
            err(f"app:install notify_push failed: {r.stderr.strip() or r.stdout.strip()}")
            return
        ok("notify_push app installed")

    sub  = os.environ.get("NEXTCLOUD_SUBDOMAIN", "cloud")
    fqdn = os.environ.get("PUBLIC_FQDN", "")
    if not fqdn:
        err("PUBLIC_FQDN not set — cannot configure notify_push endpoint")
        return
    push_url = f"https://{sub}.{fqdn}/push"

    # The notify-push container only starts the daemon once the binary exists
    # (the app we just installed). Its command loop polls every 10s, so retry
    # the self-test for ~90s to cover that startup gap on first deploy.
    last = ""
    for attempt in range(9):
        r = _nc_occ(["notify_push:setup", push_url, "--no-interaction"], timeout=60)
        if r.returncode == 0:
            ok(f"notify_push endpoint configured: {push_url}")
            return
        last = r.stderr.strip() or r.stdout.strip()
        if attempt < 8:
            time.sleep(10)
    err(f"notify_push:setup failed after retries: {last}")


def cmd_nextcloud(expensive: bool = True) -> None:
    """Clear Nextcloud admin-overview setupcheck warnings.

    Fast/idempotent steps (maintenance window, log rotation, missing indices)
    run on every invocation including nightly `all`. The expensive mimetype
    repair runs only when expensive=True (the standalone `nextcloud`
    subcommand) — on large instances it rescans the whole filecache and can
    take hours, so it must never block the nightly run.
    """
    step("nextcloud-housekeeping")

    state = _nc_container_state()
    if state != "running":
        err(f"{_NC_CONTAINER} not running (state={state!r}) — skipping")
        return

    # 1. maintenance_window_start: hour (UTC, 0-23) at which NC's 4-hour
    #    low-load window for heavy background jobs begins. Host/timezone
    #    specific — driven by .env so each deployment can pick its own.
    hour = (os.environ.get("NEXTCLOUD_MAINTENANCE_WINDOW_HOUR_UTC", "8").strip() or "8")
    _nc_set_system("maintenance_window_start", hour, "integer")

    # 2. log_rotate_size: cap nextcloud.log so it rotates and stale error
    #    entries age out (10 MB is the NC-recommended size). NOTE: enabling
    #    rotation does NOT immediately clear existing "errors in log" — those
    #    persist until the file next rotates past this size or is truncated.
    _nc_set_system("log_rotate_size", "10485760", "integer")

    # 3. db:add-missing-indices — adds optional perf indices. Idempotent;
    #    no-op once all indices exist.
    step("nextcloud: db:add-missing-indices")
    r = _nc_occ(["db:add-missing-indices"], timeout=600)
    if r.returncode == 0:
        ok("db:add-missing-indices complete")
    else:
        err(f"db:add-missing-indices failed: {r.stderr.strip() or r.stdout.strip()}")

    # 4. notify_push (Client Push). Self-skips once configured, so it's safe
    #    in both the nightly `all` and the standalone run.
    _nc_setup_notify_push()

    # 5. Mimetype migrations via the expensive repair. Standalone-only.
    if expensive:
        step("nextcloud: maintenance:repair --include-expensive (mimetype migrations)")
        r = _nc_occ(["maintenance:repair", "--include-expensive"], timeout=1800)
        if r.returncode == 0:
            ok("maintenance:repair complete")
        else:
            err(f"maintenance:repair failed: {r.stderr.strip() or r.stdout.strip()}")
    else:
        ok("skipped expensive mimetype repair — run `maintain.py nextcloud` to apply")


# ── n8n helpers ───────────────────────────────────────────────────────────────

def _n8n_container_ip() -> str:
    for name in ("n8n", "stack-n8n-1"):
        r = subprocess.run(
            ["docker", "inspect", name,
             "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}\n{{end}}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            for ip in r.stdout.splitlines():
                ip = ip.strip()
                if ip and ip != "0.0.0.0":
                    return ip
    return ""


def _n8n_request(method: str, path: str, body: dict | None, key: str, ip: str) -> dict:
    url = f"http://{ip}:5678/api/v1{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"X-N8N-API-KEY": key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw.strip() else {}


_N8N_WORKFLOW_NAME = "Stack Health Alert"
_N8N_WEBHOOK_PATH  = "stack-health-alert"
_NTFY_URL          = "http://192.0.2.10:80/alerts"


def _ensure_n8n_alert_workflow(key: str, ip: str) -> str:
    """Idempotently create and activate the Stack Health Alert workflow. Returns webhook path."""
    workflows = _n8n_request("GET", "/workflows", None, key, ip)
    for w in workflows.get("data", []):
        if w.get("name") == _N8N_WORKFLOW_NAME:
            if not w.get("active"):
                try:
                    _n8n_request("POST", f"/workflows/{w['id']}/activate", None, key, ip)
                except Exception:
                    pass
            return _N8N_WEBHOOK_PATH

    workflow_def = {
        "name": _N8N_WORKFLOW_NAME,
        "active": True,
        "nodes": [
            {
                "name": "Trigger",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [240, 300],
                "id": str(uuid.uuid4()),
                "webhookId": str(uuid.uuid4()),
                "parameters": {
                    "httpMethod": "POST",
                    "path": _N8N_WEBHOOK_PATH,
                    "responseMode": "onReceived",
                    "options": {},
                },
            },
            {
                "name": "ntfy Alert",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [480, 300],
                "id": str(uuid.uuid4()),
                "parameters": {
                    "method": "POST",
                    "url": _NTFY_URL,
                    "sendHeaders": True,
                    "headerParameters": {
                        "parameters": [
                            {"name": "Title",    "value": "={{ $json.body.title }}"},
                            {"name": "Priority", "value": "={{ $json.body.priority }}"},
                            {"name": "Tags",     "value": "warning,server"},
                        ],
                    },
                    "sendBody": True,
                    "contentType": "raw",
                    "rawContentType": "text/plain",
                    "body": "={{ $json.body.message }}",
                },
            },
        ],
        "connections": {
            "Trigger": {
                "main": [[{"node": "ntfy Alert", "type": "main", "index": 0}]]
            }
        },
        "settings": {"executionOrder": "v1"},
    }
    created = _n8n_request("POST", "/workflows", workflow_def, key, ip)
    wf_id = created.get("id")
    if wf_id:
        try:
            _n8n_request("POST", f"/workflows/{wf_id}/activate", None, key, ip)
        except Exception:
            pass
    return _N8N_WEBHOOK_PATH


def _send_n8n_alert(ip: str, webhook_path: str, title: str, message: str, priority: str = "4") -> None:
    url = f"http://{ip}:5678/webhook/{webhook_path}"
    payload = json.dumps({"title": title, "message": message, "priority": priority}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15)


# ── dashy ─────────────────────────────────────────────────────────────────────

def cmd_dashy() -> None:
    """Regenerate the Dashy dashboard from live discovery; restart on change.

    Idempotent: only restarts dashy when the rendered conf.yml differs. Keeps
    the dashboard links current as subdomains change, without a full redeploy.
    """
    step("dashy-dashboard")
    import filecmp
    stack = _STACK_DIR
    dst = "/dock/conf/dashy/conf.yml"
    gen = stack / "scripts" / "gen-dashy-config.py"
    r = subprocess.run(
        ["python3", str(gen), "-o", dst + ".new",
         "--env", str(stack / ".env"),
         "--caddyfile", str(stack / "templates/caddy/Caddyfile")],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        err(f"gen-dashy-config failed: {r.stderr.strip() or r.stdout.strip()}")
        return
    if os.path.exists(dst) and filecmp.cmp(dst + ".new", dst, shallow=False):
        os.remove(dst + ".new")
        ok("dashy conf.yml already current")
        return
    shutil.move(dst + ".new", dst)
    ok("dashy conf.yml regenerated")
    subprocess.run(["docker", "restart", "dashy"], capture_output=True)


# ── manageability audit ─────────────────────────────────────────────────────

def cmd_manageability() -> int:
    """Audit end-to-end container manageability.

    For every container reports: healthcheck, autoheal label, mem_limit,
    restart policy, state — flagging long-running containers that lack a
    healthcheck/autoheal/mem_limit (one-shot containers, restart=no, are
    exempt). Then cross-checks that every Caddyfile-routed service has a
    running backend container. Returns the number of actionable gaps (0 = all
    green), so it's cron/CI-friendly.
    """
    step("manageability-audit")

    fmt = ('{{.Name}}|{{if .Config.Healthcheck}}Y{{else}}N{{end}}|'
           '{{index .Config.Labels "autoheal"}}|{{.HostConfig.Memory}}|'
           '{{.HostConfig.RestartPolicy.Name}}|{{.State.Status}}')
    ids = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True)
    if ids.returncode != 0:
        err("cannot list containers (docker unavailable)")
        return 1
    id_list = ids.stdout.split()
    if not id_list:
        ok("no containers found")
        return 0
    insp = subprocess.run(["docker", "inspect", "--format", fmt, *id_list],
                          capture_output=True, text=True)
    rows = []
    for line in insp.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 6:
            continue
        name, hc, ah, mem, restart, state = parts
        rows.append({"name": name.lstrip("/"), "hc": hc == "Y",
                     "autoheal": ah == "true", "mem": int(mem or 0),
                     "restart": restart, "state": state})

    # One-shot/init containers (restart policy "no") are exempt from
    # healthcheck/autoheal/mem expectations — they run once and exit.
    def oneshot(r): return r["restart"] in ("", "no")

    no_hc = [r["name"] for r in rows if not oneshot(r) and not r["hc"]]
    no_ah = [r["name"] for r in rows if not oneshot(r) and not r["autoheal"]]
    no_mem = [r["name"] for r in rows if not oneshot(r) and r["mem"] == 0]
    not_running = [r["name"] for r in rows
                   if not oneshot(r) and r["state"] != "running"]

    print(f"  containers: {len(rows)} total, "
          f"{sum(1 for r in rows if oneshot(r))} one-shot (exempt)")

    def report(label, items):
        if items:
            err(f"  {label} ({len(items)}): {', '.join(sorted(items))}")
        else:
            ok(f"  {label}: none")

    report("long-running without healthcheck", no_hc)
    report("long-running without autoheal=true", no_ah)
    report("long-running without mem_limit", no_mem)
    report("long-running not in 'running' state", not_running)

    # Cross-check: every Caddyfile-routed service has a running backend. The
    # upstream host is a docker DNS name = the compose *service* name (its
    # network alias), which may differ from the container_name (e.g. service
    # "janus" -> container "janus-gateway"). Resolve both, and strip any
    # scheme (https://grafana:3000 -> grafana).
    missing_backend = []
    try:
        sys.path.insert(0, str(_STACK_DIR / "scripts"))
        from utils_discovery import (  # noqa: E402
            load_env, parse_caddyfile, parse_compose_containers)
        env = load_env(_STACK_DIR / ".env")
        caddy = parse_caddyfile(_STACK_DIR / "templates/caddy/Caddyfile", env)
        svc_to_container, _ = parse_compose_containers(
            _STACK_DIR / "docker-compose.yml", _STACK_DIR / ".env")
        running_containers = {r["name"] for r in rows if r["state"] == "running"}
        running_services = {svc for svc, cont in svc_to_container.items()
                            if cont in running_containers}
        reachable = running_containers | running_services
        for sub, service in caddy["matchers"].items():
            upstream = caddy["backends"].get(service, service)
            host = upstream.split("://")[-1].split(":")[0].strip("/")
            if host and host not in reachable and service not in reachable:
                missing_backend.append(f"{sub}->{host}")
    except Exception as exc:  # discovery is best-effort
        err(f"  routed-service cross-check skipped: {exc}")
    report("routed services with no running backend", missing_backend)

    gaps = len(no_hc) + len(no_ah) + len(no_mem) + len(not_running) + len(missing_backend)
    if gaps == 0:
        ok(f"{ts()} manageability: all containers fully accounted for")
    else:
        err(f"{ts()} manageability: {gaps} gap(s) found")
    return gaps


# ── grafana ───────────────────────────────────────────────────────────────────

def cmd_versions() -> None:
    """Check every stack image for newer upstream releases and append a JSONL
    snapshot for Loki ingestion (Alloy tails /dock/conf/version-check)."""
    step("image-version-check")
    out = "/dock/conf/version-check/updates.jsonl"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    r = subprocess.run(
        ["python3", str(_STACK_DIR / "scripts" / "check-versions.py"),
         "--jsonl", out, "--quiet"],
        capture_output=True, text=True,
    )
    # Surface the concise summary the checker prints, regardless of rc.
    print(r.stdout.rstrip() or r.stderr.rstrip())
    if r.returncode != 0:
        err("check-versions.py exited non-zero")


def cmd_grafana() -> None:
    """Regenerate the Grafana Observability dashboards. Grafana auto-reloads
    provisioning every 30s, so no restart is needed."""
    step("grafana-dashboards")
    stack = _STACK_DIR
    prov = "/dock/conf/grafana/provisioning/dashboards/observability"
    os.makedirs(prov, exist_ok=True)
    r = subprocess.run(
        ["python3", str(stack / "scripts" / "gen-grafana-dashboards.py"), "-o", prov],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        err(f"gen-grafana-dashboards failed: {r.stderr.strip() or r.stdout.strip()}")
        return
    ok("grafana observability dashboards regenerated")


# ── entra-sync ────────────────────────────────────────────────────────────────

def cmd_entra_sync() -> None:
    step("entra-sync")
    scripts_dir = _STACK_DIR / "scripts"
    set_auth = str(scripts_dir / "set-auth.py")
    for argv, label in [
        ([set_auth, "entra-policies"], "set-auth entra-policies"),
        ([set_auth, "entra-sync"],     "set-auth entra-sync"),
        ([set_auth, "oidc", "--sync"], "set-auth oidc --sync"),
    ]:
        r = subprocess.run(
            [sys.executable, *argv],
            cwd=str(_STACK_DIR),
        )
        if r.returncode != 0:
            err(f"{label} exited {r.returncode}")
        else:
            ok(f"{ts()} {label} complete")


# ── check-stack ───────────────────────────────────────────────────────────────

def cmd_check_stack() -> None:
    step("check-stack")
    scripts_dir = _STACK_DIR / "scripts"
    r = subprocess.run(
        [sys.executable, str(scripts_dir / "check-stack.py"), "--no-color"],
        capture_output=True, text=True,
        cwd=str(_STACK_DIR),
    )
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)

    n_issues = 0
    for line in r.stdout.splitlines():
        m = re.search(r"(\d+)/\d+ service", line)
        if m:
            n_issues = int(m.group(1))
            break

    if n_issues == 0:
        ok(f"{ts()} all services healthy")
        return

    n8n_key = os.environ.get("N8N_API_KEY", "")
    if not n8n_key:
        err("N8N_API_KEY not set — skipping alert")
        return

    ip = _n8n_container_ip()
    if not ip:
        err("Cannot resolve n8n container IP — skipping alert")
        return

    try:
        webhook_path = _ensure_n8n_alert_workflow(n8n_key, ip)
        _send_n8n_alert(ip, webhook_path,
                        title="Stack Health Alert",
                        message=f"{n_issues} service(s) need attention — run check-stack.py for details",
                        priority="4")
        ok(f"{ts()} ntfy alert sent via n8n: {n_issues} issue(s)")
    except Exception as exc:
        err(f"Failed to send n8n alert: {exc}")


# ── dispatch ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified maintenance runner for the unified-stack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  backup       Dump all Postgres databases and prune old backups.\n"
            "  intel        Refresh Zeek threat-intel feeds.\n"
            "  prune        Remove dangling Docker images, unused volumes, and stale builder cache.\n"
            "  cloudflare       Poll Cloudflare security events and write to firewall-events.log.\n"
            "  cloudflare-hsts  PATCH the CF zone HSTS setting to a long policy (idempotent).\n"
            "  cloudflare-cidrs Refresh Cloudflare IP allowlist in .env and cf-cidrs.txt (fail-closed).\n"
            "  nextcloud        Clear NC admin-overview warnings (window, log rotate, indices, mimetypes).\n"
            "  dashy            Regenerate the Dashy dashboard from live discovery (idempotent).\n"
            "  grafana          Regenerate the Grafana Observability dashboards (idempotent).\n"
            "  manageability    Audit container healthcheck/autoheal/mem_limit + routed-backend coverage.\n"
            "  versions         Check images for newer upstream releases; log JSONL for Loki.\n"
            "  entra-sync       Sync Entra group membership into Authentik (set-auth entra-* + oidc --sync).\n"
            "  check-stack      Probe all services; send ntfy alert via n8n if any are unhealthy.\n"
            "  all              Run backup → intel → prune → cloudflare-hsts → nextcloud → dashy → grafana → manageability → versions → entra-sync → check-stack."
        ),
    )
    parser.add_argument(
        "command",
        choices=["backup", "intel", "prune", "cloudflare", "cloudflare-hsts",
                 "cloudflare-cidrs", "nextcloud", "dashy", "grafana", "manageability",
                 "versions", "entra-sync", "check-stack", "all"],
    )
    args = parser.parse_args()

    dispatch = {
        "backup":           cmd_backup,
        "intel":            cmd_intel,
        "prune":            cmd_prune,
        "cloudflare":       cmd_cloudflare,
        "cloudflare-hsts":  cmd_cloudflare_hsts,
        "cloudflare-cidrs": cmd_cloudflare_cidrs,
        "nextcloud":        cmd_nextcloud,
        "dashy":            cmd_dashy,
        "grafana":          cmd_grafana,
        "manageability":    cmd_manageability,
        "versions":         cmd_versions,
        "entra-sync":       cmd_entra_sync,
        "check-stack":      cmd_check_stack,
    }
    if args.command == "all":
        cmd_backup(); cmd_intel(); cmd_prune()
        cmd_cloudflare_hsts()
        # expensive=False: never run the slow mimetype repair in the nightly
        # window — it can take hours on large instances. Run `maintain.py
        # nextcloud` standalone for that.
        cmd_nextcloud(expensive=False)
        cmd_dashy()
        cmd_grafana()
        cmd_manageability()
        cmd_versions()
        cmd_entra_sync(); cmd_check_stack()
    else:
        dispatch[args.command]()


if __name__ == "__main__":
    main()
