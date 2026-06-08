#!/usr/bin/env python3
"""
maintain.py — Unified maintenance runner for the unified-stack.

Subcommands:
  backup       Dump all Postgres databases and prune old backups.
  intel        Refresh Zeek threat-intel feeds (URLhaus, Feodo, CrowdStrike).
  wazuh        Sync custom Wazuh decoders/rules and merge agent localfiles.
  prune        Remove dangling Docker images, unused volumes, and stale builder cache.
  cloudflare   Poll Cloudflare security events API and write to firewall-events.log.
  entra-sync   Sync Entra group membership into Authentik (set-auth entra-* + oidc --sync).
  check-stack  Probe all services; send ntfy alert via n8n if any are unhealthy.
  all          Run backup → intel → wazuh → prune → entra-sync → check-stack.

Usage:
  python3 scripts/maintain.py <backup|intel|wazuh|prune|cloudflare|all>

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

_WAZUH_CONTAINER = "wazuh-manager"
_WAZUH_API       = "https://localhost:55000"
_WAZUH_API_USER  = "wazuh-wui"

_CF_API_BASE = "https://api.cloudflare.com/client/v4"
_CF_STATE    = Path("/dock/conf/cloudflare/state.json")
_CF_LOG      = Path("/dock/conf/cloudflare/firewall-events.log")

_CF_GRAPHQL_QUERY = """\
query ($zoneTag: String!, $datetimeGt: String!, $datetimeLt: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_gt: $datetimeGt, datetime_lt: $datetimeLt}
        limit: 1000
        orderBy: [datetime_ASC]
      ) {
        action
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        datetime
        rayName
        ruleId
        source
        userAgent
      }
    }
  }
}
"""


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


# ── Cloudflare API helpers ────────────────────────────────────────────────────

def _cf_api_get(token: str, path: str) -> dict:
    """GET from CF REST API with one retry on 429/5xx."""
    url = f"{_CF_API_BASE}{path}"
    for attempt in range(2):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in (429, 500, 502, 503, 504):
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")


def _cf_api_patch(token: str, path: str, body: dict) -> dict:
    """PATCH to CF REST API with one retry on 429/5xx."""
    url = f"{_CF_API_BASE}{path}"
    payload = json.dumps(body).encode()
    for attempt in range(2):
        req = urllib.request.Request(
            url, data=payload, method="PATCH",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in (429, 500, 502, 503, 504):
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")


def _cf_graphql(token: str, variables: dict) -> dict:
    """POST to CF GraphQL API with one retry on 429/5xx."""
    url = f"{_CF_API_BASE}/graphql"
    payload = json.dumps({"query": _CF_GRAPHQL_QUERY, "variables": variables}).encode()
    for attempt in range(2):
        req = urllib.request.Request(
            url, data=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if attempt == 0 and exc.code in (429, 500, 502, 503, 504):
                time.sleep(5)
                continue
            raise
    raise RuntimeError("unreachable")


def _cf_resolve_zone(token: str, domain: str) -> str:
    """Return zone ID for the apex domain."""
    apex = ".".join(domain.split(".")[-2:])
    data = _cf_api_get(token, f"/zones?name={apex}")
    zones = data.get("result", [])
    if not zones:
        raise ValueError(f"No Cloudflare zone found for {apex!r}")
    return zones[0]["id"]


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


# ── wazuh ─────────────────────────────────────────────────────────────────────

def _sync_dir(src: Path, dst: Path, pattern: str = "*.xml") -> bool:
    """Copy src files matching pattern to dst. Return True if changed.

    Tries root:wazuh 640 (host-agent case); falls back to 644 if wazuh group
    doesn't exist (container case — wazuh-manager reads bind-mounts as root).
    """
    dst.mkdir(parents=True, exist_ok=True)
    src_files = {f.name: f for f in src.glob(pattern)}

    changed = False
    for name, sf in src_files.items():
        df = dst / name
        if not df.exists() or sf.read_bytes() != df.read_bytes():
            shutil.copy2(str(sf), str(df))
            try:
                shutil.chown(str(df), user="root", group="wazuh")
                df.chmod(0o640)
            except LookupError:
                df.chmod(0o644)
            changed = True

    return changed


def _extract_ossec_body(conf_path: Path) -> str:
    """Return the lines between <ossec_config> and </ossec_config>, exclusive."""
    lines = conf_path.read_text(encoding="utf-8").splitlines(keepends=True)
    body, inside = [], False
    for line in lines:
        if "<ossec_config>" in line:
            inside = True
            continue
        if "</ossec_config>" in line:
            break
        if inside:
            body.append(line)
    return "".join(body)


def _merge_ossec_conf(ossec_conf: Path, insert_block: str) -> None:
    """Insert insert_block with sentinel comments before the closing </ossec_config>."""
    lines = ossec_conf.read_text(encoding="utf-8").splitlines(keepends=True)

    close_idx = next(
        (i for i in range(len(lines) - 1, -1, -1) if "</ossec_config>" in lines[i]),
        None,
    )
    if close_idx is None:
        raise ValueError(f"No </ossec_config> tag found in {ossec_conf}")

    block = insert_block if insert_block.endswith("\n") else insert_block + "\n"
    new_lines = (
        lines[:close_idx]
        + ["<!-- BEGIN unified-stack localfiles -->\n", block, "<!-- END unified-stack localfiles -->\n"]
        + lines[close_idx:]
    )

    tmp = ossec_conf.with_suffix(".new")
    tmp.write_text("".join(new_lines), encoding="utf-8")
    shutil.chown(str(tmp), user="root", group="wazuh")
    tmp.chmod(0o640)
    tmp.replace(ossec_conf)


def _docker_cp_xmls(src_dir: Path, container_dst: str) -> bool:
    """docker cp all XML files from src_dir into the container. Returns True if any changed."""
    changed = False
    for xml in src_dir.glob("*.xml"):
        r = subprocess.run(
            ["docker", "exec", _WAZUH_CONTAINER, "cat", f"{container_dst}/{xml.name}"],
            capture_output=True,
        )
        if r.returncode == 0 and r.stdout == xml.read_bytes():
            continue
        subprocess.run(
            ["docker", "cp", str(xml), f"{_WAZUH_CONTAINER}:{container_dst}/{xml.name}"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["docker", "exec", _WAZUH_CONTAINER,
             "chown", "root:wazuh", f"{container_dst}/{xml.name}"],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["docker", "exec", _WAZUH_CONTAINER,
             "chmod", "640", f"{container_dst}/{xml.name}"],
            capture_output=True, check=True,
        )
        changed = True
    return changed


def _wazuh_container_state() -> str | None:
    r = subprocess.run(
        ["docker", "inspect", _WAZUH_CONTAINER, "--format", "{{.State.Status}}"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def _wazuh_api_ready() -> bool:
    r = subprocess.run(
        ["docker", "exec", _WAZUH_CONTAINER,
         "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
         f"{_WAZUH_API}/"],
        capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() in ("200", "401", "403")


def _wazuh_wait_api(timeout: int = 120) -> None:
    """Block until the Wazuh REST API responds, e.g. after a container restart."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _wazuh_api_ready():
            return
        time.sleep(5)
    err(f"Wazuh API not ready after {timeout}s — is wazuh-manager healthy?")
    sys.exit(1)


def _wazuh_token(password: str) -> str:
    r = subprocess.run(
        ["docker", "exec", _WAZUH_CONTAINER,
         "curl", "-sk", "-X", "GET",
         "-u", f"{_WAZUH_API_USER}:{password}",
         f"{_WAZUH_API}/security/user/authenticate"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(r.stdout)["data"]["token"]


def _wazuh_restart(token: str) -> None:
    subprocess.run(
        ["docker", "exec", _WAZUH_CONTAINER,
         "curl", "-sk", "-X", "PUT",
         "-H", f"Authorization: Bearer {token}",
         f"{_WAZUH_API}/manager/restart"],
        capture_output=True, check=True,
    )


def _wazuh_merge_ossec_container(block: str) -> bool:
    """Merge localfile block into ossec.conf inside the container. Returns True if changed.

    If the sentinel is already present, replaces the existing block so that
    updates to agent-host.conf are picked up on re-runs.
    """
    snippet = f"""\
import re, shutil
from pathlib import Path
start_s = "<!-- BEGIN unified-stack localfiles -->"
end_s   = "<!-- END unified-stack localfiles -->"
block   = {json.dumps(block)}
conf    = Path("/var/ossec/etc/ossec.conf")
text    = conf.read_text()
if start_s in text:
    new = re.sub(
        re.escape(start_s) + r".*?" + re.escape(end_s),
        start_s + "\\n" + block + "\\n" + end_s,
        text, flags=re.DOTALL)
    if new == text:
        print("SKIP"); exit(0)
else:
    idx = text.rfind("</ossec_config>")
    if idx == -1:
        print("ERROR: no </ossec_config>"); exit(1)
    new = text[:idx] + start_s + "\\n" + block + "\\n" + end_s + "\\n" + text[idx:]
tmp = conf.with_suffix(".new")
tmp.write_text(new)
shutil.chown(str(tmp), user="root", group="wazuh")
tmp.chmod(0o640)
tmp.replace(conf)
print("OK")
"""
    r = subprocess.run(
        ["docker", "exec", _WAZUH_CONTAINER, "python3", "-c", snippet],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or r.stdout.strip().startswith("ERROR"):
        err(r.stdout + r.stderr)
        sys.exit(1)
    return r.stdout.strip() == "OK"


def cmd_wazuh() -> None:
    step("wazuh-ingest")

    # ── Containerized manager path ─────────────────────────────────────────────
    if _wazuh_container_state() == "running":
        password = os.environ.get("WAZUH_API_PASSWORD", "")
        if not password:
            err("WAZUH_API_PASSWORD not set — cannot authenticate to Wazuh API")
            sys.exit(1)

        changed = False
        tpl_dir  = _STACK_DIR / "templates" / "wazuh"
        conf_dir = Path("/dock/conf/wazuh")

        for subdir in ("decoders", "rules"):
            if _docker_cp_xmls(tpl_dir / subdir, f"/var/ossec/etc/{subdir}"):
                ok(f"synced {subdir}")
                changed = True
            else:
                ok(f"no change: {subdir}")

        block = _extract_ossec_body(conf_dir / "agent-host.conf")
        if _wazuh_merge_ossec_container(block):
            ok("merged localfile block into ossec.conf")
            changed = True
        else:
            ok("no change: ossec.conf")

        if changed:
            _wazuh_wait_api()
            token = _wazuh_token(password)
            _wazuh_restart(token)
            ok("wazuh-manager restarted via API")
        else:
            ok("no changes — skipping restart")
        return

    # ── Host-agent path ────────────────────────────────────────────────────────
    src_dir       = Path("/dock/conf/wazuh")
    agent_etc     = Path("/var/ossec/etc")
    ossec_conf    = agent_etc / "ossec.conf"
    wazuh_control = Path("/var/ossec/bin/wazuh-control")

    if not wazuh_control.is_file():
        err(f"{_WAZUH_CONTAINER} container not running and {wazuh_control} not found.")
        sys.exit(1)

    changed = False

    for subdir in ("decoders", "rules"):
        if _sync_dir(src_dir / subdir, agent_etc / subdir):
            ok(f"synced {subdir}")
            changed = True
        else:
            ok(f"no change: {subdir}")

    conf_text = ossec_conf.read_text(encoding="utf-8") if ossec_conf.exists() else ""
    if "unified-stack localfiles" not in conf_text:
        body = _extract_ossec_body(src_dir / "agent-host.conf")
        _merge_ossec_conf(ossec_conf, body)
        ok("merged agent-host.conf localfiles into ossec.conf")
        changed = True

    if changed:
        subprocess.run(["systemctl", "restart", "wazuh-agent"], check=True)
        ok("wazuh-agent restarted with updated decoders/rules/localfiles")
    else:
        ok("no wazuh-agent changes")


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

    # Load state
    state: dict = {}
    if _CF_STATE.exists():
        try:
            state = json.loads(_CF_STATE.read_text())
        except (json.JSONDecodeError, OSError):
            err(f"WARNING: {_CF_STATE} unparseable — starting from last 15 minutes")

    # Resolve zone ID (cached; re-resolved on 404)
    zone_id: str = state.get("zone_id", "")
    if zone_id:
        try:
            _cf_api_get(token, f"/zones/{zone_id}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                err(f"Cached zone ID {zone_id!r} is invalid — re-resolving")
                zone_id = ""
    if not zone_id:
        zone_id = _cf_resolve_zone(token, fqdn)
        state["zone_id"] = zone_id
        ok(f"resolved zone ID: {zone_id}")

    # Cursor — cap lookback at 23h to stay within firewallEventsAdaptive's 1d limit
    _utcnow  = datetime.datetime.now(datetime.timezone.utc)
    now_str  = _utcnow.strftime("%Y-%m-%dT%H:%M:%SZ")
    max_back = (_utcnow - datetime.timedelta(hours=23)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fallback = (_utcnow - datetime.timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_last: str = state.get("last_seen") or fallback
    last_seen = raw_last if raw_last >= max_back else max_back
    if not state.get("last_seen"):
        err(f"WARNING: no last_seen in state — fetching from {last_seen}")
    elif last_seen != raw_last:
        err(f"WARNING: last_seen {raw_last!r} > 23h ago — clamped to {last_seen}")

    # Query GraphQL
    try:
        result = _cf_graphql(token, {"zoneTag": zone_id, "datetimeGt": last_seen, "datetimeLt": now_str})
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        err(f"CF API error after retry: {exc} — cursor not advanced")
        return

    if result.get("errors"):
        err(f"CF GraphQL errors: {result['errors']} — cursor not advanced")
        return

    data = result.get("data")
    if data is None:
        err(f"CF GraphQL returned null data — cursor not advanced")
        return

    events = (data.get("viewer", {})
              .get("zones", [{}])[0].get("firewallEventsAdaptive", []))

    # Write log + heartbeat; action first so prematch ^{"action": fires on all lines
    _CF_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _CF_LOG.open("a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
        f.write(json.dumps({
            "action": "heartbeat",
            "datetime": now_str,
            "type": "heartbeat",
            "events_fetched": len(events),
        }) + "\n")

    # Advance cursor
    new_cursor = events[-1]["datetime"] if events else now_str
    state["last_seen"] = new_cursor
    _CF_STATE.parent.mkdir(parents=True, exist_ok=True)
    _CF_STATE.write_text(json.dumps(state, indent=2))

    ok(f"fetched {len(events)} events; cursor → {new_cursor}")


# Cloudflare rewrites the origin's Strict-Transport-Security header at edge,
# overriding whatever Caddy sends. The dashboard control lives under SSL/TLS →
# Edge Certificates → HSTS; this subcommand sets the same fields via API so
# fresh hosts get a long HSTS policy without manual dashboard clicks.
# Target values mirror what Caddy's security-headers snippet sends so the
# observable header is the same whether a request goes via CF or origin-direct.
# CF caps max_age at 31536000s (1y); that still satisfies Nextcloud's
# setupcheck threshold of 15552000s (6 mo). These are exactly the fields
# CF echoes back in GET .../settings/security_header, so the idempotency
# comparison below matches cleanly (an earlier draft included a phantom
# "nodefault" key CF never returns, which forced a PATCH on every run).
_HSTS_TARGET = {
    "enabled":            True,
    "max_age":            31536000,
    "include_subdomains": True,
    "preload":            True,
}


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

    zone_id = _cf_resolve_zone(token, fqdn)

    # GET current — only PATCH if values differ. Avoids audit-log churn on
    # every deploy and gives a clean "already configured" report when correct.
    try:
        current = _cf_api_get(token, f"/zones/{zone_id}/settings/security_header")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            err("CF API returned 403 on /zones/.../settings/security_header.")
            err("The CLOUDFLARE_API_TOKEN is missing `Zone.Zone Settings:Edit`.")
            err("Add that permission scope to the token (dashboard → My Profile")
            err("→ API Tokens → edit) and re-run this command.")
            return
        raise
    sts = (current.get("result", {})
                  .get("value", {})
                  .get("strict_transport_security", {}) or {})
    if all(sts.get(k) == v for k, v in _HSTS_TARGET.items()):
        ok(f"HSTS already at target: max_age={sts.get('max_age')} "
           f"include_subdomains={sts.get('include_subdomains')} "
           f"preload={sts.get('preload')}")
        return

    resp = _cf_api_patch(token, f"/zones/{zone_id}/settings/security_header", {
        "value": {"strict_transport_security": _HSTS_TARGET},
    })
    if not resp.get("success"):
        errors = resp.get("errors") or resp
        err(f"CF HSTS PATCH failed: {errors}")
        sys.exit(1)
    new_sts = resp.get("result", {}).get("value", {}).get("strict_transport_security", {})
    ok(f"HSTS updated: max_age={new_sts.get('max_age')} "
       f"include_subdomains={new_sts.get('include_subdomains')} "
       f"preload={new_sts.get('preload')}")


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
    # scheme (https://wazuh-dashboard:5601 -> wazuh-dashboard).
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
            "  wazuh        Sync Wazuh decoders/rules and merge agent localfiles.\n"
            "  prune        Remove dangling Docker images, unused volumes, and stale builder cache.\n"
            "  cloudflare       Poll Cloudflare security events and write to firewall-events.log.\n"
            "  cloudflare-hsts  PATCH the CF zone HSTS setting to a long policy (idempotent).\n"
            "  nextcloud        Clear NC admin-overview warnings (window, log rotate, indices, mimetypes).\n"
            "  dashy            Regenerate the Dashy dashboard from live discovery (idempotent).\n"
            "  grafana          Regenerate the Grafana Observability dashboards (idempotent).\n"
            "  manageability    Audit container healthcheck/autoheal/mem_limit + routed-backend coverage.\n"
            "  versions         Check images for newer upstream releases; log JSONL for Loki.\n"
            "  entra-sync       Sync Entra group membership into Authentik (set-auth entra-* + oidc --sync).\n"
            "  check-stack      Probe all services; send ntfy alert via n8n if any are unhealthy.\n"
            "  all              Run backup → intel → wazuh → prune → cloudflare-hsts → nextcloud → dashy → grafana → manageability → versions → entra-sync → check-stack."
        ),
    )
    parser.add_argument(
        "command",
        choices=["backup", "intel", "wazuh", "prune", "cloudflare", "cloudflare-hsts",
                 "nextcloud", "dashy", "grafana", "manageability", "versions",
                 "entra-sync", "check-stack", "all"],
    )
    args = parser.parse_args()

    dispatch = {
        "backup":           cmd_backup,
        "intel":            cmd_intel,
        "wazuh":            cmd_wazuh,
        "prune":            cmd_prune,
        "cloudflare":       cmd_cloudflare,
        "cloudflare-hsts":  cmd_cloudflare_hsts,
        "nextcloud":        cmd_nextcloud,
        "dashy":            cmd_dashy,
        "grafana":          cmd_grafana,
        "manageability":    cmd_manageability,
        "versions":         cmd_versions,
        "entra-sync":       cmd_entra_sync,
        "check-stack":      cmd_check_stack,
    }
    if args.command == "all":
        cmd_backup(); cmd_intel(); cmd_wazuh(); cmd_prune()
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
