#!/usr/bin/env python3
"""
maintain.py — Unified maintenance runner for the unified-stack.

Subcommands:
  backup   Dump all Postgres databases and prune old backups.
  intel    Refresh Zeek threat-intel feeds (URLhaus, Feodo, CrowdStrike).
  wazuh    Sync custom Wazuh decoders/rules and merge agent localfiles.
  all      Run backup → intel → wazuh in sequence.

Usage:
  python3 scripts/maintain.py <backup|intel|wazuh|all>

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
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# scripts/photonos/ is two levels below the repo root.
_STACK_DIR = Path(__file__).resolve().parent.parent.parent


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
    """Copy src files matching pattern to dst at root:wazuh 640. Return True if changed."""
    dst.mkdir(parents=True, exist_ok=True)
    src_files = {f.name: f for f in src.glob(pattern)}

    changed = False
    for name, sf in src_files.items():
        df = dst / name
        if not df.exists() or sf.read_bytes() != df.read_bytes():
            shutil.copy2(str(sf), str(df))
            shutil.chown(str(df), user="root", group="wazuh")
            df.chmod(0o640)
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


def cmd_wazuh() -> None:
    step("wazuh-agent-ingest")

    src_dir   = Path("/dock/conf/wazuh")
    agent_etc = Path("/var/ossec/etc")
    ossec_conf    = agent_etc / "ossec.conf"
    wazuh_control = Path("/var/ossec/bin/wazuh-control")

    if not wazuh_control.is_file():
        err(f"{wazuh_control} not found. Install wazuh-agent first.")
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


# ── dispatch ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified maintenance runner for the unified-stack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  backup   Dump all Postgres databases and prune old backups.\n"
            "  intel    Refresh Zeek threat-intel feeds.\n"
            "  wazuh    Sync Wazuh decoders/rules and merge agent localfiles.\n"
            "  all      Run backup → intel → wazuh in sequence."
        ),
    )
    parser.add_argument("command", choices=["backup", "intel", "wazuh", "all"])
    args = parser.parse_args()

    dispatch = {
        "backup": cmd_backup,
        "intel":  cmd_intel,
        "wazuh":  cmd_wazuh,
    }
    if args.command == "all":
        for fn in dispatch.values():
            fn()
    else:
        dispatch[args.command]()


if __name__ == "__main__":
    main()
