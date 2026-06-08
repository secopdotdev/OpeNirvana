#!/usr/bin/env python3
"""check-versions.py — monitor every stack image for newer upstream releases.

For each service it reads the *currently deployed* version (from the running
container's image tag / OCI version label) and the *latest* upstream version
(GitHub Releases API, or Docker Hub tags), then reports which images have an
update available.

Sources use the upstream **GitHub repo** or **Docker Hub repo** (never the
service's own public domain) so checks keep working through subdomain changes.

Outputs:
  - human: a concise table to stdout (used by run.sh / on-demand)
  - --jsonl PATH: append one JSON object per service to a log file, for
    ingestion into Loki (Alloy tails it; see templates/alloy/config.alloy) and
    the Grafana "Image updates available" table.

GitHub API is rate-limited to 60 req/h unauthenticated; set GITHUB_TOKEN in
.env to raise it to 5000/h (the registry has ~45 entries).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

_STACK = Path(__file__).resolve().parent.parent
_DEFAULT_MANIFEST = _STACK / "images-manifest.toml"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}$")

# ── Service registry ─────────────────────────────────────────────────────────
# service: container name (for current-version lookup) is the key.
#   gh   = "owner/repo" → latest non-prerelease GitHub release tag
#   hub  = "namespace/repo" → newest semver Docker Hub tag (when no GH releases)
#   note = repo reference shown in output
# Pure data — add a row when a service is added; no per-service logic.
REGISTRY: dict[str, dict] = {
    "tailscale-ingress": {"gh": "tailscale/tailscale"},
    "crowdsec":          {"gh": "crowdsecurity/crowdsec"},
    "socket-proxy-rw":   {"gh": "Tecnativa/docker-socket-proxy"},
    "autoheal":          {"gh": "willfarrell/docker-autoheal"},
    "postgres":          {"gh": "pgvector/pgvector"},
    "redis":             {"hub": "library/redis"},
    "wazuh-manager":     {"gh": "wazuh/wazuh"},
    "wazuh-dashboard":   {"gh": "wazuh/wazuh"},
    "falco":             {"gh": "falcosecurity/falco"},
    "zeek":              {"gh": "zeek/zeek"},
    "authentik-server":  {"gh": "goauthentik/authentik"},
    "nextcloud":         {"gh": "nextcloud/server"},
    "coturn":            {"gh": "coturn/coturn"},
    "spreed-signaling":  {"gh": "strukturag/nextcloud-spreed-signaling"},
    "janus":             {"gh": "meetecho/janus-gateway"},
    "gluetun":           {"gh": "qdm12/gluetun"},
    "prowlarr":          {"gh": "Prowlarr/Prowlarr"},
    "radarr":            {"gh": "Radarr/Radarr"},
    "sonarr":            {"gh": "Sonarr/Sonarr"},
    "lidarr":            {"gh": "Lidarr/Lidarr"},
    "flaresolverr":      {"gh": "FlareSolverr/FlareSolverr"},
    "qbittorrent":       {"gh": "qbittorrent/qBittorrent"},
    "jellyfin":          {"gh": "jellyfin/jellyfin"},
    "jellyseerr":        {"gh": "fallenbagel/jellyseerr"},
    "ntfy":              {"gh": "binwiederhier/ntfy"},
    "tandoor":           {"gh": "TandoorRecipes/recipes"},
    "vikunja":           {"gh": "go-vikunja/vikunja"},
    "affine":            {"gh": "toeverything/AFFiNE"},
    "dockhand":          {"gh": "fnbox-dev/dockhand"},
    "falcosidekick":     {"gh": "falcosecurity/falcosidekick"},
    "falcosidekick-ui":  {"gh": "falcosecurity/falcosidekick-ui"},
    "redis-falco":       {"gh": "redis-stack/redis-stack"},
    "zeek-logs":         {"gh": "filebrowser/filebrowser"},
    "redpanda":          {"gh": "redpanda-data/redpanda"},
    "redpanda-console":  {"gh": "redpanda-data/console"},
    "immich-server":     {"gh": "immich-app/immich"},
    "n8n":               {"gh": "n8n-io/n8n"},
    "dashy":             {"gh": "Lissy93/dashy"},
    "grafana":           {"gh": "grafana/grafana"},
    "prometheus":        {"gh": "prometheus/prometheus"},
    "cadvisor":          {"gh": "google/cadvisor"},
    "node-exporter":     {"gh": "prometheus/node_exporter"},
    "postgres-exporter": {"gh": "prometheus-community/postgres_exporter"},
    "redis-exporter":    {"gh": "oliver006/redis_exporter"},
    "alertmanager":      {"gh": "prometheus/alertmanager"},
    "loki":              {"gh": "grafana/loki"},
    "alloy":             {"gh": "grafana/alloy"},
}

_SEMVER = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _norm(v: str) -> str:
    """Strip common prefixes/suffixes: v, version/, refs/tags/, -ls/-alpine/-ubu."""
    v = v.strip()
    v = re.sub(r"^refs/tags/", "", v)
    v = re.sub(r"^version/", "", v)
    v = v.lstrip("vV")
    v = re.split(r"[-_+~]", v, maxsplit=1)[0]   # drop -ls30, -alpine, -r3, etc.
    return v


def _semver_tuple(v: str):
    m = _SEMVER.search(v)
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())


def _docker(args: list[str], timeout: int = 15) -> str:
    r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else ""


def current_version(container: str) -> str:
    """Best current version for a running container: a semver tag, else the
    OCI version label, else the raw tag."""
    image = _docker(["inspect", "-f", "{{.Config.Image}}", container])
    label = _docker(["inspect", "-f",
                     '{{index .Config.Labels "org.opencontainers.image.version"}}', container])
    tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
    if tag and _semver_tuple(tag):
        return tag
    if label and _semver_tuple(label):
        return label
    return tag or label or "?"


def _get_json(url: str, token: str | None = None) -> dict | list | None:
    headers = {"Accept": "application/json", "User-Agent": "your-org-version-check"}
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None


def _clean_tag(v: str) -> str:
    """Drop a leading path segment some projects use in tags
    (e.g. 'version/2026.5.0' -> '2026.5.0', 'docker/4.11.0-r0' -> '4.11.0-r0')."""
    return v.split("/", 1)[1] if "/" in v and _semver_tuple(v.split("/", 1)[1]) else v


def latest_version(spec: dict, token: str | None) -> str | None:
    if "gh" in spec:
        data = _get_json(f"https://api.github.com/repos/{spec['gh']}/releases/latest", token)
        if isinstance(data, dict) and data.get("tag_name"):
            return _clean_tag(data["tag_name"])
        # Fall back to tags when a repo publishes no GitHub "releases".
        tags = _get_json(f"https://api.github.com/repos/{spec['gh']}/tags?per_page=50", token)
        if isinstance(tags, list):
            sv = [t["name"] for t in tags if _semver_tuple(_norm(t.get("name", "")))]
            if sv:
                return max(sv, key=lambda t: _semver_tuple(_norm(t)) or (0,))
    if "hub" in spec:
        data = _get_json(
            f"https://hub.docker.com/v2/repositories/{spec['hub']}/tags?page_size=100")
        if isinstance(data, dict):
            names = [t["name"] for t in data.get("results", [])
                     if _semver_tuple(_norm(t.get("name", "")))]
            if names:
                return max(names, key=lambda t: _semver_tuple(_norm(t)) or (0,))
    return None


def check(token: str | None) -> list[dict]:
    results = []
    for container, spec in REGISTRY.items():
        cur = current_version(container)
        latest = latest_version(spec, token)
        cur_t, lat_t = _semver_tuple(_norm(cur)), _semver_tuple(_norm(latest or ""))
        update = bool(cur_t and lat_t and lat_t > cur_t)
        results.append({
            "service": container,
            "repo": spec.get("gh") or spec.get("hub"),
            "current": cur,
            "latest": latest or "?",
            "update_available": update,
        })
    return results


def _deployed_repo_digest(container: str) -> str | None:
    """The manifest digest a running container was pulled by (from RepoDigests),
    comparable to the index digest pinned in images-manifest.toml. None if the
    container is absent or has no repo digest (e.g. built locally)."""
    out = _docker(["inspect", "-f", "{{range .RepoDigests}}{{println .}}{{end}}", container])
    for line in out.splitlines():
        if "@sha256:" in line:
            return "sha256:" + line.split("@sha256:", 1)[1].strip()
    return None


def verify_pins(manifest_path: Path | None = None) -> int:
    """Gate half of the supply-chain control (Rec 6). Loads the digest-pin manifest
    and (1) validates every digest is well-formed offline, then (2) where the
    container is running, asserts the deployed image digest matches the pin.

    Exit non-zero only on a MALFORMED pin or a real DRIFT — absent containers are
    skipped (so this is safe to run in CI / on a dev box with nothing deployed)."""
    manifest_path = manifest_path or _DEFAULT_MANIFEST
    if not manifest_path.exists():
        print(f"  no manifest at {manifest_path} — nothing to verify")
        return 0
    with open(manifest_path, "rb") as f:
        data = tomllib.load(f)
    images = data.get("image", [])

    malformed = [i for i in images if not _SHA256.fullmatch(i.get("digest", ""))]
    for i in malformed:
        print(f"  MALFORMED digest for {i.get('ref', '?')}: {i.get('digest', '')!r}")
    if malformed:
        print(f"  verify-pins: {len(malformed)} malformed pin(s) — fix images-manifest.toml")
        return 1

    drift = checked = skipped = 0
    for i in images:
        svc, pin, ref = i["service"], i["digest"], i.get("ref", i["service"])
        deployed = _deployed_repo_digest(svc)
        if deployed is None:
            skipped += 1
            continue
        checked += 1
        if deployed != pin:
            print(f"  DRIFT: {svc} ({ref}) deployed {deployed} != pinned {pin}")
            drift += 1
    print(f"  verify-pins: {len(images)} pinned, {checked} live-checked, "
          f"{drift} drift, {skipped} not-running")
    return 1 if drift else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Check stack images for newer upstream versions")
    ap.add_argument("--jsonl", help="Append one JSON line per service to this file (for Loki)")
    ap.add_argument("--quiet", action="store_true", help="Only print the updates summary")
    ap.add_argument("--verify-pins", action="store_true",
                    help="Verify deployed image digests match images-manifest.toml (Rec 6 gate)")
    args = ap.parse_args()

    if args.verify_pins:
        return verify_pins()

    # Load GITHUB_TOKEN from .env if present (raises the API rate limit).
    token = os.environ.get("GITHUB_TOKEN")
    env_file = _STACK / ".env"
    if not token and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("GITHUB_TOKEN="):
                token = line.split("=", 1)[1].split("#")[0].strip().strip('"').strip("'") or None
                break

    results = check(token)
    updates = [r for r in results if r["update_available"]]

    if args.jsonl:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        Path(args.jsonl).parent.mkdir(parents=True, exist_ok=True)
        with open(args.jsonl, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps({**r, "ts": ts}) + "\n")

    if updates:
        print(f"\n  {len(updates)} image(s) with updates available:")
        w = max(len(r["service"]) for r in updates)
        for r in sorted(updates, key=lambda x: x["service"]):
            print(f"    {r['service']:<{w}}  {r['current']:>14}  →  {r['latest']:<14}  ({r['repo']})")
    else:
        print("  All images up to date (or latest could not be determined).")
    if not args.quiet:
        unknown = [r["service"] for r in results if r["latest"] == "?"]
        if unknown:
            print(f"  (latest unknown for {len(unknown)}: {', '.join(unknown)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
