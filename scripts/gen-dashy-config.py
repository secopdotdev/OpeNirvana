#!/usr/bin/env python3
"""gen-dashy-config.py — generate Dashy conf.yml from live discovery.

Tile URLs are derived from the Caddyfile routes + .env subdomains (never
stale). An ENRICHMENT table (keyed by the Caddyfile *backend* name) adds
polished icon/description/category; routed services not in it auto-appear
with sensible defaults. Non-UI routes are marked hidden. Emits the config as
JSON — which is valid YAML (YAML is a JSON superset, and Dashy's parser
accepts it) — so there are no hand-emitted-YAML escaping bugs, and the
generator needs only the stdlib.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from utils_discovery import load_env, parse_caddyfile

_STACK = Path(__file__).resolve().parent.parent

# Descriptive data (NOT routing logic), keyed by the Caddyfile backend/service
# name as returned by parse_caddyfile (e.g. `falco`, `authentik`, not the
# container names `falcosidekick-ui`, `authentik-server`).
ENRICHMENT: dict[str, dict] = {
    # Security
    "wazuh":            {"title": "Wazuh SIEM", "icon": "hl-wazuh", "category": "Security",
                         "description": "SIEM · threat detection · log analysis"},
    "crowdsec":         {"title": "CrowdSec", "icon": "hl-crowdsec", "category": "Security",
                         "description": "Community IPS · Caddy bouncer"},
    "falco":            {"title": "Falco", "icon": "hl-falco", "category": "Security",
                         "description": "Runtime syscall · container security"},
    "zeek":             {"title": "Zeek", "icon": "hl-zeek", "category": "Security",
                         "description": "Network security monitor · logs"},
    "redpanda-console": {"title": "Kafka / Redpanda", "icon": "hl-redpanda", "category": "Security",
                         "description": "Event streaming · security telemetry"},
    # Monitoring
    "grafana":          {"title": "Grafana", "icon": "hl-grafana", "category": "Monitoring",
                         "description": "Metrics · health dashboards"},
    "dockhand":         {"title": "Dockhand", "icon": "hl-portainer", "category": "Monitoring",
                         "description": "Container management · lifecycle"},
    # Identity
    "authentik":        {"title": "Authentik", "icon": "hl-authentik", "category": "Identity",
                         "description": "SSO · identity provider"},
    # Apps
    "nextcloud":        {"title": "Nextcloud", "icon": "hl-nextcloud", "category": "Apps",
                         "description": "Files · calendar · contacts · office"},
    "affine":           {"title": "AFFiNE", "icon": "hl-affine", "category": "Apps",
                         "description": "Knowledge base · collaborative docs"},
    "vikunja":          {"title": "Vikunja", "icon": "hl-vikunja", "category": "Apps",
                         "description": "Projects · task tracking"},
    "tandoor":          {"title": "Tandoor", "icon": "hl-tandoor", "category": "Apps",
                         "description": "Recipes · meal planning"},
    "n8n":              {"title": "n8n", "icon": "hl-n8n", "category": "Apps",
                         "description": "Workflow automation · SOAR"},
    "immich":           {"title": "Immich", "icon": "hl-immich", "category": "Apps",
                         "description": "Photo · video library"},
    "ntfy":             {"title": "ntfy", "icon": "hl-ntfy", "category": "Apps",
                         "description": "Push notifications"},
    # Media
    "jellyfin":         {"title": "Jellyfin", "icon": "hl-jellyfin", "category": "Media",
                         "description": "Media server · streaming"},
    "jellyseerr":       {"title": "Jellyseerr", "icon": "hl-jellyseerr", "category": "Media",
                         "description": "Media requests"},
    "prowlarr":         {"title": "Prowlarr", "icon": "hl-prowlarr", "category": "Media",
                         "description": "Indexer manager"},
    "radarr":           {"title": "Radarr", "icon": "hl-radarr", "category": "Media",
                         "description": "Movie management"},
    "sonarr":           {"title": "Sonarr", "icon": "hl-sonarr", "category": "Media",
                         "description": "TV management"},
    "lidarr":           {"title": "Lidarr", "icon": "hl-lidarr", "category": "Media",
                         "description": "Music management"},
    "qbittorrent":      {"title": "qBittorrent", "icon": "hl-qbittorrent", "category": "Media",
                         "description": "Download client"},
    # Non-UI routes — no tile.
    "spreed-signaling": {"hidden": True},   # Talk HPB WebSocket endpoint
    "janus":            {"hidden": True},   # WebRTC admin API
    "notify-push":      {"hidden": True},   # Nextcloud push daemon
    "flaresolverr":     {"hidden": True},   # internal *arr captcha solver, no UI
    "authentik-proxy":  {"hidden": True},   # outpost
}

CATEGORY_ORDER = ["Security", "Monitoring", "Identity", "Apps", "Media", "Services"]
CATEGORY_META = {
    "Security":   ("fas fa-shield-halved", "Defense · detection · response"),
    "Monitoring": ("fas fa-chart-line", "Eyes on glass"),
    "Identity":   ("fas fa-key", "Who goes there"),
    "Apps":       ("fas fa-grid-2", "Daily drivers"),
    "Media":      ("fas fa-play-circle", "Stream · collect · enjoy"),
    "Services":   ("fas fa-cubes", "Everything else"),
}

_CUSTOM_CSS = "\n".join([
    ".item{transition:transform .15s ease,box-shadow .15s ease;}",
    ".item:hover{transform:translateY(-3px);box-shadow:0 0 18px var(--primary);}",
    "h1.dashboard-title{font-family:'JetBrains Mono',monospace;letter-spacing:3px;"
    "text-shadow:0 0 14px var(--primary);}",
    ".section-title{font-family:'JetBrains Mono',monospace;text-transform:uppercase;"
    "letter-spacing:1px;}",
    ".collapsable-section{backdrop-filter:blur(2px);}",
])


def _autodefault(service: str) -> dict:
    return {
        "title": service.replace("-", " ").replace("_", " ").title(),
        "icon": f"hl-{service}",
        "category": "Services",
        "description": "",
    }


def build_tiles(matchers: dict[str, str], fqdn: str) -> list[dict]:
    """matchers {subdomain: service} → list of tile dicts (hidden excluded)."""
    tiles: list[dict] = []
    for sub, service in sorted(matchers.items()):
        meta = ENRICHMENT.get(service)
        if meta and meta.get("hidden"):
            continue
        meta = meta or _autodefault(service)
        tiles.append({
            "service": service,
            "title": meta["title"],
            "url": f"https://{sub}.{fqdn}",
            "icon": meta["icon"],
            "description": meta.get("description", ""),
            "category": meta.get("category", "Services"),
        })
    return tiles


def render(matchers: dict[str, str], fqdn: str, nav: dict[str, str]) -> str:
    """Build the Dashy config and return it as JSON text (valid YAML)."""
    tiles = build_tiles(matchers, fqdn)
    buckets: dict[str, list[dict]] = {c: [] for c in CATEGORY_ORDER}
    for t in tiles:
        buckets.setdefault(t["category"], []).append(t)

    def navp(key: str, default: str) -> str:
        return f"https://{nav.get(key, default)}.{fqdn}"

    sections = []
    for cat in CATEGORY_ORDER:
        items = buckets.get(cat) or []
        if not items:
            continue
        icon, tagline = CATEGORY_META[cat]
        sec_items = []
        for t in items:
            item = {"title": t["title"], "url": t["url"], "icon": t["icon"],
                    "statusCheck": True}
            if t["description"]:
                item["description"] = t["description"]
            sec_items.append(item)
        sections.append({
            "name": cat,
            "icon": icon,
            "displayData": {"sortBy": "default", "rows": 1, "cols": 1},
            "items": sec_items,
        })

    config = {
        "pageInfo": {
            "title": f"{fqdn} // ops",
            "description": "example.com · Operations Center · stay frosty",
            "navLinks": [
                {"title": "Grafana",   "path": navp("GRAFANA_SUBDOMAIN", "dash")},
                {"title": "Dockhand",  "path": navp("DOCKHAND_SUBDOMAIN", "dock")},
                {"title": "Authentik", "path": navp("AUTHENTIK_SUBDOMAIN", "auth")},
            ],
        },
        "appConfig": {
            "theme": "callisto",
            "customColors": {
                "callisto": {"primary": "#00e0c6", "background": "#0a0e14"},
            },
            "customCss": _CUSTOM_CSS,
            "iconSize": "medium",
            "layout": "auto",
            "defaultOpeningMethod": "newtab",
            "statusCheck": True,
            "statusCheckInterval": 60,
            "preventWriteToDisk": True,
            "disableUpdateChecks": True,
        },
        "sections": sections,
    }
    header = "# GENERATED by gen-dashy-config.py — do not edit by hand.\n"
    return header + json.dumps(config, indent=2) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate Dashy conf.yml from live discovery")
    ap.add_argument("--output", "-o", help="Write to file (default: stdout)")
    ap.add_argument("--env", default=str(_STACK / ".env"))
    ap.add_argument("--caddyfile", default=str(_STACK / "templates/caddy/Caddyfile"))
    args = ap.parse_args()

    env = load_env(Path(args.env))
    fqdn = env.get("PUBLIC_FQDN", "yourdomain.com")
    caddy = parse_caddyfile(Path(args.caddyfile), env)
    out = render(caddy["matchers"], fqdn, env)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Written {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
