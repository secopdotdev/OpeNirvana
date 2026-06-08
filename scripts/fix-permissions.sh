#!/usr/bin/env bash
# fix-permissions.sh — Fix host bind-mount ownership for Docker services.
#
# Most containers run as svc-user:media (1010:1010) so docker-host-config.sh
# creates /dock/conf/<svc> and /dock/data/<svc> with that ownership.
#
# Exception: services that run as a DIFFERENT UID AND have cap_drop:ALL lose
# DAC_OVERRIDE, meaning their "root" user cannot bypass normal Unix permission
# checks. Without this script those services cannot access their own bind-mounts.
# Services that run as a non-root, non-1010 UID also need their top-level
# bind-mount directory owned by that UID for traversal.
#
# Known exception — Nextcloud:
#   Runs Apache as www-data (UID 33, GID 33). /dock/data/nextcloud is bind-mounted
#   as /var/www/html. With svc-user:media 770, www-data (UID 33) is "other" and
#   cannot traverse the directory, causing Apache to return 403 and fail its
#   healthcheck (php occ status). Fix: chown top-level dir to www-data:www-data.
#   Do NOT recurse — files inside are already owned by www-data and content dirs
#   (data/) are also www-data-owned.
#
# Known exception — AFFiNE:
#   Runs as UID 0 (root) inside the container with cap_drop:ALL.
#   Without DAC_OVERRIDE, root cannot traverse directories owned by 1010:1010
#   with mode 770, causing EACCES on /root/.affine/storage/blobs at startup.
#   Fix: chown /dock/data/affine to root:root so the container's restricted
#   root user (UID 0, no DAC_OVERRIDE) has normal owner-level access.
#
# Usage:
#   sudo bash scripts/fix-permissions.sh
#
# Idempotent: safe to re-run at any time without side effects.
# Run after docker-host-config.sh, after pulling new service additions, or
# whenever a service fails with "EACCES" on its bind-mount path.

set -euo pipefail

# Source .env from the unified-stack root so path vars come from config, not defaults.
_ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
if [ -f "$_ENV_FILE" ]; then
    # shellcheck source=/dev/null
    set -a; . "$_ENV_FILE"; set +a
fi

DOCK_CONF="${DOCK_CONF:-/dock/conf}"
DOCK_DATA="${DOCK_DATA:-/dock/data}"
MEDIA_PATH="${MEDIA_PATH:-/mnt/media}"
DOWNLOADS_PATH="${DOWNLOADS_PATH:-/mnt/HDD/downloads}"

DEFAULT_USER="svc-user"
DEFAULT_GROUP="media"
DEFAULT_MODE="775"

c_grn() { printf "\033[32m%s\033[0m\n" "$*"; }
c_yel() { printf "\033[33m%s\033[0m\n" "$*"; }
c_red() { printf "\033[31m%s\033[0m\n" "$*" >&2; }

fix_dir() {
    local dir="$1" owner="$2" group="$3"
    if [ ! -d "$dir" ]; then
        c_yel "  skip (not found): $dir"
        return
    fi
    chown -R "${owner}:${group}" "$dir"
    c_grn "  chown ${owner}:${group} $dir"
}

# ── Single-service provisioning mode ─────────────────────────────────────────
# Usage: fix-permissions.sh --service <name> [--tailscale]
# Creates /dock/conf/<name> and /dock/data/<name> (and /dock/conf/tail/<name>
# when --tailscale is passed), then sets svc-user:media 770 ownership.
# Called automatically by add-service.py after scaffolding a new service.
if [ "${1:-}" = "--service" ]; then
    svc="${2:?Usage: fix-permissions.sh --service <name> [--tailscale]}"
    want_tailscale=false
    for arg in "$@"; do [ "$arg" = "--tailscale" ] && want_tailscale=true; done

    echo "Provisioning host directories for service: $svc"

    for dir in "${DOCK_CONF}/${svc}" "${DOCK_DATA}/${svc}"; do
        install -d -o 1010 -g 1010 -m 770 "$dir"
        c_grn "  ${dir}  (svc-user:media 770)"
    done

    if $want_tailscale; then
        install -d -o 1010 -g 1010 -m 770 "${DOCK_CONF}/tail/${svc}"
        c_grn "  ${DOCK_CONF}/tail/${svc}  (svc-user:media 770)"
    fi

    c_grn "Done. Directories ready for ${svc}."
    exit 0
fi

# ── Standard services: svc-user:media ───────────────────────────────────────
echo "Applying standard ownership (${DEFAULT_USER}:${DEFAULT_GROUP}) to all service dirs..."

for base in "$DOCK_CONF" "$DOCK_DATA"; do
    [ -d "$base" ] || continue
    for svc_dir in "$base"/*/; do
        svc=$(basename "$svc_dir")
        # Skip services with known overrides (handled below)
        case "$svc" in nextcloud|vikunja|affine|spreed-signaling|janus|redpanda|redpanda-console|grafana|prometheus|cadvisor|node-exporter|dashy|alertmanager|loki|alloy) continue ;; esac
        chown "${DEFAULT_USER}:${DEFAULT_GROUP}" "$svc_dir" 2>/dev/null || true
        # Don't recurse here — service-internal dirs may be owned by container UIDs
    done
done

# ── Vikunja: UID/GID 1000 (top-level only) ───────────────────────────────────
# Runs as UID 1000 (maps to admin on this host). /dock/data/vikunja is bind-mounted
# as /app/vikunja/files. With svc-user:media 770, UID 1000 is "other" and cannot
# write attachments/uploads. Top-level dir must be owned by 1000:1000.
echo ""
echo "Applying 1000:1000 to Vikunja files dir (top-level only)..."
if [ -d "${DOCK_DATA}/vikunja" ]; then
    chown 1000:1000 "${DOCK_DATA}/vikunja"
    c_grn "  chown 1000:1000 ${DOCK_DATA}/vikunja"
else
    c_yel "  skip (not found): ${DOCK_DATA}/vikunja"
fi

# ── Nextcloud: www-data:www-data (top-level only) ────────────────────────────
# Apache runs as www-data (UID 33). /dock/data/nextcloud is bind-mounted as
# /var/www/html. Top-level dir must be owned by www-data for traversal.
# Files inside are already www-data-owned; do NOT recurse.
echo ""
echo "Applying www-data:www-data to Nextcloud data dir (top-level only)..."
if [ -d "${DOCK_DATA}/nextcloud" ]; then
    chown www-data:www-data "${DOCK_DATA}/nextcloud"
    c_grn "  chown www-data:www-data ${DOCK_DATA}/nextcloud"
else
    c_yel "  skip (not found): ${DOCK_DATA}/nextcloud"
fi

# ── Redpanda: UID/GID 101 ────────────────────────────────────────────────────
# Runs as UID/GID 101 (redpanda user inside the container). Requires owner-level
# access to /dock/data/redpanda for WAL and data segments. conf dir uses standard
# svc-user:media ownership since it holds no container-written files.
echo ""
echo "Applying 101:101 to Redpanda data dir..."
fix_dir "${DOCK_DATA}/redpanda" 101 101

# ── AFFiNE: root:root ─────────────────────────────────────────────────────────
# Runs as UID 0 with cap_drop:ALL (no DAC_OVERRIDE). Must own its dirs as root.
echo ""
echo "Applying root:root to AFFiNE dirs..."
fix_dir "${DOCK_DATA}/affine"         root root
fix_dir "${DOCK_DATA}/affine/config"  root root
fix_dir "${DOCK_DATA}/affine/storage" root root
# Recurse into storage subdirs (blobs, avatars, copilot created by the container)
if [ -d "${DOCK_DATA}/affine/storage" ]; then
    find "${DOCK_DATA}/affine/storage" -mindepth 1 -exec chown root:root {} +
    c_grn "  chown root:root ${DOCK_DATA}/affine/storage/** (recursive)"
fi
fix_dir "${DOCK_CONF}/affine" root root 2>/dev/null || true

# ── spreed-signaling + janus: root:root 644 ─────────────────────────────────────
# Both run as root with cap_drop:ALL (no DAC_OVERRIDE). spreed-signaling also drops
# to an unprivileged user at startup, so "other" read is required (mode 644).
echo ""
echo "Applying root:root 644 to spreed-signaling/janus rendered configs..."
for f in "${DOCK_CONF}/spreed-signaling/server.conf" \
         "${DOCK_CONF}/janus/janus.jcfg" \
         "${DOCK_CONF}/janus/janus.transport.http.jcfg"; do
    if [ -f "$f" ]; then
        chown root:root "$f"
        chmod 644 "$f"
        c_grn "  root:root 644 $f"
    else
        c_yel "  skip (not found): $f"
    fi
done

# ── Media paths: svc-user:media (top-level only — don't recurse into content) ─
echo ""
echo "Applying ${DEFAULT_USER}:${DEFAULT_GROUP} to media paths..."
for mdir in "$MEDIA_PATH" "$DOWNLOADS_PATH"; do
    if [ -d "$mdir" ]; then
        chown "${DEFAULT_USER}:${DEFAULT_GROUP}" "$mdir"
        c_grn "  chown ${DEFAULT_USER}:${DEFAULT_GROUP} $mdir"
    else
        c_yel "  skip (not found): $mdir"
    fi
done

# ── Grafana: UID/GID 472 ──────────────────────────────────────────────────────
# Runs as UID 472 (grafana user) with cap_drop:ALL (no DAC_OVERRIDE).
# /dock/data/grafana must be owned by grafana so it can create its database.
# /dock/conf/grafana/provisioning is bind-mounted as /etc/grafana/provisioning;
# Grafana must own the entire tree to read datasource/dashboard YAML at startup.
echo ""
echo "Applying 472:472 to Grafana data dir (top-level only)..."
if [ -d "${DOCK_DATA}/grafana" ]; then
    chown 472:472 "${DOCK_DATA}/grafana"
    c_grn "  chown 472:472 ${DOCK_DATA}/grafana"
else
    c_yel "  skip (not found): ${DOCK_DATA}/grafana"
fi

echo "Applying 472:472 to Grafana provisioning dir (recursive)..."
if [ -d "${DOCK_CONF}/grafana/provisioning" ]; then
    chown -R 472:472 "${DOCK_CONF}/grafana/provisioning"
    find "${DOCK_CONF}/grafana/provisioning" -type f -exec chmod 644 {} +
    c_grn "  chown -R 472:472 ${DOCK_CONF}/grafana/provisioning (files chmod 644)"
else
    c_yel "  skip (not found): ${DOCK_CONF}/grafana/provisioning"
fi

# ── Prometheus: UID/GID 65534 (nobody) ───────────────────────────────────────
# Runs as nobody (UID 65534) with cap_drop:ALL. Data dir must be writable.
echo ""
echo "Applying 65534:65534 to Prometheus data dir (top-level only)..."
if [ -d "${DOCK_DATA}/prometheus" ]; then
    chown 65534:65534 "${DOCK_DATA}/prometheus"
    c_grn "  chown 65534:65534 ${DOCK_DATA}/prometheus"
else
    c_yel "  skip (not found): ${DOCK_DATA}/prometheus"
fi

# ── Alertmanager: UID/GID 65534 (nobody) ─────────────────────────────────────
# Runs as nobody (UID 65534) with cap_drop:ALL. Data dir must be writable.
echo ""
echo "Applying 65534:65534 to Alertmanager data dir (top-level only)..."
if [ -d "${DOCK_DATA}/alertmanager" ]; then
    chown 65534:65534 "${DOCK_DATA}/alertmanager"
    c_grn "  chown 65534:65534 ${DOCK_DATA}/alertmanager"
else
    c_yel "  skip (not found): ${DOCK_DATA}/alertmanager"
fi

# ── Loki: UID/GID 10001 ───────────────────────────────────────────────────────
# Runs as UID 10001 (loki user) with cap_drop:ALL. Data dir must be owned by
# 10001:10001 so the compactor and ingester can write chunks and index files.
echo ""
echo "Applying 10001:10001 to Loki data dir (top-level only)..."
if [ -d "${DOCK_DATA}/loki" ]; then
    chown 10001:10001 "${DOCK_DATA}/loki"
    c_grn "  chown 10001:10001 ${DOCK_DATA}/loki"
else
    c_yel "  skip (not found): ${DOCK_DATA}/loki"
fi

# ── Alloy: UID/GID 473 ───────────────────────────────────────────────────────
# Runs as UID 473 (alloy user) with cap_drop:ALL. Without DAC_OVERRIDE, it
# cannot traverse a 770 dir owned by 1010:1010, so conf dir must be 473:473.
# Data is ephemeral (in-container WAL) — no host data dir needed.
echo ""
echo "Applying 473:473 to Alloy conf dir (top-level only)..."
if [ -d "${DOCK_CONF}/alloy" ]; then
    chown 473:473 "${DOCK_CONF}/alloy"
    c_grn "  chown 473:473 ${DOCK_CONF}/alloy"
else
    c_yel "  skip (not found): ${DOCK_CONF}/alloy"
fi
if [ -f "${DOCK_CONF}/alloy/config.alloy" ]; then
    chown 473:473 "${DOCK_CONF}/alloy/config.alloy"
    c_grn "  chown 473:473 ${DOCK_CONF}/alloy/config.alloy"
fi

# ── Dashy: UID/GID 1000 (node user) ──────────────────────────────────────────
# Runs as UID 1000 (node) with cap_drop:ALL. conf dir must be owned by 1000:1000
# so the container can read conf.yml and write validated config back.
echo ""
echo "Applying 1000:1000 to Dashy conf dir (top-level only)..."
if [ -d "${DOCK_CONF}/dashy" ]; then
    chown 1000:1000 "${DOCK_CONF}/dashy"
    c_grn "  chown 1000:1000 ${DOCK_CONF}/dashy"
else
    c_yel "  skip (not found): ${DOCK_CONF}/dashy"
fi
if [ -f "${DOCK_CONF}/dashy/conf.yml" ]; then
    chown 1000:1000 "${DOCK_CONF}/dashy/conf.yml"
    c_grn "  chown 1000:1000 ${DOCK_CONF}/dashy/conf.yml"
fi

echo ""
c_grn "fix-permissions.sh complete."
echo "Restart any affected containers:"
echo "  docker compose --profile apps up -d --no-deps --force-recreate affine"
