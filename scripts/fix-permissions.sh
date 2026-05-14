#!/usr/bin/env bash
# fix-permissions.sh — Fix host bind-mount ownership for Docker services.
#
# Most containers run as docktaetor:media (1010:1010) so docker-host-config.sh
# creates /dock/conf/<svc> and /dock/data/<svc> with that ownership.
#
# Exception: services that run as a DIFFERENT UID AND have cap_drop:ALL lose
# DAC_OVERRIDE, meaning their "root" user cannot bypass normal Unix permission
# checks. Without this script those services cannot access their own bind-mounts.
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

DOCK_CONF="${DOCK_CONF:-/dock/conf}"
DOCK_DATA="${DOCK_DATA:-/dock/data}"

DEFAULT_USER="docktaetor"
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
# when --tailscale is passed), then sets docktaetor:media 770 ownership.
# Called automatically by add-service.py after scaffolding a new service.
if [ "${1:-}" = "--service" ]; then
    svc="${2:?Usage: fix-permissions.sh --service <name> [--tailscale]}"
    want_tailscale=false
    for arg in "$@"; do [ "$arg" = "--tailscale" ] && want_tailscale=true; done

    echo "Provisioning host directories for service: $svc"

    for dir in "${DOCK_CONF}/${svc}" "${DOCK_DATA}/${svc}"; do
        install -d -o 1010 -g 1010 -m 770 "$dir"
        c_grn "  ${dir}  (docktaetor:media 770)"
    done

    if $want_tailscale; then
        install -d -o 1010 -g 1010 -m 770 "${DOCK_CONF}/tail/${svc}"
        c_grn "  ${DOCK_CONF}/tail/${svc}  (docktaetor:media 770)"
    fi

    c_grn "Done. Directories ready for ${svc}."
    exit 0
fi

# ── Standard services: docktaetor:media ───────────────────────────────────────
echo "Applying standard ownership (${DEFAULT_USER}:${DEFAULT_GROUP}) to all service dirs..."

for base in "$DOCK_CONF" "$DOCK_DATA"; do
    [ -d "$base" ] || continue
    for svc_dir in "$base"/*/; do
        svc=$(basename "$svc_dir")
        # Skip services with known overrides (handled below)
        case "$svc" in affine|spreed-signaling|janus|redpanda|redpanda-console) continue ;; esac
        chown "${DEFAULT_USER}:${DEFAULT_GROUP}" "$svc_dir" 2>/dev/null || true
        # Don't recurse here — service-internal dirs may be owned by container UIDs
    done
done

# ── Redpanda: UID/GID 101 ────────────────────────────────────────────────────
# Runs as UID/GID 101 (redpanda user inside the container). Requires owner-level
# access to /dock/data/redpanda for WAL and data segments. conf dir uses standard
# docktaetor:media ownership since it holds no container-written files.
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

echo ""
c_grn "fix-permissions.sh complete."
echo "Restart any affected containers:"
echo "  docker compose --profile apps up -d --no-deps --force-recreate affine"
