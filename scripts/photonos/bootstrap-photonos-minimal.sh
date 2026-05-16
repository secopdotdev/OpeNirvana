#!/bin/sh
# bootstrap-photonos-minimal.sh
# Prepare a fresh VMware Photon OS *Minimal* host so docker-host-config.sh runs.
#
# The Photon OS Minimal image is intentionally tiny: it ships tdnf, rpm, systemd
# and a core shell, but omits much of the userland — curl, tar, gzip, grep, sed,
# gawk, findutils, iproute2, python3 — that docker-host-config.sh and the stack
# scripts assume is present. This script installs that foundational layer.
#
# It is written in POSIX sh and uses only tdnf plus shell builtins, so it runs
# on a bare Minimal box (even one without bash — which it then installs).
#
# Idempotent: safe to re-run. tdnf install is a no-op for present packages.
#
# Usage:
#   sudo sh scripts/photonos/bootstrap-photonos-minimal.sh
#
# Then bootstrap the full stack host:
#   sudo ./scripts/photonos/docker-host-config.sh
set -eu

# ── Output helpers (no colour-tool dependency) ───────────────────────────────
red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
yel()  { printf '\033[33m%s\033[0m\n' "$*"; }
step() { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

# ── Preconditions ────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    red "Run as root: sudo sh $0"
    exit 1
fi

if [ ! -r /etc/os-release ]; then
    red "/etc/os-release not found — cannot confirm this is Photon OS."
    exit 1
fi
# shellcheck source=/dev/null
. /etc/os-release
if [ "${ID:-}" != "photon" ]; then
    red "Unsupported OS: ${ID:-unknown}. This bootstrap targets VMware Photon OS."
    exit 1
fi
if ! command -v tdnf >/dev/null 2>&1; then
    red "tdnf not found — this does not look like a Photon OS host."
    exit 1
fi
grn "Photon OS ${VERSION_ID:-?} detected."

# ── Foundational packages ────────────────────────────────────────────────────
# Userland that Photon Minimal may omit but docker-host-config.sh / the stack
# scripts need. Installed individually so one unknown package name cannot abort
# the whole run; a final command check below is the real safety net.
PACKAGES="
bash
coreutils
grep
sed
gawk
findutils
tar
gzip
curl
wget
ca-certificates
shadow
iproute2
procps-ng
openssh
sudo
python3
python3-pip
"

step "Refreshing tdnf metadata..."
tdnf makecache >/dev/null 2>&1 || true

step "Installing foundational packages..."
failed=""
for pkg in $PACKAGES; do
    if tdnf install -y "$pkg" >/dev/null 2>&1; then
        grn "  ok: $pkg"
    else
        yel "  could not install: $pkg"
        failed="$failed $pkg"
    fi
done

# ── Verify the commands docker-host-config.sh actually needs ─────────────────
step "Verifying required commands..."
missing=""
for cmd in bash curl tar gzip grep sed awk find install python3 systemctl rpm tdnf; do
    if command -v "$cmd" >/dev/null 2>&1; then
        grn "  found: $cmd"
    else
        red "  MISSING: $cmd"
        missing="$missing $cmd"
    fi
done

if [ -n "$missing" ]; then
    red ""
    red "Bootstrap incomplete — these required commands are still missing:$missing"
    red "Install the providing packages manually with tdnf, then re-run this script."
    exit 1
fi

# ── Done ─────────────────────────────────────────────────────────────────────
step "Bootstrap complete."
if [ -n "$failed" ]; then
    yel "Some packages did not install (non-fatal — required commands are present):$failed"
fi
grn "This Photon OS Minimal host now has the dependencies docker-host-config.sh needs."
cat <<'EOF'

Next step — bootstrap the full stack host:

  sudo ./scripts/photonos/docker-host-config.sh

That script installs Docker, Tailscale and the Wazuh agent, creates the /dock
tree, generates secrets, and configures the firewall.
EOF
