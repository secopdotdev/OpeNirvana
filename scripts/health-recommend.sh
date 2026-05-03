#!/usr/bin/env bash
# Inspect host CPU + RAM and print a recommended tier block.
set -euo pipefail

CPUS=$(nproc)
MEM_GB=$(awk '/MemTotal/ {printf "%d\n", $2/1024/1024}' /proc/meminfo)

TIER="UNKNOWN"
if [ "$MEM_GB" -ge 48 ] && [ "$CPUS" -ge 12 ]; then
    TIER="HIGH"
elif [ "$MEM_GB" -ge 14 ] && [ "$CPUS" -ge 6 ]; then
    TIER="MED"
else
    TIER="LOW"
fi

cat <<EOF
Host inspection:
    CPUs: $CPUS
    RAM:  ${MEM_GB} GB

Recommended tier: ${TIER}

Edit /dock/conf/.env: uncomment the ${TIER} tier block, comment the others.
EOF
