#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 22.04+ host for the unified-stack compose.
# Idempotent: safe to re-run. Never overwrites existing user data or .env values.
set -euo pipefail

# Colour output helpers.
c_red()  { printf "\033[31m%s\033[0m\n" "$*"; }
c_grn()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_blu()  { printf "\033[34m%s\033[0m\n" "$*"; }
step()   { printf "\n\033[36m==> %s\033[0m\n" "$*"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/dock/conf/.env"
CRS_VERSION="v4.7.0"

require_root() {
    if [ "$EUID" -ne 0 ]; then
        c_red "Run as root: sudo $0"
        exit 1
    fi
}

detect_ubuntu() {
    step "Detecting OS..."
    # shellcheck source=/dev/null
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        c_red "Unsupported OS: $ID. Ubuntu only."
        exit 1
    fi
    local major=${VERSION_ID%%.*}
    if [ "$major" -lt 22 ]; then
        c_red "Ubuntu $VERSION_ID is too old; require 22.04+."
        exit 1
    fi
    c_grn "Ubuntu $VERSION_ID OK"
}

apt_upgrade() {
    step "apt update + full-upgrade..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get full-upgrade -y -qq
    apt-get autoremove -y -qq
}

install_base_packages() {
    step "Installing base packages..."
    apt-get install -y -qq \
        curl wget jq zstd unzip \
        ca-certificates gnupg lsb-release \
        ufw fail2ban cron \
        bash-completion \
        libxml2-utils \
        openssl \
        python3 \
        libpam-google-authenticator
}

install_docker() {
    step "Installing Docker Engine..."
    if command -v docker >/dev/null 2>&1; then
        c_grn "Docker already installed: $(docker --version)"
        return
    fi
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

install_tailscale() {
    step "Installing Tailscale..."
    if command -v tailscale >/dev/null 2>&1; then
        c_grn "Tailscale already installed: $(tailscale --version | head -1)"
        return
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg" \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list" \
        -o /etc/apt/sources.list.d/tailscale.list
    apt-get update -qq
    apt-get install -y -qq tailscale
    systemctl enable --now tailscaled
}

create_user_and_groups() {
    step "Creating docktaetor:media (1010:1010)..."
    if ! getent group media >/dev/null; then
        groupadd -g 1010 media
    fi
    if ! id docktaetor >/dev/null 2>&1; then
        useradd -m -u 1010 -g 1010 -s /bin/bash docktaetor
    fi
    usermod -aG docker docktaetor || true
}

create_dock_tree() {
    step "Creating /dock tree..."
    local dirs=(
        /dock/conf/caddy/{snippets,coraza/rules,data,logs,souin}
        /dock/conf/crowdsec/{notifications,db,hub}
        /dock/conf/socket-proxy-ro
        /dock/conf/socket-proxy-rw
        /dock/conf/authentik/{media,custom-templates,certs}
        /dock/conf/wazuh/{manager,indexer,dashboard,certs,decoders,rules}
        /dock/conf/falco/rules.d
        /dock/conf/zeek/{intel,logs}
        /dock/conf/qbittorrent/qBittorrent
        # Media stack
        /dock/conf/jellyfin
        /dock/conf/jellyseerr
        # Productivity stack
        /dock/conf/ntfy
        # HPB: Nextcloud Talk High-Performance Backend
        /dock/conf/spreed-signaling
        /dock/conf/janus
        /dock/data/authentik
        /dock/data/nextcloud
        /dock/data/wazuh/{indexer-1,indexer-2,indexer-3,manager}
        # Media stack data
        /dock/data/jellyfin
        # Productivity stack data
        /dock/data/ntfy/{cache,data}
        /dock/data/tandoor/{media,static}
        /dock/data/vikunja
        /dock/data/affine/{config,storage}
        /dock/db/postgres/{data,init.d}
        /dock/db/redis
        /dock/tail/ingress
        /dock/backups/postgres
        /dock/backups/redis
    )
    for d in "${dirs[@]}"; do
        install -d -o 1010 -g 1010 -m 770 "$d"
    done
    # On a fresh /dock the install loop above may leave auto-created parent dirs
    # as root:root 755. Fix the whole tree once — but only when postgres/data is
    # empty, meaning the stack has never run. On re-runs this is skipped to avoid
    # resetting ownership on live container-managed files (Postgres data, Redis
    # appendonly, Wazuh indices).
    if [ -z "$(ls -A /dock/db/postgres/data 2>/dev/null)" ]; then
        chown -R 1010:1010 /dock
        find /dock -type d -exec chmod 770 {} +
    fi
    # Tighter perms on DB dirs
    chmod 700 /dock/db/postgres/data /dock/db/redis
    # Wazuh images ship uid 1000 (wazuh-indexer/wazuh-dashboard). Manager runs as root
    # so it can read everything; indexer + dashboard need ownership of their own trees
    # and the shared certs dir. Perms stay 750 — group (media/1001) retains read.
    chown -R 1000:1000 \
        /dock/conf/wazuh/indexer \
        /dock/conf/wazuh/dashboard \
        /dock/conf/wazuh/certs \
        /dock/data/wazuh/indexer-1 \
        /dock/data/wazuh/indexer-2 \
        /dock/data/wazuh/indexer-3
    chmod 750 /dock/conf/wazuh/indexer /dock/conf/wazuh/dashboard /dock/conf/wazuh/certs
    # Authentik runs as uid 1000 via the x-hardened anchor and needs rw access
    # to its media + custom-templates dirs.
    chown -R 1000:1000 /dock/conf/authentik /dock/data/authentik
    # Nextcloud official image runs as www-data (uid 33:gid 33). The data dir
    # must be owned by 33:33 or the container will fail to write on first start.
    chown 33:33 /dock/data/nextcloud
    # Tandoor runs as uid 1000 (gunicorn/django). Media + static dirs need 1000 ownership.
    chown -R 1000:1000 /dock/data/tandoor
    # Vikunja runs as uid 1000. Files dir needs 1000 ownership.
    chown -R 1000:1000 /dock/data/vikunja
    # ntfy runs as root (uid 0) inside the container but cap_drop:ALL removes
    # CAP_DAC_OVERRIDE. Dirs owned by docktaetor:media (1010:1010) would be
    # inaccessible to the containerised root. Own them by root so the process
    # can read/write without elevated capabilities.
    chown -R root:root /dock/data/ntfy /dock/conf/ntfy
    chmod -R 755 /dock/data/ntfy /dock/conf/ntfy
}

copy_templates() {
    step "Copying templates to /dock/conf/..."
    local src="$REPO_DIR/templates"
    [ -d "$src" ] || { c_red "Missing $src"; exit 1; }
    # Rsync-style: copy only if target absent, never overwrite local edits.
    find "$src" -type f | while read -r f; do
        local rel="${f#"$src"/}"
        local dst="/dock/conf/${rel}"
        if [ ! -f "$dst" ]; then
            install -D -o 1010 -g 1010 -m 640 "$f" "$dst"
        fi
    done
    # Postgres init scripts go under /dock/db/postgres/init.d/
    if [ -f "$src/postgres/init.d/00-create-app-dbs.sh" ]; then
        install -D -o 1010 -g 1010 -m 750 \
            "$src/postgres/init.d/00-create-app-dbs.sh" \
            /dock/db/postgres/init.d/00-create-app-dbs.sh
    fi
    # Render interpolated configs that can't be envsubst'd at container runtime.
    # Zeek reads /etc/zeek/node.cfg at startup and needs lb_procs as a bare integer
    # and the sniff interface as a bare device name.
    local zeek_node=/dock/conf/zeek/node.cfg
    if [ -f "$zeek_node" ] && grep -qE '\$\{ZEEK_WORKER_COUNT|\$\{ZEEK_INTERFACE' "$zeek_node"; then
        local count=4
        local iface_setting=auto
        if [ -f "$ENV_FILE" ]; then
            count=$(grep -E '^ZEEK_WORKER_COUNT=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]' || true)
            [ -n "$count" ] || count=4
            iface_setting=$(grep -E '^ZEEK_INTERFACES=' "$ENV_FILE" | cut -d= -f2- | awk '{print $1}' || true)
            [ -n "$iface_setting" ] || iface_setting=auto
        fi
        # Resolve auto → first active non-loopback/docker/tail/bridge interface.
        local iface
        if [ "$iface_setting" = "auto" ]; then
            iface=$(ip -o link show up | awk -F': ' '{print $2}' \
                | grep -Ev '^(lo|docker|br-|veth|tailscale)' | head -1)
            [ -n "$iface" ] || iface=eth0
        else
            iface="${iface_setting%%,*}"
        fi
        # shellcheck disable=SC2016  # single-quoted vars are intentional: envsubst filter list
        ZEEK_WORKER_COUNT="$count" ZEEK_INTERFACE="$iface" \
            envsubst '${ZEEK_WORKER_COUNT} ${ZEEK_INTERFACE}' \
            < "$zeek_node" > "$zeek_node.new"
        install -o 1010 -g 1010 -m 640 "$zeek_node.new" "$zeek_node"
        rm -f "$zeek_node.new"
        c_grn "Rendered zeek node.cfg (interface=$iface, lb_procs=$count)"
    fi
}

configure_hpb() {
    step "Configuring HPB (nextcloud-spreed-signaling + janus-gateway)..."

    # Warn if public IP is not configured — required for Janus NAT mapping.
    local pub_ip
    pub_ip=$(grep -E '^HOST_PUBLIC_IP=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
    if [ -z "$pub_ip" ]; then
        c_red "WARNING: HOST_PUBLIC_IP is not set in $ENV_FILE"
        c_red "  Set it to this server's public IP address before deploying janus-gateway."
        c_red "  janus.jcfg will be rendered with an empty nat_1_1_mapping — WebRTC will NOT work."
    fi

    local tmpl_dir="$REPO_DIR/templates"

    # --- nextcloud-spreed-signaling/server.conf ---
    local ss_conf=/dock/conf/spreed-signaling/server.conf
    if [ -f "$ss_conf" ] && ! grep -qE '\$\{NC_HPB_' "$ss_conf"; then
        c_grn "spreed-signaling/server.conf already rendered."
    else
        local hash_key block_key shared_secret janus_api_secret
        hash_key=$(grep    -E '^NC_HPB_HASH_KEY='      "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        block_key=$(grep   -E '^NC_HPB_BLOCK_KEY='     "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        shared_secret=$(grep -E '^NC_HPB_SHARED_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        janus_api_secret=$(grep -E '^JANUS_API_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        # shellcheck disable=SC2016
        NC_HPB_HASH_KEY="$hash_key" NC_HPB_BLOCK_KEY="$block_key" \
        NC_HPB_SHARED_SECRET="$shared_secret" JANUS_API_SECRET="$janus_api_secret" \
            envsubst '${NC_HPB_HASH_KEY} ${NC_HPB_BLOCK_KEY} ${NC_HPB_SHARED_SECRET} ${JANUS_API_SECRET}' \
            < "$tmpl_dir/spreed-signaling/server.conf" > "$ss_conf.new"
        install -o 1010 -g 1010 -m 640 "$ss_conf.new" "$ss_conf"
        rm -f "$ss_conf.new"
        c_grn "Rendered spreed-signaling/server.conf"
    fi

    # --- janus-gateway/janus.jcfg ---
    local janus_jcfg=/dock/conf/janus/janus.jcfg
    # Re-render if: file is absent, still has placeholders, or nat_1_1_mapping is empty
    # (happens when a previous run had no HOST_PUBLIC_IP — now that it's resolved, re-render).
    if [ -f "$janus_jcfg" ] && ! grep -qE '\$\{' "$janus_jcfg" \
       && grep -qE 'nat_1_1_mapping\s*=\s*"[0-9]' "$janus_jcfg"; then
        c_grn "janus/janus.jcfg already rendered."
    else
        local janus_admin_secret
        janus_api_secret=$(grep   -E '^JANUS_API_SECRET='   "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        janus_admin_secret=$(grep -E '^JANUS_ADMIN_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
        # shellcheck disable=SC2016
        JANUS_API_SECRET="$janus_api_secret" JANUS_ADMIN_SECRET="$janus_admin_secret" \
        HOST_PUBLIC_IP="$pub_ip" \
            envsubst '${JANUS_API_SECRET} ${JANUS_ADMIN_SECRET} ${HOST_PUBLIC_IP}' \
            < "$tmpl_dir/janus/janus.jcfg" > "$janus_jcfg.new"
        install -o 1010 -g 1010 -m 640 "$janus_jcfg.new" "$janus_jcfg"
        rm -f "$janus_jcfg.new"
        c_grn "Rendered janus/janus.jcfg (nat_1_1_mapping=${pub_ip:-UNSET})"
    fi

    # --- janus-gateway/janus.transport.http.jcfg (no template vars) ---
    local janus_http=/dock/conf/janus/janus.transport.http.jcfg
    if [ ! -f "$janus_http" ]; then
        install -o 1010 -g 1010 -m 640 \
            "$tmpl_dir/janus/janus.transport.http.jcfg" "$janus_http"
        c_grn "Installed janus/janus.transport.http.jcfg"
    else
        c_grn "janus/janus.transport.http.jcfg already present."
    fi
}

fetch_wazuh_certs_tool() {
    step "Fetching wazuh-certs-tool.sh..."
    local target=/dock/conf/wazuh/cert-tool/wazuh-certs-tool.sh
    if [ -f "$target" ]; then
        c_grn "wazuh-certs-tool.sh already present."
        return
    fi
    install -d -o 1010 -g 1010 -m 770 /dock/conf/wazuh/cert-tool
    curl -fsSL https://packages.wazuh.com/4.9/wazuh-certs-tool.sh \
        -o "$target"
    chown 1010:1010 "$target"
    chmod 750 "$target"
    c_grn "wazuh-certs-tool.sh installed."
}

seed_crowdsec_defaults() {
    step "Seeding crowdsec image defaults into /dock/conf/crowdsec/..."
    local target=/dock/conf/crowdsec
    if [ -d "$target/patterns" ]; then
        c_grn "crowdsec defaults already present."
        return
    fi
    # /etc/crowdsec/ is empty in the image; defaults live under /staging/etc/crowdsec/.
    # Seed the runtime dirs (patterns, parsers, scenarios, collections, contexts,
    # postoverflows, acquis.d, *.yaml defaults) into the host bind-mount so the whole
    # /etc/crowdsec tree is usable when we mount it read-write.
    docker run --rm --user 0:0 -v "$target":/target \
        --entrypoint sh crowdsecurity/crowdsec:latest \
        -c "cd /staging/etc/crowdsec && cp -rn patterns parsers scenarios collections contexts postoverflows acquis.d console.yaml dev.yaml user.yaml /target/ && chown -R 1010:1010 /target"
}

fetch_owasp_crs() {
    step "Fetching OWASP CRS ${CRS_VERSION}..."
    local target=/dock/conf/caddy/coraza/rules
    if compgen -G "${target}/REQUEST-*.conf" > /dev/null 2>&1; then
        c_grn "CRS rules already present."
        return
    fi
    local tmp; tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
        | tar -xz --strip-components=2 -C "$tmp" "coreruleset-${CRS_VERSION#v}/rules"
    cp -n "$tmp"/*.conf "$target/" || true
    # crs-setup example stays under the repo template; users may override.
    chown -R 1010:1010 "$target"
}

ensure_env_file() {
    step "Ensuring .env file..."
    if [ ! -f "$ENV_FILE" ]; then
        install -D -o 1010 -g 1010 -m 600 "$REPO_DIR/.env.example" "$ENV_FILE"
        c_grn "Created $ENV_FILE from .env.example"
    fi
}

resolve_public_ip() {
    step "Resolving host public IP..."

    # Skip if already set to a non-empty value.
    local current
    current=$(grep -E '^HOST_PUBLIC_IP=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]\r' || true)
    if [ -n "$current" ]; then
        c_grn "HOST_PUBLIC_IP already set: $current"
        return
    fi

    local ip=""
    for url in \
        "https://api.ipify.org" \
        "https://checkip.amazonaws.com" \
        "https://icanhazip.com"; do
        ip=$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]') || true
        if echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
            break
        fi
        ip=""
    done

    if [ -z "$ip" ]; then
        c_red "WARNING: Could not resolve public IP — set HOST_PUBLIC_IP in $ENV_FILE manually."
        return
    fi

    python3 - "$ENV_FILE" "HOST_PUBLIC_IP" "$ip" <<'PYEOF'
import sys, re
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r') as f:
    content = f.read()
new_content = re.sub(
    rf'^({re.escape(key)}=)\s*$',
    lambda m: f'{m.group(1)}{val}',
    content,
    flags=re.MULTILINE
)
if new_content == content:
    # Line absent (or has trailing comment) — append it.
    new_content = content.rstrip('\n') + f'\n{key}={val}\n'
with open(path, 'w') as f:
    f.write(new_content)
PYEOF
    c_grn "HOST_PUBLIC_IP resolved and set: $ip"
}

generate_missing_secrets() {
    step "Generating missing secrets..."
    # Delegate to gen-secrets.sh which uses a safe character set, handles Wazuh
    # password complexity requirements, and never overwrites existing values.
    bash "$REPO_DIR/scripts/gen-secrets.sh" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    chown docktaetor:media "$ENV_FILE"
}

install_wazuh_agent() {
    step "Installing Wazuh Agent..."
    if dpkg -s wazuh-agent >/dev/null 2>&1; then
        c_grn "Wazuh agent already installed."
    else
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update -qq
        WAZUH_MANAGER="127.0.0.1" apt-get install -y -qq wazuh-agent
        systemctl enable wazuh-agent
    fi
    # Install our custom decoders/rules and localfile config.
    bash "$REPO_DIR/scripts/wazuh-agent-ingest.sh"
}

install_cron_jobs() {
    step "Installing cron jobs..."
    install -m 755 "$REPO_DIR/scripts/pg-backup.sh"           /usr/local/bin/pg-backup.sh
    install -m 755 "$REPO_DIR/scripts/zeek-intel-refresh.sh"  /usr/local/bin/zeek-intel-refresh.sh
    cat > /etc/cron.d/unified-stack <<'EOF'
# Unified-stack scheduled jobs
MAILTO=""
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

0 2 * * * root /usr/local/bin/pg-backup.sh           >> /var/log/pg-backup.log 2>&1
0 3 * * * root /usr/local/bin/zeek-intel-refresh.sh  >> /var/log/zeek-intel.log 2>&1
EOF
    chmod 644 /etc/cron.d/unified-stack
}

install_systemd_units() {
    step "Installing compose-stack.service..."
    cat > /etc/systemd/system/compose-stack.service <<EOF
[Unit]
Description=Unified stack docker compose
After=docker.service tailscaled.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
User=docktaetor
Group=media
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable compose-stack.service
}

harden_sshd() {
    step "Hardening /etc/ssh/sshd_config..."
    local cfg=/etc/ssh/sshd_config

    local before
    before=$(md5sum "$cfg" | cut -d' ' -f1)

    # Edit directives in place — handles both commented (#Directive val) and
    # uncommented (Directive val) forms. Appends the line if not present at all.
    sshd_set() {
        local key="$1" val="$2"
        if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$cfg"; then
            sed -i -E "s|^#?[[:space:]]*(${key})[[:space:]].*|\1 ${val}|" "$cfg"
        else
            echo "${key} ${val}" >> "$cfg"
        fi
    }

    sshd_set SyslogFacility       AUTH
    sshd_set LogLevel              INFO
    sshd_set LoginGraceTime        2m
    sshd_set PermitRootLogin       no
    sshd_set MaxAuthTries          3
    sshd_set MaxSessions           5
    sshd_set AuthorizedKeysFile    ".ssh/authorized_keys"
    sshd_set AllowAgentForwarding  yes
    sshd_set PrintLastLog          yes
    sshd_set X11Forwarding         yes
    sshd_set PubkeyAuthentication  yes
    sshd_set HostbasedAuthentication yes

    # Validate before reloading — bail out rather than lock ourselves out.
    if ! sshd -t -f "$cfg"; then
        c_red "sshd_config validation failed — NOT restarting SSH. Fix $cfg manually."
        return 1
    fi

    if [ "$before" = "$(md5sum "$cfg" | cut -d' ' -f1)" ]; then
        c_grn "sshd_config unchanged — skipping restart"
        return 0
    fi

    systemctl daemon-reload
    systemctl restart ssh.socket
    c_grn "sshd hardened and restarted"
}

harden_ufw() {
    step "Configuring UFW..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    # ufw allow from 192.168.1.0/24 to any port 22 proto tcp # For added security if you SSH from a fixed LAN, but can lock you out if you move around.
    ufw allow 80/tcp
    ufw allow 443/tcp
    # coturn TURN/STUN — required for Nextcloud Talk WebRTC relay.
    # 3478 is the signalling port; 49152:49200 is the relay port range.
    ufw allow 3478/tcp
    ufw allow 3478/udp
    ufw allow 49152:49200/udp
    # Janus Gateway — WebRTC media ports for Nextcloud Talk HPB.
    ufw allow 20000:20100/udp
    ufw allow in on tailscale0
    ufw --force enable
}

kernel_tuning() {
    step "Applying kernel tuning..."
    cat > /etc/sysctl.d/99-unified-stack.conf <<'EOF'
net.ipv4.ip_forward = 1
vm.max_map_count = 262144
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
EOF
    sysctl -p /etc/sysctl.d/99-unified-stack.conf >/dev/null
}

health_tier_recommend() {
    step "Host-tier recommendation..."
    bash "$REPO_DIR/scripts/health-recommend.sh"
}

validate_env() {
    step "Validating docker compose config..."
    if (cd "$REPO_DIR" && docker compose --env-file "$ENV_FILE" config --quiet); then
        c_grn "compose config OK"
    else
        c_red "compose config FAILED"
        exit 1
    fi
}

print_summary() {
    step "Summary"
    # Read FQDN from the env file for a tailored summary.
    local pub_fqdn tailnet_fqdn
    pub_fqdn=$(grep  '^PUBLIC_FQDN='  "$ENV_FILE" | cut -d= -f2 | tr -d '\r' || echo "yourdomain.com")
    tailnet_fqdn=$(grep '^TAILNET_FQDN=' "$ENV_FILE" | cut -d= -f2 | tr -d '\r' || echo "your-tailnet.ts.net")
    cat <<EOF

Host bootstrapped successfully.

IMPORTANT: Before starting the stack, complete these steps:

  1. Edit ${ENV_FILE} and set the two required external credentials:
       TAILSCALE_AUTHKEY  — from https://login.tailscale.com/admin/settings/keys
       CLOUDFLARE_API_TOKEN — from your Cloudflare API tokens dashboard

  2. All other secrets were generated by gen-secrets.sh above.
     Review ${ENV_FILE} to verify everything looks correct.

  3. Bring up the core stack:
       sudo -u docktaetor bash -c 'cd ${REPO_DIR} && docker compose up --build -d'

  4. (Optional) Media stack:
       sudo -u docktaetor bash -c 'cd ${REPO_DIR} && docker compose --profile media up -d'
       Note: requires PROTONVPN_WIREGUARD_PRIVATE_KEY in ${ENV_FILE}
             and physical media/download paths mounted at MEDIA_PATH/DOWNLOADS_PATH.

  5. (Optional) Productivity stack:
       sudo -u docktaetor bash -c 'cd ${REPO_DIR} && docker compose --profile apps up -d'

After ~2-3 min for healthchecks:
  Core:         https://auth.${pub_fqdn}    (Authentik SSO)
                https://wazuh.${pub_fqdn}   (Wazuh SIEM, gated by Authentik)
                https://cloud.${pub_fqdn}   (Nextcloud, OIDC login via Authentik)
  Tailnet:      https://auth.${tailnet_fqdn}

After Authentik first-run (set MFA, create users), retrieve the outpost token:
  docker exec authentik-server ak shell
  >>> from authentik.core.models import Token
  >>> print(Token.objects.get(identifier__startswith='ak-outpost').key)
  Set AUTHENTIK_OUTPOST_TOKEN in ${ENV_FILE}, then restart authentik-proxy.

OIDC setup — Nextcloud, Tandoor, and AFFiNE (run after Authentik is healthy):
  python3 scripts/setup-oidc.py ${ENV_FILE}

  The script:
    • Provisions OAuth2/OIDC providers and applications in Authentik via API
    • Writes CLIENT_ID, CLIENT_SECRET, and discovery URLs back into ${ENV_FILE}
    • Restarts running containers automatically
    • Writes remaining manual steps to oidc-setup-output.txt

  Remaining manual steps (shown in detail in oidc-setup-output.txt):
    Nextcloud — install the user_oidc app in Nextcloud admin → Apps, then run:
      docker exec --user www-data nextcloud sh -c '
        php occ user_oidc:provider "\$NEXTCLOUD_OIDC_PROVIDER_NAME" \\
          --clientid="\$NEXTCLOUD_OIDC_CLIENT_ID" \\
          --clientsecret="\$NEXTCLOUD_OIDC_CLIENT_SECRET" \\
          --discoveryuri="\$NEXTCLOUD_OIDC_DISCOVERY_URL" \\
          --check-bearer'
    AFFiNE — go to Admin Panel → Settings → OAuth → OIDC provider config and
      paste the JSON from oidc-setup-output.txt (contains live client credentials)

HPB (Nextcloud Talk High-Performance Backend):
  talk.${pub_fqdn}   — nextcloud-spreed-signaling (WebSocket, no Authentik)
  gate.${pub_fqdn}   — janus-gateway admin API (Authentik-gated)
  UDP 20000-20100    — WebRTC media ports (direct to host, UFW allowed)

  Post-deploy: configure Nextcloud Talk → "High-performance backend":
    Signaling server URL:   https://talk.${pub_fqdn}/
    Shared secret:          value of NC_HPB_SHARED_SECRET in ${ENV_FILE}
  Then configure Talk → TURN/STUN:
    docker exec --user www-data nextcloud php occ talk:turn:add \\
      --secret \$COTURN_SECRET turn \$HOST_PUBLIC_IP:3478 udp,tcp

Boot persistence: systemctl status compose-stack.service
Logs:           docker compose logs -f --tail=50
EOF
}

main() {
    require_root
    detect_ubuntu
    apt_upgrade
    install_base_packages
    install_docker
    install_tailscale
    create_user_and_groups
    create_dock_tree
    ensure_env_file
    resolve_public_ip
    copy_templates
    fetch_wazuh_certs_tool
    seed_crowdsec_defaults
    fetch_owasp_crs
    generate_missing_secrets
    configure_hpb
    install_wazuh_agent
    install_cron_jobs
    install_systemd_units
    harden_sshd
    harden_ufw
    kernel_tuning
    health_tier_recommend
    validate_env
    print_summary
    # MFA setup is interactive — run last so non-interactive steps complete first.
    bash "$REPO_DIR/scripts/setup-mfa.sh"
}

main "$@"