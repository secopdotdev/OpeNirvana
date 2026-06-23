#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 24.04+ host for the unified-stack compose.
# Idempotent: safe to re-run. Never overwrites existing user data or .env values.
set -euo pipefail

# Colour output helpers.
c_red()  { printf "\033[31m%s\033[0m\n" "$*"; }
c_grn()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yel()  { printf "\033[33m%s\033[0m\n" "$*"; }
c_blu()  { printf "\033[34m%s\033[0m\n" "$*"; }
step()   { printf "\n\033[36m==> %s\033[0m\n" "$*"; }

# Read a value from an .env-style file, stripping inline `# comment` suffixes
# and surrounding whitespace. The old approach (`cut -d= -f2- | tr -d '[:space:]\r'`)
# silently concatenated the comment into the value when .env lines have trailing
# documentation — e.g. `PUBLIC_FQDN=example.com   # The zone CF manages`. That
# produced corrupted secrets and URLs in rendered configs.
#
# Usage: env_get <KEY> [path]   (defaults to $ENV_FILE)
# Prints the value to stdout, empty if absent.
env_get() {
    local key="$1" file="${2:-$ENV_FILE}"
    # Strip only `<whitespace>#<comment>` so a `#` inside a value (no leading
    # whitespace, e.g. random secrets) is preserved. Then trim ends.
    awk -v k="$key" '
        $0 ~ "^"k"=" {
            sub("^"k"=", "")
            sub(/[ \t]+#.*$/, "")
            sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "")
            print; exit
        }
    ' "$file"
}

# Edit a directive in an OpenSSH-style config file in place.
# Handles commented (#Directive val) and uncommented (Directive val) forms.
# Appends the directive if absent.
sshd_config_set() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$file"; then
        sed -i -E "s|^#?[[:space:]]*(${key})[[:space:]].*|\1 ${val}|" "$file"
    else
        echo "${key} ${val}" >> "$file"
    fi
}

# Script lives in unified-stack/scripts/. REPO_DIR is the stack root (one up),
# which is where docker-compose.yml, .env, templates/, and run.sh live.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_DIR/.env"
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
    if [ "$major" -lt 24 ]; then
        c_red "Ubuntu $VERSION_ID is too old; require 24.04+ (Python 3.11+ for stdlib tomllib)."
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
        python3 python3-pip \
        libpam-google-authenticator qrencode
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

install_python_packages() {
    step "Installing Python packages for scripts..."
    # --break-system-packages is required on Ubuntu 23+ (PEP 668); absent on 22.04's pip.
    local pip_flags=()
    pip3 install --help 2>&1 | grep -q '\-\-break-system-packages' \
        && pip_flags=(--break-system-packages)

    _pip_install() {
        local pkg="$1" desc="$2"
        if pip3 show "$pkg" >/dev/null 2>&1; then
            c_grn "  $pkg already installed"
        else
            local out
            # On Ubuntu 23+ with mixed apt/pip environments, pip may fail to uninstall
            # apt-managed packages (no RECORD file). Retry with --no-deps so deps
            # already provided by apt satisfy requirements at runtime.
            out=$(pip3 install --quiet "${pip_flags[@]}" "$pkg" 2>&1) || {
                if echo "$out" | grep -qi 'RECORD file not found\|no-record-file\|installed by debian'; then
                    pip3 install --quiet "${pip_flags[@]}" --no-deps "$pkg"
                else
                    echo "$out" >&2
                    return 1
                fi
            }
            c_grn "  installed $pkg ($desc)"
        fi
    }

    _pip_install msal  "set-auth.py entra-* — Microsoft Entra ID federation"
    _pip_install dtop  "Docker container monitoring TUI"
    _pip_install hvac  "bao-*.py — OpenBao/Vault client (ADR 0002)"
}

create_user_and_groups() {
    step "Creating svc-user:media (1010:1010)..."
    if ! getent group media >/dev/null; then
        groupadd -g 1010 media
    fi
    if ! id svc-user >/dev/null 2>&1; then
        useradd -m -u 1010 -g 1010 -s /bin/bash svc-user
    fi
    usermod -aG docker svc-user || true

    # The operator who runs run.sh (this script's sudo invoker) must ALSO reach
    # the docker socket: run.sh invokes `docker compose` as that user, not as the
    # svc-user service account. Adding only svc-user (above) left the real
    # deploy user (e.g. admin on prod-host) unable to talk to
    # /var/run/docker.sock. Derive the operator from $SUDO_USER so this is
    # host-agnostic and idempotent (usermod -aG is additive, safe to re-run).
    local _operator="${SUDO_USER:-}"
    if [[ -n "$_operator" && "$_operator" != "root" && "$_operator" != "svc-user" ]]; then
        usermod -aG docker "$_operator" || true
        c_grn "  added operator '$_operator' to docker group"
    fi
}

# Returns 0 if <user> already has a Docker Hub (index.docker.io) credential.
_docker_hub_authed() {
    local u="$1" home
    home=$(getent passwd "$u" | cut -d: -f6)
    [[ -n "$home" && -f "$home/.docker/config.json" ]] || return 1
    grep -q 'index\.docker\.io' "$home/.docker/config.json" 2>/dev/null
}

configure_docker_registry_auth() {
    step "Authenticating to Docker Hub (docker.io)..."
    # WHY: the stack pulls ~50 images from Docker Hub; anonymous pulls hit the
    # 100-per-6h rate limit and abort `compose up`. An authenticated login draws
    # on the operator's account budget instead. `docker login` is PER-USER and
    # PER-registry-hostname, so we authenticate every user that runs docker compose:
    #   svc-user — the compose-stack.service account (systemd User=svc-user)
    #   $SUDO_USER — the operator who runs run.sh's `docker compose` directly
    # BOOTSTRAP-CLEARTEXT (deliberate): the token comes from .env, not OpenBao —
    # OpenBao's own image must be pulled before it can serve secrets (chicken/egg).
    # Use a PULL-SCOPED Docker Hub access token, never the account password.
    local hub_user hub_token
    hub_user=$(env_get DOCKERHUB_USERNAME)
    hub_token=$(env_get DOCKERHUB_TOKEN)

    # No creds supplied: preserve any existing interactive login (e.g. a host that
    # was logged in by hand) rather than failing or clobbering it.
    if [[ -z "$hub_user" || -z "$hub_token" ]]; then
        if _docker_hub_authed svc-user; then
            c_grn "  no DOCKERHUB_TOKEN in .env; svc-user already authenticated — preserved"
        else
            c_yel "  no DOCKERHUB_USERNAME/DOCKERHUB_TOKEN in .env and no existing login;"
            c_yel "  Docker Hub pulls will be anonymous and may hit the rate limit."
        fi
        return 0
    fi

    # Build the unique user set (svc-user + operator, deduped, never root).
    local users=("svc-user") u home
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" && "$SUDO_USER" != "svc-user" ]]; then
        users+=("$SUDO_USER")
    fi
    for u in "${users[@]}"; do
        id "$u" >/dev/null 2>&1 || { c_yel "  user $u missing; skipping"; continue; }
        home=$(getent passwd "$u" | cut -d: -f6)
        # runuser drops privileges; `env HOME=` forces the credential into the
        # target user's ~/.docker/config.json (runuser does not set HOME without -l).
        if printf '%s' "$hub_token" \
            | runuser -u "$u" -- env HOME="$home" docker login -u "$hub_user" --password-stdin >/dev/null 2>&1; then
            c_grn "  $u authenticated to docker.io"
        else
            c_red "  docker login failed for $u — check DOCKERHUB_USERNAME/DOCKERHUB_TOKEN"
        fi
    done
}

create_dock_tree() {
    step "Creating /dock tree..."
    local dirs=(
        /dock/conf/caddy/{snippets,coraza/rules,data,logs,souin}
        /dock/conf/crowdsec/{notifications,db,hub}
        /dock/conf/socket-proxy-ro
        /dock/conf/socket-proxy-rw
        /dock/conf/authentik/{media,custom-templates,certs}
        /dock/conf/falco/rules.d
        /dock/conf/zeek/{intel,logs}
        /dock/conf/cloudflare
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
        # Media stack data
        /dock/data/jellyfin
        # Productivity stack data
        /dock/data/ntfy/{cache,data}
        /dock/data/tandoor/{media,static}
        /dock/data/vikunja
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
    # appendonly).
    if [ -z "$(ls -A /dock/db/postgres/data 2>/dev/null)" ]; then
        chown -R 1010:1010 /dock
        find /dock -type d -exec chmod 770 {} +
    fi
    # ── Per-service ownership (ADR-0014) ──────────────────────────────────────
    # Everything above leaves the tree at the 1010:1010 / mode-770 baseline. The
    # exceptions below — services that run as other UIDs (openbao=100, nextcloud=33,
    # authentik/tandoor/vikunja/n8n=1000, prometheus/alertmanager=65534, loki=10001,
    # grafana=472, alloy=473, zeek-logs=1010, ntfy=root, couchdb=5984) or need tighter
    # modes (openbao/db=700) — are now DATA in profiles.toml [[ownership]], emitted
    # by `profiles.py --ownership-manifest` and applied here in one idempotent loop.
    # This ends the whack-a-mole: a non-1010 service declares its ownership at
    # catalog-edit time instead of CrashLooping on first deploy until someone
    # appends another chown. The numeric `chown` below (not `install -d -o <uid>`)
    # is deliberate — fixed container UIDs like loki=10001 have no host passwd
    # entry, and GNU `install -o` calls getpwnam and would abort on them.
    #
    # Fail loud (ADR-0014): a missing profiles.py or malformed TOML aborts host
    # prep — never a silent fall-back to partial/old ownership.
    local _ownership
    if ! _ownership="$(python3 "$REPO_DIR/scripts/profiles.py" --ownership-manifest)"; then
        c_red "FATAL: profiles.py --ownership-manifest failed — aborting host prep (ADR-0014 fail-loud)"
        exit 1
    fi
    if [ -z "$_ownership" ]; then
        c_red "FATAL: ownership manifest is empty — aborting host prep (ADR-0014 fail-loud)"
        exit 1
    fi
    # Columns: path<TAB>uid<TAB>gid<TAB>mode<TAB>chown_recursive<TAB>chmod_recursive
    # uid/gid/mode == "-" leaves that dimension at the baseline (a mode-only entry
    # keeps the 1010 owner; a chown-only entry keeps mode 770). The recursion flags
    # preserve the exact -R vs top-only behaviour of the original lines (openbao
    # chowns -R but chmods top-only; ntfy does both -R; observability neither).
    local _path _uid _gid _mode _crec _mrec
    while IFS=$'\t' read -r _path _uid _gid _mode _crec _mrec; do
        [ -n "$_path" ] || continue
        mkdir -p "$_path"
        if [ "$_uid" != "-" ]; then
            if [ "$_crec" = "1" ]; then chown -R "$_uid:$_gid" "$_path"; else chown "$_uid:$_gid" "$_path"; fi
        fi
        if [ "$_mode" != "-" ]; then
            if [ "$_mrec" = "1" ]; then chmod -R "$_mode" "$_path"; else chmod "$_mode" "$_path"; fi
        fi
    done <<< "$_ownership"
}

copy_templates() {
    step "Copying templates to /dock/conf/..."
    local src="$REPO_DIR/templates"
    [ -d "$src" ] || { c_red "Missing $src"; exit 1; }
    # Rsync-style: copy only if target absent, never overwrite local edits.
    # Exclude templates/openbao/ — it has a non-trivial mount path and is handled
    # explicitly below (the compose service mounts /dock/conf/openbao/config, not
    # /dock/conf/openbao directly, so a generic dst=/dock/conf/openbao/... install
    # would land in the wrong place).
    find "$src" -type f -not -path "$src/openbao/*" | while read -r f; do
        local rel="${f#"$src"/}"
        local dst="/dock/conf/${rel}"
        if [ ! -f "$dst" ]; then
            install -D -o 1010 -g 1010 -m 640 "$f" "$dst"
        fi
    done
    # Postgres init scripts go under /dock/db/postgres/init.d/ — copy ALL of them
    # (00-create-app-dbs.sh provisions roles/DBs; 01-immich-extensions.sh creates
    # the superuser-only extensions immich needs). Always refresh so script fixes
    # propagate to the host copy that postgres mounts.
    if [ -d "$src/postgres/init.d" ]; then
        for initf in "$src"/postgres/init.d/*.sh; do
            [ -e "$initf" ] || continue
            install -D -o 1010 -g 1010 -m 750 \
                "$initf" "/dock/db/postgres/init.d/$(basename "$initf")"
        done
    fi
    # Render interpolated configs that can't be envsubst'd at container runtime.
    # Zeek reads /etc/zeek/node.cfg at startup and needs lb_procs as a bare integer
    # and the sniff interface as a bare device name.
    local zeek_node=/dock/conf/zeek/node.cfg
    if [ -f "$zeek_node" ] && grep -qE '\$\{ZEEK_WORKER_COUNT|\$\{ZEEK_INTERFACE' "$zeek_node"; then
        local count=4
        local iface_setting=auto
        if [ -f "$ENV_FILE" ]; then
            count=$(env_get ZEEK_WORKER_COUNT)
            [ -n "$count" ] || count=4
            # ZEEK_INTERFACES is a space-separated list; take the first token.
            iface_setting=$(env_get ZEEK_INTERFACES | awk '{print $1}')
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
    # OpenBao HCL config — explicit install because the compose mount path differs
    # from the generic template tree layout:
    #   templates/openbao/openbao.hcl  (source)
    #   /dock/conf/openbao/config/openbao.hcl  (target, mounted :ro at /openbao/config)
    # The generic find-loop above would copy to /dock/conf/openbao/openbao.hcl which
    # is wrong — the container only reads from the /config sub-directory.
    local bao_hcl_src="$src/openbao/openbao.hcl"
    local bao_hcl_dst="/dock/conf/openbao/config/openbao.hcl"
    if [ -f "$bao_hcl_src" ]; then
        if [ ! -f "$bao_hcl_dst" ]; then
            install -m 0644 "$bao_hcl_src" "$bao_hcl_dst"
            c_grn "  installed openbao/config/openbao.hcl"
        fi
    else
        c_yel "  WARN: templates/openbao/openbao.hcl not found — OpenBao HCL not installed."
        c_yel "        Create it before starting the openbao container."
    fi
}

# Sync the Caddyfile + snippets from templates/ into /dock/conf/caddy and
# reload Caddy if anything changed. The caddy container reads
# /etc/caddy/Caddyfile + /etc/caddy/snippets/ which are bind-mounted from
# /dock/conf/caddy. copy_templates() only seeds these on a fresh host —
# this function is for propagating template changes to existing hosts.
# Idempotent: no-op when files are byte-identical.
sync_caddy_config() {
    step "Syncing Caddy config from templates/..."
    local src="$REPO_DIR/templates/caddy"
    [ -d "$src" ] || { c_red "Missing $src"; return 1; }
    local changed=0
    # Sync top-level Caddyfile + every file under snippets/ + coraza/ + build/
    # is intentionally excluded (image content). We sync exactly the files the
    # container bind-mounts.
    install -d -o 1010 -g 1010 -m 750 /dock/conf/caddy/snippets /dock/conf/caddy/coraza
    while IFS= read -r f; do
        local rel="${f#"$src"/}"
        # Skip the build context — it's baked into the image, not bind-mounted.
        # Skip cf-origin-mtls.caddy — render_cf_origin_mtls owns it (active vs
        # no-op depends on host AOP state); a blind copy of the no-op template
        # would revert a provisioned snippet and drop mTLS.
        case "$rel" in
            build/*) continue ;;
            snippets/cf-origin-mtls.caddy) continue ;;
        esac
        local dst="/dock/conf/caddy/${rel}"
        install -d -o 1010 -g 1010 -m 750 "$(dirname "$dst")"
        if [ ! -f "$dst" ] || ! cmp -s "$f" "$dst"; then
            install -o 1010 -g 1010 -m 640 "$f" "$dst"
            c_grn "  updated /dock/conf/caddy/${rel}"
            changed=1
        fi
    done < <(find "$src" -type f)
    if [ "$changed" -eq 1 ]; then
        if docker ps --format '{{.Names}}' | grep -qx caddy; then
            # Validate first — invalid config leaves the container running.
            if ! docker exec caddy caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
                c_red "Caddy config failed validation; not restarting. Run:"
                c_red "  docker exec caddy caddy validate --config /etc/caddy/Caddyfile"
                return 1
            fi
            # `caddy reload` is graceful but does NOT cleanly apply changes to
            # the middleware chain (e.g. removing an `import` that wraps the
            # response). Empirically observed corrupting WS upgrades through
            # talk.{$PUBLIC_FQDN} until the container was restarted in full.
            # Restart drops in-flight connections briefly — acceptable for a
            # config-sync step that only runs on template changes.
            docker restart caddy >/dev/null 2>&1 \
                && c_grn "Caddy restarted (config change applied)" \
                || c_yel "Caddy restart failed"
        fi
    else
        c_grn "Caddy config already up to date."
    fi
}

# Sync CouchDB local.d config from templates/ into /dock/conf/couchdb/local.d.
# The dir AND files must be owned by uid 5984 (the container runs as 5984:5984
# with cap_drop:ALL, so it cannot chown at runtime) and the dir must be WRITABLE
# by 5984 — the official entrypoint writes its own docker.ini (admin creds) into
# this same dir at every boot. Idempotent: only re-installs files that changed.
sync_couchdb_config() {
    step "Syncing CouchDB config from templates/..."
    local src="$REPO_DIR/templates/couchdb/local.d"
    [ -d "$src" ] || { c_yel "No $src; skipping CouchDB config sync"; return 0; }
    # 5984 owns the dir (rwx) so the entrypoint can write docker.ini alongside ours.
    install -d -o 5984 -g 5984 -m 700 /dock/conf/couchdb/local.d
    while IFS= read -r f; do
        local rel="${f#"$src"/}"
        local dst="/dock/conf/couchdb/local.d/${rel}"
        install -d -o 5984 -g 5984 -m 700 "$(dirname "$dst")"
        if [ ! -f "$dst" ] || ! cmp -s "$f" "$dst"; then
            install -o 5984 -g 5984 -m 640 "$f" "$dst"
            c_grn "  updated /dock/conf/couchdb/local.d/${rel}"
        else
            # copy_templates runs first and lays every template down as 1010:1010
            # (640). The couchdb container runs as 5984 and reads its config as owner,
            # so enforce 5984:5984 + 640 even when the content is byte-identical —
            # otherwise the gate above skips the install and couchdb crashes on a
            # config-read eacces. Ownership must not be gated on content change.
            chown 5984:5984 "$dst"
            chmod 640 "$dst"
        fi
    done < <(find "$src" -type f)
}

# ADR-0020 Layer 1: render the Cloudflare origin-pull mTLS snippet from host AOP
# state. The template snippet ships EMPTY (no-op) so Caddy always boots; this
# function activates client_auth ONLY when an origin-pull trust anchor exists,
# and reverts to the no-op when it does not. Idempotent (byte-compare + validate
# before restart). Standalone-dispatchable; called from main() (after
# sync_caddy_config) and from provision_origin_pull on success.
render_cf_origin_mtls() {
    step "Rendering Cloudflare origin-pull mTLS snippet (ADR-0020 Layer 1)..."
    local snip=/dock/conf/caddy/snippets/cf-origin-mtls.caddy
    local ca_dst=/dock/conf/caddy/snippets/cf-origin-pull-ca.pem
    local op_dir=/dock/conf/cloudflare/origin-pull
    # Trust anchor: an explicit CA (CA-signed client cert) wins; otherwise the
    # self-signed client cert is its own anchor.
    local anchor=""
    if [ -s "$op_dir/ca.pem" ]; then
        anchor="$op_dir/ca.pem"
    elif [ -s "$op_dir/client.pem" ]; then
        anchor="$op_dir/client.pem"
    fi
    install -d -o 1010 -g 1010 -m 750 /dock/conf/caddy/snippets
    local tmp; tmp="$(mktemp)"
    if [ -n "$anchor" ]; then
        # Deliver the trust anchor into the (bind-mounted) snippets dir;
        # `import snippets/*.caddy` ignores the .pem so it is never parsed.
        install -o 1010 -g 1010 -m 640 "$anchor" "$ca_dst"
        printf '%s\n' \
            '# RENDERED by docker-host-config.sh:render_cf_origin_mtls — do not edit by hand.' \
            '# Active: an origin-pull trust anchor was found. Reverts to no-op when removed.' \
            '# Mode staged via {$CLOUDFLARE_MTLS_MODE} (compose default = request).' \
            '(cf-origin-mtls) {' \
            $'\tclient_auth {' \
            $'\t\tmode {$CLOUDFLARE_MTLS_MODE:request}' \
            $'\t\ttrust_pool file {' \
            $'\t\t\tpem_file /etc/caddy/snippets/cf-origin-pull-ca.pem' \
            $'\t\t}' \
            $'\t}' \
            '}' > "$tmp"
    else
        rm -f "$ca_dst"
        printf '%s\n' \
            '# RENDERED by docker-host-config.sh:render_cf_origin_mtls — do not edit by hand.' \
            '# No-op: no origin-pull trust anchor at /dock/conf/cloudflare/origin-pull/.' \
            '# Provide ca.pem (or self-signed client.pem) + run provision_origin_pull.' \
            '(cf-origin-mtls) {' \
            '}' > "$tmp"
    fi
    local state; state="$([ -n "$anchor" ] && echo "active — mTLS on" || echo "no-op — mTLS off")"
    if [ -f "$snip" ] && cmp -s "$tmp" "$snip"; then
        rm -f "$tmp"
        c_grn "  cf-origin-mtls snippet already current (${state})."
        return 0
    fi
    install -o 1010 -g 1010 -m 640 "$tmp" "$snip"
    rm -f "$tmp"
    c_grn "  cf-origin-mtls snippet rendered (${state})."
    # Apply to a running caddy: validate then restart (reload does not cleanly
    # re-apply tls/middleware changes — same caveat as sync_caddy_config).
    if docker ps --format '{{.Names}}' | grep -qx caddy; then
        if ! docker exec caddy caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
            c_red "Caddy config failed validation after rendering cf-origin-mtls; not restarting."
            c_red "  docker exec caddy caddy validate --config /etc/caddy/Caddyfile"
            return 1
        fi
        docker restart caddy >/dev/null 2>&1 \
            && c_grn "Caddy restarted (cf-origin-mtls applied)" \
            || c_yel "Caddy restart failed"
    fi
}

# Generate the Dashy dashboard from live discovery (Caddyfile routes + .env
# subdomains) and install it. Idempotent: only restarts dashy when the rendered
# conf.yml actually changed. The generator is the source of truth — there is no
# static templates/dashy/conf.yml anymore.
render_dashy() {
    step "Generating Dashy dashboard from discovery..."
    local dst=/dock/conf/dashy/conf.yml
    # dashy runs as uid 1000 (node); the conf is public service URLs (no
    # secrets), so the dir is traversable (755) and the file world-readable
    # (644) — otherwise dashy can't read its own config and silently falls
    # back to the default dashboard.
    install -d -o 1010 -g 1010 -m 755 "$(dirname "$dst")"
    if python3 "$REPO_DIR/scripts/gen-dashy-config.py" -o "$dst.new" \
            --env "$ENV_FILE" --caddyfile "$REPO_DIR/templates/caddy/Caddyfile" >/dev/null; then
        if [ -f "$dst" ] && cmp -s "$dst.new" "$dst"; then
            c_grn "Dashy conf.yml already up to date."
            rm -f "$dst.new"
            # Enforce perms even on no-op (self-heal a previously wrong mode).
            chown 1010:1010 "$dst" 2>/dev/null || true
            chmod 644 "$dst" 2>/dev/null || true
        else
            install -o 1010 -g 1010 -m 644 "$dst.new" "$dst"
            rm -f "$dst.new"
            c_grn "Rendered Dashy conf.yml"
            docker ps --format '{{.Names}}' | grep -qx dashy \
                && docker restart dashy >/dev/null 2>&1 \
                && c_grn "Restarted dashy" || true
        fi
    else
        c_red "gen-dashy-config.py failed; left existing conf.yml in place."
        rm -f "$dst.new"
    fi
}

# Generate the Grafana "Observability" dashboards and refresh the provisioned
# datasource file. Grafana auto-reloads provisioning every 30s, so no container
# restart is needed — just write current files. Files are world-readable (644);
# they contain no secrets.
render_grafana() {
    step "Generating Grafana observability dashboards..."
    local prov=/dock/conf/grafana/provisioning/dashboards/observability
    install -d -o 1010 -g 1010 -m 755 "$prov"
    if python3 "$REPO_DIR/scripts/gen-grafana-dashboards.py" -o "$prov" >/dev/null; then
        chown -R 1010:1010 "$prov" 2>/dev/null || true
        chmod 644 "$prov"/*.json 2>/dev/null || true
        c_grn "Rendered Grafana observability dashboards"
    else
        c_red "gen-grafana-dashboards.py failed."
    fi
    # Keep the provisioned Prometheus datasource (uid pin) current.
    local ds_src="$REPO_DIR/templates/grafana/provisioning/datasources/prometheus.yml"
    local ds=/dock/conf/grafana/provisioning/datasources/prometheus.yml
    if [ -f "$ds_src" ]; then
        install -o 1010 -g 1010 -m 644 "$ds_src" "$ds"
    fi
}

configure_hpb() {
    step "Configuring HPB (nextcloud-spreed-signaling + janus-gateway)..."

    # Warn if public IP is not configured — required for Janus NAT mapping.
    local pub_ip
    pub_ip=$(env_get HOST_PUBLIC_IP)
    if [ -z "$pub_ip" ]; then
        c_red "WARNING: HOST_PUBLIC_IP is not set in $ENV_FILE"
        c_red "  Set it to this server's public IP address before deploying janus-gateway."
        c_red "  janus.jcfg will be rendered with an empty nat_1_1_mapping — WebRTC will NOT work."
    fi

    local tmpl_dir="$REPO_DIR/templates"

    # --- nextcloud-spreed-signaling/server.conf ---
    # Always render to tmp + diff against current — the template can change
    # (e.g. new backend URL, debug flag) and we need every host to pick that
    # up. Falling back to a "placeholders gone → assume rendered" sentinel
    # silently keeps stale configs on long-lived hosts.
    local ss_conf=/dock/conf/spreed-signaling/server.conf
    local hash_key block_key shared_secret janus_api_secret nc_sub nc_fqdn nc_pub_url
    hash_key=$(env_get NC_HPB_HASH_KEY)
    block_key=$(env_get NC_HPB_BLOCK_KEY)
    shared_secret=$(env_get NC_HPB_SHARED_SECRET)
    janus_api_secret=$(env_get JANUS_API_SECRET)
    nc_sub=$(env_get NEXTCLOUD_SUBDOMAIN)
    nc_fqdn=$(env_get PUBLIC_FQDN)
    nc_pub_url="${nc_sub}.${nc_fqdn}"
    install -d -o root -g root -m 755 "$(dirname "$ss_conf")"
    # shellcheck disable=SC2016
    NC_HPB_HASH_KEY="$hash_key" NC_HPB_BLOCK_KEY="$block_key" \
    NC_HPB_SHARED_SECRET="$shared_secret" JANUS_API_SECRET="$janus_api_secret" \
    NEXTCLOUD_PUBLIC_URL="$nc_pub_url" \
        envsubst '${NC_HPB_HASH_KEY} ${NC_HPB_BLOCK_KEY} ${NC_HPB_SHARED_SECRET} ${JANUS_API_SECRET} ${NEXTCLOUD_PUBLIC_URL}' \
        < "$tmpl_dir/spreed-signaling/server.conf" > "$ss_conf.new"
    if [ -f "$ss_conf" ] && cmp -s "$ss_conf.new" "$ss_conf"; then
        c_grn "spreed-signaling/server.conf already up to date."
        rm -f "$ss_conf.new"
    else
        # 644: spreed-signaling drops from root to an unprivileged user at startup;
        # the dropped user needs "other" read access since the file is root:root.
        install -o root -g root -m 644 "$ss_conf.new" "$ss_conf"
        rm -f "$ss_conf.new"
        c_grn "Rendered spreed-signaling/server.conf"
        # Restart spreed-signaling so the new config takes effect. Best-effort —
        # if the container isn't up yet (first deploy) the up command later will
        # pick up the new config naturally.
        if docker ps --format '{{.Names}}' | grep -qx spreed-signaling; then
            docker restart spreed-signaling >/dev/null 2>&1 \
                && c_grn "Restarted spreed-signaling" \
                || c_yel "Could not restart spreed-signaling (will pick up new config on next deploy)"
        fi
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
        janus_api_secret=$(env_get JANUS_API_SECRET)
        janus_admin_secret=$(env_get JANUS_ADMIN_SECRET)
        # shellcheck disable=SC2016
        JANUS_API_SECRET="$janus_api_secret" JANUS_ADMIN_SECRET="$janus_admin_secret" \
        HOST_PUBLIC_IP="$pub_ip" \
            envsubst '${JANUS_API_SECRET} ${JANUS_ADMIN_SECRET} ${HOST_PUBLIC_IP}' \
            < "$tmpl_dir/janus/janus.jcfg" > "$janus_jcfg.new"
        # 644: janus runs as root with cap_drop:ALL; without DAC_OVERRIDE it cannot
        # read svc-user-owned files. root:root 644 lets any UID read the config.
        install -o root -g root -m 644 "$janus_jcfg.new" "$janus_jcfg"
        rm -f "$janus_jcfg.new"
        c_grn "Rendered janus/janus.jcfg (nat_1_1_mapping=${pub_ip:-UNSET})"
    fi

    # --- janus-gateway/janus.transport.http.jcfg (no template vars) ---
    local janus_http=/dock/conf/janus/janus.transport.http.jcfg
    if [ ! -f "$janus_http" ]; then
        # 644: same cap_drop:ALL / no DAC_OVERRIDE reason as janus.jcfg above.
        install -o root -g root -m 644 \
            "$tmpl_dir/janus/janus.transport.http.jcfg" "$janus_http"
        c_grn "Installed janus/janus.transport.http.jcfg"
    else
        # copy_templates() may have laid this down as 1010:1010 640 — always fix.
        chown root:root "$janus_http"
        chmod 644 "$janus_http"
        c_grn "janus/janus.transport.http.jcfg already present (perms ensured root:root 644)."
    fi
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
        # Copy .env.example; keep ownership with the git-repo owner (SUDO_USER or current),
        # not with svc-user, so the user running docker compose can read secrets.
        local repo_owner
        repo_owner=$(stat -c '%U' "$REPO_DIR" 2>/dev/null || echo "${SUDO_USER:-$(id -un)}")
        install -D -o "$repo_owner" -g "$repo_owner" -m 600 "$REPO_DIR/.env.example" "$ENV_FILE"
        c_grn "Created $ENV_FILE from .env.example (owned by ${repo_owner})"
    fi
}

resolve_public_ip() {
    step "Resolving host public IP..."

    # Skip if already set to a non-empty value.
    local current
    current=$(env_get HOST_PUBLIC_IP)
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

    python3 "$REPO_DIR/scripts/gen-secrets.py" "$ENV_FILE" --set "HOST_PUBLIC_IP=$ip"
    c_grn "HOST_PUBLIC_IP resolved and set: $ip"
}

generate_missing_secrets() {
    step "Generating missing secrets..."
    python3 "$REPO_DIR/scripts/gen-secrets.py" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    # Keep ownership with the repo user so docker compose (running as that user) can read it.
    local repo_owner
    repo_owner=$(stat -c '%U' "$REPO_DIR" 2>/dev/null || echo "${SUDO_USER:-$(id -un)}")
    chown "${repo_owner}:${repo_owner}" "$ENV_FILE"
}

install_cron_jobs() {
    step "Installing cron jobs..."
    cat > /etc/cron.d/unified-stack <<EOF
# Unified-stack scheduled jobs
MAILTO=""
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

0 2 * * *    root python3 ${REPO_DIR}/scripts/maintain.py all >> /var/log/maintain.log 2>&1
*/15 * * * * root python3 ${REPO_DIR}/scripts/maintain.py cloudflare >> /dock/conf/cloudflare/maintain-cloudflare.log 2>&1
# ADR-0020 Layer 3: weekly refresh of the Cloudflare CIDR allowlist. refresh_cf_ufw
# re-runs maintain.py cloudflare-cidrs (updates cf-cidrs.txt + .env CLOUDFLARE_CIDRS,
# fail-closed) then re-applies the 80/443 allows WITHOUT a ufw reset (no fail-open
# window); the caddy restart reloads Layer 2's CLOUDFLARE_CIDRS env. Sun 03:30.
30 3 * * 0   root bash ${REPO_DIR}/scripts/docker-host-config.sh refresh_cf_ufw >> /dock/conf/cloudflare/maintain-cloudflare.log 2>&1 && docker restart caddy >> /dock/conf/cloudflare/maintain-cloudflare.log 2>&1
EOF
    chmod 644 /etc/cron.d/unified-stack
}

install_logrotate_cloudflare() {
    step "Installing cloudflare logrotate config..."
    cat > /etc/logrotate.d/cloudflare <<'EOF'
/dock/conf/cloudflare/firewall-events.log
/dock/conf/cloudflare/maintain-cloudflare.log {
    weekly
    rotate 4
    copytruncate
    missingok
    notifempty
    compress
}
EOF
    chmod 644 /etc/logrotate.d/cloudflare
    c_grn "cloudflare logrotate config installed."
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
User=svc-user
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

    sshd_config_set "$cfg" SyslogFacility       AUTH
    sshd_config_set "$cfg" LogLevel              INFO
    sshd_config_set "$cfg" LoginGraceTime        2m
    sshd_config_set "$cfg" PermitRootLogin       no
    sshd_config_set "$cfg" MaxAuthTries          3
    sshd_config_set "$cfg" MaxSessions           5
    sshd_config_set "$cfg" AuthorizedKeysFile    ".ssh/authorized_keys"
    sshd_config_set "$cfg" AllowAgentForwarding  yes
    sshd_config_set "$cfg" PrintLastLog          yes
    sshd_config_set "$cfg" X11Forwarding         yes
    sshd_config_set "$cfg" PubkeyAuthentication  yes
    sshd_config_set "$cfg" HostbasedAuthentication yes

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

# Add the CF-origin 80/443 allow rules (one set per Cloudflare CIDR) plus the
# optional EXTRA_ALLOWED_IP escape-hatch. Tolerant of a single malformed line so
# a bad CIDR cannot abort the caller mid-rebuild (which under `set -e` would
# leave ufw disabled, i.e. fail-OPEN). Returns non-zero only if NOT ONE valid
# CIDR produced a rule (total failure) — the caller then keeps 80/443 closed.
_ufw_allow_cf_origin() {
    local cidr_file="$1" extra="$2" cidr n=0
    while IFS= read -r cidr; do
        cidr="${cidr%%#*}"; cidr="${cidr//[[:space:]]/}"
        [ -z "$cidr" ] && continue
        if ufw allow from "$cidr" to any port 80 proto tcp >/dev/null \
        && ufw allow from "$cidr" to any port 443 proto tcp >/dev/null \
        && ufw allow from "$cidr" to any port 443 proto udp >/dev/null; then
            n=$((n + 1))
        else
            c_yel "  WARN: skipped invalid CF CIDR '$cidr'"
        fi
    done < "$cidr_file"
    if [ -n "$extra" ]; then
        if ufw allow from "$extra" to any port 80 proto tcp  >/dev/null \
        && ufw allow from "$extra" to any port 443 proto tcp >/dev/null \
        && ufw allow from "$extra" to any port 443 proto udp >/dev/null; then
            c_grn "  EXTRA_ALLOWED_IP '$extra' allowed on 80/443"
        else
            c_yel "  WARN: EXTRA_ALLOWED_IP '$extra' rejected by ufw — ignored"
        fi
    fi
    [ "$n" -gt 0 ] || { c_red "  FATAL: no valid CF CIDR yielded a ufw rule."; return 1; }
}

# ADR-0020 Layer 3 (corrected mechanism): the ufw INPUT allowlist above CANNOT
# filter Docker's DNAT-published 80/443 — those packets traverse
# PREROUTING->FORWARD->DOCKER-USER->DOCKER-FORWARD and are ACCEPTed there, never
# entering INPUT where `ufw allow` rules live. This programs the DOCKER-USER chain
# (FORWARD rule #1, Docker's user hook) so non-Cloudflare traffic to the public web
# ingress is dropped at the kernel before any TLS compute — fulfilling L3's intent
# for the containerized ingress. ufw INPUT still governs host-mode services (coturn,
# Zeek). Keys on the WAN interface (not the container IP): IP-agnostic across
# redeploys, and Tailnet/inter-container traffic is excluded by construction (it
# never arrives `-i <WAN>` — Tailnet is delivered into the ingress netns over
# WireGuard). Idempotent (delete-by-comment, then append). FAIL-OPEN: a missing CIDR
# list SKIPS the DROP rather than locking out the origin — a coarse pre-filter must
# never be the layer that severs ingress; L1 mTLS is the real control.
_docker_user_lock_cf_origin() {
    local cidr_file="$1" extra="$2" dry="${3:-}" tag="cf-origin-l3" cidr n=0
    local wan; wan="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    [ -n "$wan" ] || { c_red "  FATAL: cannot determine WAN interface (default route)."; return 1; }
    if [ ! -s "$cidr_file" ]; then
        c_yel "  WARN: $cidr_file empty/missing — skipping DOCKER-USER origin lock (fail-open; L1 mTLS unaffected)."
        return 1
    fi
    local ipt="iptables"
    if [ "$dry" = "--dry-run" ]; then
        ipt="echo   iptables"
        c_grn "  DRY-RUN — DOCKER-USER rules for WAN=$wan (no mutation):"
    else
        # Idempotent: strip any rules a prior run added (matched by our comment).
        while iptables -L DOCKER-USER -n 2>/dev/null | grep -q "$tag"; do
            local ln; ln="$(iptables -L DOCKER-USER --line-numbers -n 2>/dev/null | awk -v t="$tag" '$0 ~ t {print $1; exit}')"
            [ -n "$ln" ] && iptables -D DOCKER-USER "$ln" || break
        done
    fi
    # 1. Established/related flows continue (cheap safety net).
    $ipt -A DOCKER-USER -i "$wan" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$tag" -j RETURN
    $ipt -A DOCKER-USER -i "$wan" -p udp --dport 443 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$tag" -j RETURN
    # 2. Allow each Cloudflare CIDR (the only legitimate public-origin source).
    #    IPv6 CIDRs are skipped: this is the IPv4 chain, the origin is IPv4-only
    #    (no global v6 on the WAN iface, no v6 DNAT) so there is no v6 ingress path.
    #    A public AAAA / v6 origin would require an ip6tables variant (re-eval trigger).
    while IFS= read -r cidr; do
        cidr="${cidr%%#*}"; cidr="${cidr//[[:space:]]/}"; [ -z "$cidr" ] && continue
        case "$cidr" in *:*) continue ;; esac
        if $ipt -A DOCKER-USER -i "$wan" -s "$cidr" -p tcp -m multiport --dports 80,443 -m comment --comment "$tag" -j RETURN \
        && $ipt -A DOCKER-USER -i "$wan" -s "$cidr" -p udp --dport 443 -m comment --comment "$tag" -j RETURN; then
            n=$((n + 1))
        else
            c_yel "  WARN: skipped invalid CF CIDR '$cidr'"
        fi
    done < "$cidr_file"
    # 3. EXTRA_ALLOWED_IP escape hatch (operator/LAN vantage that must reach origin direct).
    if [ -n "$extra" ]; then
        $ipt -A DOCKER-USER -i "$wan" -s "$extra" -p tcp -m multiport --dports 80,443 -m comment --comment "$tag" -j RETURN
        $ipt -A DOCKER-USER -i "$wan" -s "$extra" -p udp --dport 443 -m comment --comment "$tag" -j RETURN
    fi
    # 4. Tailnet CGNAT (belt-and-suspenders; Tailnet does not normally arrive -i WAN).
    $ipt -A DOCKER-USER -i "$wan" -s 100.64.0.0/10 -p tcp -m multiport --dports 80,443 -m comment --comment "$tag" -j RETURN
    # 5. Drop all other (non-CF) traffic to the public web ingress; DROP not REJECT
    #    so the port does not advertise itself to scanners.
    $ipt -A DOCKER-USER -i "$wan" -p tcp -m multiport --dports 80,443 -m comment --comment "$tag" -j DROP
    $ipt -A DOCKER-USER -i "$wan" -p udp --dport 443 -m comment --comment "$tag" -j DROP
    [ "$n" -gt 0 ] || { c_red "  FATAL: no valid CF CIDR yielded a DOCKER-USER rule."; return 1; }
    [ "$dry" = "--dry-run" ] || c_grn "  DOCKER-USER: 80/443 on $wan locked to $n CF CIDRs${extra:+ + $extra} (ADR-0020 L3)"
}

# Standalone-dispatchable wrapper for the DOCKER-USER origin lock
# (`docker-host-config.sh lock_cf_origin_forward`). Set CF_L3_DRYRUN=1 to preview
# the iptables rules without mutating (skips the CIDR refresh and prints only).
lock_cf_origin_forward() {
    step "Locking DNAT'd public 80/443 to Cloudflare in DOCKER-USER (ADR-0020 Layer 3)..."
    local extra cidr_file="/dock/conf/cloudflare/cf-cidrs.txt"
    [ -n "${CF_L3_DRYRUN:-}" ] || python3 "${REPO_DIR}/scripts/maintain.py" cloudflare-cidrs || true
    extra="$(env_get EXTRA_ALLOWED_IP)"
    _docker_user_lock_cf_origin "$cidr_file" "$extra" "${CF_L3_DRYRUN:+--dry-run}"
}

# ADR-0020 Layer 3: the kernel firewall only admits 80/443 from Cloudflare edge
# CIDRs (+ optional EXTRA_ALLOWED_IP). Recovery rules (22, tailscale0) and the
# WebRTC ports are added BEFORE the CF loop and `ufw --force enable` runs
# unconditionally, so a partial CF-rule failure still ends with a default-deny
# firewall UP and the recovery path intact — never disabled/open.
# Re-runnable standalone (`docker-host-config.sh harden_ufw`); the weekly cron
# uses it to re-apply the refreshed CF allowlist.
harden_ufw() {
    step "Configuring UFW (Cloudflare-only 80/443, ADR-0020 Layer 3)..."
    local extra rc=0 cidr_file="/dock/conf/cloudflare/cf-cidrs.txt"
    # Ensure the CF CIDR allowlist exists before locking down 80/443. `|| true`:
    # a transient fetch failure must not abort — maintain.py is fail-closed and
    # leaves the last-good cf-cidrs.txt in place, which the check below honours.
    python3 "${REPO_DIR}/scripts/maintain.py" cloudflare-cidrs || true
    if [ ! -s "$cidr_file" ]; then
        c_red "FATAL: $cidr_file empty/missing after refresh; refusing to open 80/443 to all (fail-closed)."
        c_red "  Run: python3 ${REPO_DIR}/scripts/maintain.py cloudflare-cidrs  then retry."
        return 1
    fi
    extra="$(env_get EXTRA_ALLOWED_IP)"

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    # Recovery + management FIRST so any later error still leaves these in place.
    ufw allow 22/tcp
    # ufw allow from 198.51.100.20/24 to any port 22 proto tcp # Lock SSH to a fixed LAN if you never roam — can lock you out otherwise.
    ufw allow in on tailscale0
    # coturn TURN/STUN — required for Nextcloud Talk WebRTC relay.
    # 3478 is the signalling port; 49152:49200 is the relay port range.
    ufw allow 3478/tcp
    ufw allow 3478/udp
    ufw allow 49152:49200/udp
    # Janus Gateway — WebRTC media ports for Nextcloud Talk HPB.
    ufw allow 20000:20100/udp
    # Public origin: 80/443 reachable ONLY from Cloudflare edge CIDRs.
    _ufw_allow_cf_origin "$cidr_file" "$extra" || rc=1
    # Bring the firewall UP unconditionally — even on a partial CF-rule failure
    # the host ends default-deny + recovery, never disabled/open.
    ufw --force enable
    if [ "$rc" -ne 0 ]; then
        c_red "UFW is up with recovery rules, but the Cloudflare origin allowlist is incomplete — 80/443 stay closed. Investigate $cidr_file."
        return 1
    fi
    c_grn "UFW: 80/443 restricted to $(grep -c '[^[:space:]]' "$cidr_file") Cloudflare CIDRs${extra:+ + $extra}"
    # L3 for the DNAT'd containerized ingress: ufw INPUT (above) cannot see
    # Docker-published 80/443; the DOCKER-USER chain (FORWARD) can. Fail-open.
    _docker_user_lock_cf_origin "$cidr_file" "$extra" \
        || c_yel "  DOCKER-USER origin lock not applied (see WARN) — L1 mTLS remains the control."
}

# ADR-0020 Layer 3 weekly refresh — re-apply the Cloudflare 80/443 allowlist
# WITHOUT a `ufw --force reset`, so there is NO fail-open window on the live
# host (reset disables ufw for the whole rule-add loop — seconds of default-
# ACCEPT every week). `ufw allow` is idempotent: existing rules are a no-op, so
# this only ADDS rules for newly-published CF CIDRs. A CIDR that Cloudflare
# *removed* leaves a stale allow until the next full harden_ufw (host-prep /
# deploy) — a bounded, known risk backstopped by Layers 1 (AOP mTLS) + 2 (Caddy
# remote_ip), unlike a recurring open window over unknown published ports.
# Used by the weekly cron; safe to run repeatedly against a live firewall.
refresh_cf_ufw() {
    step "Refreshing Cloudflare UFW allowlist (no reset, ADR-0020 Layer 3)..."
    local extra cidr_file="/dock/conf/cloudflare/cf-cidrs.txt"
    python3 "${REPO_DIR}/scripts/maintain.py" cloudflare-cidrs || true
    if [ ! -s "$cidr_file" ]; then
        c_red "FATAL: $cidr_file empty/missing after refresh; leaving existing ufw rules untouched (fail-closed)."
        return 1
    fi
    extra="$(env_get EXTRA_ALLOWED_IP)"
    _ufw_allow_cf_origin "$cidr_file" "$extra"
    # Re-apply the DOCKER-USER lock too (idempotent) so the weekly refresh keeps
    # the FORWARD-path allowlist in sync with newly-published CF CIDRs.
    _docker_user_lock_cf_origin "$cidr_file" "$extra" \
        || c_yel "  DOCKER-USER origin lock not refreshed (see WARN) — L1 mTLS remains the control."
}

# ADR-0020 Layer 1: provision Cloudflare Authenticated Origin Pulls (AOP) from the
# host .env using the vendored cf-origin-pull tool. Reads the token via the
# fall-through model (CLOUDFLARE_ORIGIN_TLS_RW_TOKEN -> CLOUDFLARE_API_TOKEN) from .env —
# no Windows/kms dependency. Standalone-dispatchable
# (`docker-host-config.sh provision_origin_pull`); NOT auto-run in main() because
# enabling AOP is an externally-visible, lockout-capable CF mutation that must
# follow the staged request->require rollout (STAGE -> PAUSE -> SUBMIT). Guarded +
# fail-safe: a missing cert/key/token or an API failure logs and returns 0 so it
# never aborts the bootstrap.
provision_origin_pull() {
    step "Provisioning Cloudflare Authenticated Origin Pulls (AOP, ADR-0020 Layer 1)..."
    local op_dir="/dock/conf/cloudflare/origin-pull"
    local cert="${op_dir}/client.pem" key="${op_dir}/client.key"
    # Create the drop location (root-owned, 700) so the operator knows where the
    # openssl-generated client cert/key go — the key is sensitive.
    mkdir -p "$op_dir" && chmod 700 "$op_dir"
    local fqdn; fqdn="$(env_get PUBLIC_FQDN)"
    if [ -z "$fqdn" ]; then
        c_yel "  skipped — PUBLIC_FQDN not set in ${ENV_FILE}"
        return 0
    fi
    if [ ! -s "$cert" ] || [ ! -s "$key" ]; then
        c_yel "  skipped — origin-pull client cert/key not found at ${op_dir}/client.{pem,key}"
        c_yel "  Generate them (openssl), set CLOUDFLARE_ORIGIN_TLS_RW_TOKEN (or CLOUDFLARE_API_TOKEN) in"
        c_yel "  ${ENV_FILE}, then re-run: sudo bash scripts/docker-host-config.sh provision_origin_pull"
        return 0
    fi
    # cf-origin-pull resolves the token from .env (fall-through, never logged) and
    # is idempotent (ensure_origin_pull dedupes by normalized cert).
    if python3 "${REPO_DIR}/scripts/cf-origin-pull.py" \
            --store env --env-path "${ENV_FILE}" \
            --fqdn "$fqdn" --cert-file "$cert" --key-file "$key" --enable; then
        c_grn "  AOP provisioned + enabled for the zone of ${fqdn}"
        # Activate the Caddy origin-mTLS snippet now that the trust anchor exists.
        render_cf_origin_mtls
    else
        c_yel "  AOP provisioning did not complete (token scope needs Zone:SSL and Certificates:Edit?)."
        c_yel "  Deploy continues; re-run after fixing. Caddy must stay in CLOUDFLARE_MTLS_MODE=request until AOP is confirmed."
    fi
    return 0
}

kernel_tuning() {
    step "Applying kernel tuning..."
    cat > /etc/sysctl.d/99-unified-stack.conf <<'EOF'
net.ipv4.ip_forward = 1
vm.max_map_count = 262144
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
# cadvisor + the many watch-heavy containers (loki, alloy, prometheus, autoheal)
# exhaust the default inotify limits on a dense host: cadvisor dies with
# "inotify_init: too many open files" (exit 255). Raise instances + watches.
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 1048576
EOF
    sysctl -p /etc/sysctl.d/99-unified-stack.conf >/dev/null
}

health_tier_recommend() {
    step "Host-tier recommendation..."

    local cpus mem_gb tier
    cpus=$(nproc)
    mem_gb=$(awk '/MemTotal/ {printf "%d\n", $2/1024/1024}' /proc/meminfo)

    if [ "$mem_gb" -ge 48 ] && [ "$cpus" -ge 12 ]; then
        tier="HIGH"
    elif [ "$mem_gb" -ge 14 ] && [ "$cpus" -ge 6 ]; then
        tier="MED"
    else
        tier="LOW"
    fi

    printf "    CPUs: %s\n    RAM:  %s GB\n\nRecommended tier: %s\n\nEdit .env: uncomment the %s tier block, comment the others.\n" \
        "$cpus" "$mem_gb" "$tier" "$tier"
}

setup_mfa() {
    step "MFA setup (TOTP + SSH key hardening)..."

    local mfa_user mfa_home sshd_cfg pam_sshd key_path
    mfa_user=${SUDO_USER:-$(id -un)}
    mfa_home=$(getent passwd "$mfa_user" | cut -d: -f6)
    sshd_cfg=/etc/ssh/sshd_config
    pam_sshd=/etc/pam.d/sshd
    key_path="${mfa_home}/.ssh/id_ed25519"

    # MFA/SSH-hardening is inherently interactive (QR scan, yes/no choices). If there
    # is no controlling terminal (unattended/CI, e.g. run.sh -y piping bootstrap),
    # skip cleanly instead of blocking forever on the read prompts below.
    if [ ! -t 0 ]; then
        c_yel "No interactive terminal — skipping MFA / SSH-hardening setup."
        c_yel "Run 'sudo ${0##*/} setup_mfa' from an interactive shell when ready."
        return
    fi

    _mfa_wall_of_shame() {
        echo
        c_red "╔══════════════════════════════════════════════════════════════════╗"
        c_red "║                     ⚠  SECURITY WARNING  ⚠                      ║"
        c_red "╠══════════════════════════════════════════════════════════════════╣"
        c_red "║  Password authentication remains enabled on this host.           ║"
        c_red "║  This makes it susceptible to brute-force and credential-        ║"
        c_red "║  stuffing attacks.                                                ║"
        c_red "║                                                                   ║"
        c_red "║  Re-run docker-host-config.sh when you are ready to disable it.  ║"
        c_red "╚══════════════════════════════════════════════════════════════════╝"
        echo
    }

    # Upload a public SSH key to the operator's GitHub account as an AUTHENTICATION
    # key (Settings → SSH and GPG keys → Authentication keys; the /user/keys
    # endpoint, NOT the signing-key endpoint). Prefers `gh` when authenticated;
    # otherwise prompts for a token used once. SECURITY: the token is read hidden,
    # never written to disk, and never placed in argv — it is fed to curl through a
    # `-K -` stdin config so it cannot appear in /proc/<pid>/cmdline or `ps`.
    _github_add_key() {
        local user="$1" pub_file="$2"
        local host title pub
        host=$(hostname -f 2>/dev/null || hostname)
        title="${user}@${host} (host-config)"
        pub=$(cat "$pub_file")

        # gh path: uses the user's own gh auth/keyring; no token handling here.
        if command -v gh >/dev/null 2>&1 && sudo -u "$user" gh auth status >/dev/null 2>&1; then
            if sudo -u "$user" gh ssh-key add "$pub_file" --title "$title" --type authentication; then
                c_grn "Public key added to GitHub via gh."
            else
                c_yel "gh ssh-key add did not succeed (key may already be present) — continuing."
            fi
            return
        fi

        echo
        c_blu "Paste a GitHub token with 'write:public_key' (classic PAT) or the"
        c_blu "fine-grained 'Git SSH keys: Write' permission. It is used once, never stored."
        local token
        read -rs -p "GitHub token (input hidden, blank to skip): " token; echo
        if [ -z "$token" ]; then
            c_yel "No token entered — skipping GitHub upload."
            return
        fi

        local body resp_file http
        body=$(jq -cn --arg t "$title" --arg k "$pub" '{title:$t, key:$k}')
        resp_file=$(mktemp)
        # Token via -K - (stdin config) so it never reaches argv; body holds only
        # the public key + title (no secret), so --data on the command line is fine.
        http=$(printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -sS -K - \
            -o "$resp_file" -w '%{http_code}' \
            -X POST \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            --data "$body" \
            https://api.github.com/user/keys)
        unset token
        case "$http" in
            201) c_grn "Public key added to GitHub." ;;
            422) if grep -qi "already" "$resp_file"; then
                     c_grn "Key already on your GitHub account — nothing to do."
                 else
                     c_red "GitHub rejected the key (422):"; cat "$resp_file"
                 fi ;;
            401|403) c_red "GitHub auth failed (${http}) — token lacks 'write:public_key' / 'Git SSH keys: Write'." ;;
            *)   c_red "Unexpected GitHub response (${http}):"; cat "$resp_file" ;;
        esac
        rm -f "$resp_file"
    }

    # ── TOTP ──────────────────────────────────────────────────────────────────
    if [ -f "${mfa_home}/.google_authenticator" ]; then
        c_grn "TOTP already configured for ${mfa_user} — skipping"
    else
        local want_mfa win_in
        # Script-level gate: "no" here actually means NO MFA. (Answering "n" to
        # google-authenticator's own "time-based?" prompt only switches to HOTP —
        # it does not decline setup, which is what confused operators previously.)
        read -r -p "Set up TOTP MFA (authenticator app) for ${mfa_user}? (y/n): " want_mfa
        if [[ ! "$want_mfa" =~ ^[Yy]$ ]]; then
            c_yel "Skipping TOTP MFA setup for ${mfa_user}."
            _mfa_wall_of_shame
            return
        fi

        # Configurable validation window: number of concurrently-valid 30s codes.
        # google-authenticator accepts 1-21 (-w); we accept 1-20 per ops request.
        local ga_window=3
        read -r -p "TOTP validation window — concurrently-valid 30s codes (1-20) [3]: " win_in
        if [ -n "$win_in" ]; then
            if [[ "$win_in" =~ ^[0-9]+$ ]] && [[ "$win_in" -ge 1 ]] && [[ "$win_in" -le 20 ]]; then
                ga_window="$win_in"
            else
                c_yel "Invalid window '${win_in}' (must be 1-20) — using default ${ga_window}."
            fi
        fi

        local mfa_fqdn
        mfa_fqdn=$(hostname -f 2>/dev/null || hostname)
        c_blu "Generating TOTP secret for ${mfa_user} (QR renders locally; secret never leaves this host)..."
        echo
        # Deterministic, non-interactive TOTP:
        #   -t time-based   -f write-without-confirm   -C skip the verify-code prompt
        #   -d disallow reuse   -r 3 -R 30 rate-limit   -w window   -e 5 emergency codes
        #   -Q NONE suppress the tool's own QR output.
        # NOTE: -f alone is NOT non-interactive — it still blocks on the verify-code
        # prompt; -C is what suppresses it.
        # SECURITY: the Ubuntu-packaged google-authenticator does NOT use libqrencode
        # at runtime, so `-Q UTF8` silently falls back to printing a
        # https://www.google.com/chart?...secret=... URL that leaks the OTP secret to
        # Google. We force -Q NONE and render the QR ourselves from the otpauth URI
        # with the standalone `qrencode` CLI, so the secret stays entirely on-host.
        sudo -u "$mfa_user" google-authenticator \
            -t -f -C -d -r 3 -R 30 -w "$ga_window" -e 5 -Q NONE

        if [ ! -f "${mfa_home}/.google_authenticator" ]; then
            c_red "${mfa_home}/.google_authenticator not found — TOTP setup was not completed."
            _mfa_wall_of_shame
            return
        fi

        # Render the enrollment QR locally (no network, no Google). The base32 secret
        # is the first line of the secret file; build a standard otpauth:// URI.
        local ga_secret otpauth_uri
        ga_secret=$(sudo -u "$mfa_user" head -n1 "${mfa_home}/.google_authenticator")
        otpauth_uri="otpauth://totp/${mfa_user}@${mfa_fqdn}?secret=${ga_secret}&issuer=${mfa_fqdn}"
        if command -v qrencode >/dev/null 2>&1; then
            echo
            c_blu "=== Scan this QR with your authenticator app (rendered locally) ==="
            # Feed the URI via stdin — NOT as an argv — so the base32 secret is never
            # visible in /proc/<pid>/cmdline or `ps` while qrencode runs.
            printf '%s' "$otpauth_uri" | qrencode -t ANSIUTF8 -
        else
            # qrencode is a hard dependency (install_base_packages). If it is somehow
            # absent, fail loudly rather than print the raw secret to stdout/logs.
            c_red "qrencode not installed — cannot render the enrollment QR safely."
            c_red "Install it and re-enroll: apt-get install -y qrencode; rm ${mfa_home}/.google_authenticator; sudo ${0##*/} setup_mfa"
            unset ga_secret otpauth_uri
            return 1
        fi
        unset ga_secret otpauth_uri
        c_grn "TOTP setup complete. Scan the QR above, then store the emergency scratch codes safely."
    fi

    echo
    # ── SSH key ───────────────────────────────────────────────────────────────
    local gen_key disable_pass add_gh
    read -r -p "Generate SSH key for ${mfa_user} and display public key? (y/n): " gen_key
    if [[ "$gen_key" =~ ^[Yy]$ ]]; then
        install -d -o "$mfa_user" -m 700 "${mfa_home}/.ssh"
        if [ -f "$key_path" ]; then
            c_yel "Key already exists at ${key_path} — skipping generation."
        else
            sudo -u "$mfa_user" ssh-keygen -t ed25519 -f "$key_path" -N ""
            c_grn "Key generated."
        fi
        echo
        c_blu "=== Public key — add to ~/.ssh/authorized_keys on connecting clients ==="
        cat "${key_path}.pub"
        echo

        # ── Optional: register the public key on GitHub ───────────────────────
        read -r -p "Add this public key to your GitHub account now? (y/n): " add_gh
        if [[ "$add_gh" =~ ^[Yy]$ ]]; then
            _github_add_key "$mfa_user" "${key_path}.pub"
        fi
        echo

        # ── Disable password auth ─────────────────────────────────────────────
        read -r -p "Disable password authentication (key + TOTP only)? (y/n): " disable_pass
        if [[ "$disable_pass" =~ ^[Yy]$ ]]; then
            sshd_config_set "$sshd_cfg" PasswordAuthentication         no
            sshd_config_set "$sshd_cfg" KbdInteractiveAuthentication   yes

            if grep -q 'pam_google_authenticator.so' "$pam_sshd"; then
                c_grn "pam_google_authenticator.so already in ${pam_sshd}"
            else
                echo 'auth required pam_google_authenticator.so' >> "$pam_sshd"
                c_grn "Added pam_google_authenticator.so to ${pam_sshd}"
            fi

            if ! sshd -t -f "$sshd_cfg"; then
                c_red "sshd_config validation failed — NOT restarting. Fix ${sshd_cfg} manually."
                return 1
            fi

            systemctl daemon-reload
            systemctl restart ssh.socket
            c_grn "SSH restarted. Password authentication is now disabled."
            c_yel "IMPORTANT: Keep this session open and verify key+TOTP login works in a new terminal before closing."
        else
            _mfa_wall_of_shame
        fi
    else
        _mfa_wall_of_shame
    fi
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
    tailnet_fqdn=$(grep '^TAILNET_FQDN=' "$ENV_FILE" | cut -d= -f2 | tr -d '\r' || echo "your-tailnet.example")
    cat <<EOF

Host bootstrapped successfully.

IMPORTANT: Before starting the stack, complete these steps:

  1. Edit ${ENV_FILE} and set the two required external credentials:
       TAILSCALE_AUTHKEY  — from https://login.tailscale.com/admin/settings/keys
       CLOUDFLARE_API_TOKEN — from your Cloudflare API tokens dashboard

  2. All other secrets were generated by gen-secrets.py above.
     Review ${ENV_FILE} to verify everything looks correct.

  3. Bring up the core stack:
       sudo -u svc-user bash -c 'cd ${REPO_DIR} && docker compose up --build -d'

  4. (Optional) Media stack:
       sudo -u svc-user bash -c 'cd ${REPO_DIR} && docker compose --profile media up -d'
       Note: requires PROTONVPN_WIREGUARD_PRIVATE_KEY in ${ENV_FILE}
             and physical media/download paths mounted at MEDIA_PATH/DOWNLOADS_PATH.

  5. (Optional) Productivity stack:
       sudo -u svc-user bash -c 'cd ${REPO_DIR} && docker compose --profile apps up -d'

After ~2-3 min for healthchecks:
  Core:         https://auth.${pub_fqdn}    (Authentik SSO)
                https://cloud.${pub_fqdn}   (Nextcloud, OIDC login via Authentik)
  Tailnet:      https://auth.${tailnet_fqdn}

After Authentik first-run (set MFA, create users), retrieve the outpost token:
  docker exec authentik-server ak shell
  >>> from authentik.core.models import Token
  >>> print(Token.objects.get(identifier__startswith='ak-outpost').key)
  Set AUTHENTIK_OUTPOST_TOKEN in ${ENV_FILE}, then restart authentik-proxy.

OIDC setup — Nextcloud, Tandoor, Jellyfin, Immich, Vikunja, Komodo
(run after Authentik is healthy):
  python3 scripts/set-auth.py --env ${ENV_FILE} oidc

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
    install_python_packages
    install_docker
    install_tailscale
    create_user_and_groups
    create_dock_tree
    ensure_env_file
    configure_docker_registry_auth
    resolve_public_ip
    copy_templates
    sync_caddy_config
    render_cf_origin_mtls
    sync_couchdb_config
    render_dashy
    render_grafana
    seed_crowdsec_defaults
    fetch_owasp_crs
    generate_missing_secrets
    configure_hpb
    install_cron_jobs
    install_logrotate_cloudflare
    install_systemd_units
    harden_sshd
    harden_ufw
    kernel_tuning
    health_tier_recommend
    validate_env
    print_summary
    setup_mfa
}

# Allow targeted re-runs of individual idempotent steps without doing the full
# bootstrap, e.g. `sudo ./docker-host-config.sh configure_hpb` to re-render the
# HPB configs after a template change. Falls through to full main() if the arg
# isn't a known function name.
if [ $# -eq 1 ] && declare -f "$1" > /dev/null; then
    require_root
    "$1"
else
    main "$@"
fi