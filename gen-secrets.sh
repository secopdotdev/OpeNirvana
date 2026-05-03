#!/usr/bin/env bash
# gen-secrets.sh — populate empty secret vars in .env with cryptographically
# secure 30-character random values. Safe character set: A-Za-z0-9 plus - and _
# (excludes + / $ \ ' " ` # = & | ; < > ! % @ space — all known to break env
# parsing, sed, or application password validators).
#
# Usage:
#   bash scripts/gen-secrets.sh [path/to/.env] [--apply]
#
#   --apply   After generating secrets, apply them to the running stack:
#               - Updates Postgres user passwords (ALTER ROLE) to match new values
#               - Deletes the wazuh-security-init flag so it re-seeds OpenSearch
#               - Restarts wazuh-dashboard to rebuild its keystore
#             Requires the stack to already be running.
#
# Existing non-empty values are NEVER overwritten. Run again safely at any time.

set -euo pipefail

APPLY=false
ENV_FILE=""
for arg in "$@"; do
    if [[ "$arg" == "--apply" ]]; then
        APPLY=true
    else
        ENV_FILE="$arg"
    fi
done
ENV_FILE="${ENV_FILE:-$(dirname "$0")/../.env}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env not found at $ENV_FILE" >&2
    exit 1
fi

# Generate a cryptographically secure random string of the given length.
# Uses /dev/urandom → base64 → strip unsafe chars → trim to length.
gen_secret() {
    local len="${1:-30}"
    LC_ALL=C tr -dc 'A-Za-z0-9_-' < /dev/urandom | head -c "$len"
}

# Set KEY=VALUE in the env file only if the current value is empty.
set_if_empty() {
    local key="$1"
    local value="$2"

    # Match lines like KEY= or KEY=  (trailing space)
    if grep -qE "^${key}=[[:space:]]*$" "$ENV_FILE"; then
        # Use a Python one-liner to avoid sed special-char escaping issues
        python3 - "$ENV_FILE" "$key" "$value" <<'PYEOF'
import sys, re

path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r') as f:
    content = f.read()

content = re.sub(
    rf'^({re.escape(key)}=)\s*$',
    lambda m: f'{m.group(1)}{val}',
    content,
    flags=re.MULTILINE
)

with open(path, 'w') as f:
    f.write(content)
PYEOF
        echo "  SET  $key"
    else
        echo "  SKIP $key (already set)"
    fi
}

echo "Generating secrets for: $ENV_FILE"
echo

# --- Postgres ---
set_if_empty POSTGRES_SUPERUSER_PASSWORD "$(gen_secret 30)"

# --- Redis ---
set_if_empty REDIS_PASSWORD "$(gen_secret 30)"

# --- Wazuh ---
# Wazuh requires: ≥8 chars, upper, lower, digit, special. Our charset satisfies
# upper+lower+digit; append a fixed suffix to guarantee a _ (special) is present.
set_if_empty WAZUH_API_PASSWORD          "$(gen_secret 28)_W"
set_if_empty WAZUH_INDEXER_ADMIN_PASSWORD     "$(gen_secret 28)_W"
set_if_empty WAZUH_INDEXER_KIBANASERVER_PASSWORD "$(gen_secret 28)_W"

# --- Authentik ---
# Secret key: 50 chars is the Authentik recommendation.
set_if_empty AUTHENTIK_SECRET_KEY        "$(gen_secret 50)"
set_if_empty AUTHENTIK_BOOTSTRAP_PASSWORD "$(gen_secret 30)"
set_if_empty AUTHENTIK_BOOTSTRAP_TOKEN   "$(gen_secret 30)"
set_if_empty AUTHENTIK_DB_PASSWORD       "$(gen_secret 30)"

# --- Nextcloud ---
set_if_empty NEXTCLOUD_DB_PASSWORD    "$(gen_secret 30)"
set_if_empty NEXTCLOUD_ADMIN_PASSWORD "$(gen_secret 30)"

# --- Coturn ---
set_if_empty COTURN_SECRET "$(gen_secret 30)"

# --- Tandoor ---
# SECRET_KEY must not change after first run (encrypts sessions).
set_if_empty TANDOOR_DB_PASSWORD  "$(gen_secret 30)"
set_if_empty TANDOOR_SECRET_KEY   "$(gen_secret 50)"

# --- Vikunja ---
# JWT_SECRET must not change after first run (signs user tokens).
set_if_empty VIKUNJA_DB_PASSWORD  "$(gen_secret 30)"
set_if_empty VIKUNJA_JWT_SECRET   "$(gen_secret 50)"

# --- AFFiNE ---
set_if_empty AFFINE_DB_PASSWORD   "$(gen_secret 30)"

# --- Dockhand ---
set_if_empty DOCKHAND_ENCRYPTION_KEY "$(gen_secret 32)"

# --- Immich ---
set_if_empty IMMICH_DB_PASSWORD "$(gen_secret 30)"

# --- n8n ---
# ENCRYPTION_KEY must not change after first run (encrypts stored credentials).
set_if_empty N8N_DB_PASSWORD      "$(gen_secret 30)"
set_if_empty N8N_ENCRYPTION_KEY   "$(gen_secret 32)"

# --- CrowdSec bouncer key ---
# Not randomly generated — must be issued by the CrowdSec container. Requires
# the container to be running. The bouncer name is timestamped so re-runs don't
# collide with existing registrations.
fetch_crowdsec_key() {
    if ! grep -qE "^CROWDSEC_BOUNCER_KEY=[[:space:]]*$" "$ENV_FILE"; then
        echo "  SKIP CROWDSEC_BOUNCER_KEY (already set)"
        return
    fi

    local container="crowdsec"
    if ! docker inspect "$container" &>/dev/null 2>&1; then
        echo "  SKIP CROWDSEC_BOUNCER_KEY (container '$container' not found — run after first bring-up)"
        return
    fi

    local state
    state=$(docker inspect "$container" --format '{{.State.Status}}' 2>/dev/null)
    if [[ "$state" != "running" ]]; then
        echo "  SKIP CROWDSEC_BOUNCER_KEY (container '$container' is $state, not running)"
        return
    fi

    local bouncer_name
    bouncer_name="caddy-$(date +%s)"
    local key
    key=$(docker exec "$container" cscli bouncers add "$bouncer_name" -o raw 2>/dev/null) || true

    if [[ -z "$key" ]]; then
        echo "  SKIP CROWDSEC_BOUNCER_KEY (cscli bouncers add returned empty — check CrowdSec logs)"
        return
    fi

    set_if_empty CROWDSEC_BOUNCER_KEY "$key"
}
fetch_crowdsec_key

echo

if [[ "$APPLY" == true ]]; then
    COMPOSE_DIR="$(dirname "$ENV_FILE")"

    echo "--- Applying secrets to running stack ---"
    echo

    # Update Postgres user passwords to match new .env values.
    # Postgres persists credentials in its data volume; ALTER ROLE syncs them.
    # nextcloud role may not exist yet on first run (created by initdb hook);
    # the || true prevents a hard exit if the role is absent.
    # Strip trailing \r in case .env has CRLF line endings (Windows checkout).
    # cut -d= does not strip \r; python does, but we read with grep here so guard it.
    strip_r() { printf '%s' "$1" | tr -d '\r'; }

    PG_SUPERUSER_PASS=$(strip_r "$(grep '^POSTGRES_SUPERUSER_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    AK_DB_PASS=$(strip_r "$(grep '^AUTHENTIK_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    NC_DB_PASS=$(strip_r "$(grep '^NEXTCLOUD_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    TANDOOR_DB_PASS=$(strip_r "$(grep '^TANDOOR_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    VIKUNJA_DB_PASS=$(strip_r "$(grep '^VIKUNJA_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    AFFINE_DB_PASS=$(strip_r "$(grep '^AFFINE_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    IMMICH_DB_PASS=$(strip_r "$(grep '^IMMICH_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")
    N8N_DB_PASS=$(strip_r "$(grep '^N8N_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2)")

    # Helper: ALTER USER only if the role exists in Postgres.
    alter_pg_user() {
        local user="$1" pass="$2"
        [[ -z "$pass" ]] && return
        docker exec postgres psql -U postgres \
            -c "DO \$\$ BEGIN
                  IF EXISTS (SELECT FROM pg_roles WHERE rolname = '$user') THEN
                    ALTER USER $user PASSWORD '$pass';
                  END IF;
                END \$\$;" 2>/dev/null || true
    }

    if docker inspect postgres &>/dev/null 2>&1 && \
       [[ "$(docker inspect postgres --format '{{.State.Status}}')" == "running" ]]; then
        docker exec postgres psql -U postgres \
            -c "ALTER USER postgres PASSWORD '$PG_SUPERUSER_PASS';"
        alter_pg_user authentik "$AK_DB_PASS"
        alter_pg_user nextcloud "$NC_DB_PASS"
        alter_pg_user tandoor   "$TANDOOR_DB_PASS"
        alter_pg_user vikunja   "$VIKUNJA_DB_PASS"
        alter_pg_user affine    "$AFFINE_DB_PASS"
        alter_pg_user immich    "$IMMICH_DB_PASS"
        alter_pg_user n8n       "$N8N_DB_PASS"
        echo "  APPLIED  Postgres user passwords"
    else
        echo "  SKIP     Postgres not running — start stack first, then re-run with --apply"
    fi

    # Delete the wazuh-security-init flag so the next bring-up re-seeds OpenSearch
    # with the new WAZUH_INDEXER_ADMIN_PASSWORD and WAZUH_INDEXER_KIBANASERVER_PASSWORD.
    WAZUH_CERTS_FLAG="$(grep '^DOCK_CONF=' "$ENV_FILE" | cut -d= -f2)/wazuh/certs/.security-initialized"
    if [[ -f "$WAZUH_CERTS_FLAG" ]]; then
        rm -f "$WAZUH_CERTS_FLAG"
        echo "  REMOVED  $WAZUH_CERTS_FLAG (wazuh-security-init will re-seed on next up)"
    else
        echo "  SKIP     wazuh-security-init flag not present (already clean)"
    fi

    # Re-run wazuh-security-init then restart wazuh-dashboard to rebuild its keystore.
    echo "  RUNNING  wazuh-security-init ..."
    docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d wazuh-security-init \
        --env-file "$ENV_FILE" 2>/dev/null
    until docker inspect wazuh-security-init --format '{{.State.Status}}' \
          2>/dev/null | grep -qE 'exited|dead'; do sleep 3; done
    INIT_EXIT=$(docker inspect wazuh-security-init --format '{{.State.ExitCode}}' 2>/dev/null)
    if [[ "$INIT_EXIT" == "0" ]]; then
        echo "  DONE     wazuh-security-init exited 0"
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d wazuh-dashboard \
            --env-file "$ENV_FILE" 2>/dev/null
        echo "  RESTARTED wazuh-dashboard (rebuilding keystore)"
    else
        echo "  ERROR    wazuh-security-init exited $INIT_EXIT — check: docker logs wazuh-security-init"
    fi

    echo
    echo "Apply complete. Run 'docker compose ps' to verify stack health."
else
    echo "Done. Review $ENV_FILE, then bring up the stack:"
    echo "  docker compose up -d"
    echo
    echo "To also apply secrets to a running stack in one step:"
    echo "  bash scripts/gen-secrets.sh $ENV_FILE --apply"
fi
