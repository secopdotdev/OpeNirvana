#!/usr/bin/env bash
# setup-oidc.sh — Provisions Authentik OAuth2 providers and applications for all
# native-OIDC services (Nextcloud, Tandoor, Vikunja, AFFiNE), then writes the
# generated client credentials and discovery URLs back into .env.
#
# Usage:
#   bash scripts/setup-oidc.sh [path/to/.env]
#   (defaults to /dock/conf/.env)
#
# Prerequisites:
#   - Authentik must be running and healthy
#   - AUTHENTIK_BOOTSTRAP_TOKEN must be set in .env
#   - curl and jq must be installed (apt install -y curl jq)
#
# Idempotent: any service whose CLIENT_ID var is already non-empty is skipped.
# The Authentik provider/application is created regardless of skip — re-running
# after a partial failure is safe (duplicate providers get a numeric suffix from
# Authentik; use the admin UI to clean up orphans if needed).

set -euo pipefail

ENV_FILE="${1:-$(dirname "$0")/../.env}"
ENV_FILE="$(realpath "$ENV_FILE")"
REPO_DIR="$(dirname "$ENV_FILE")"
[ -f "$ENV_FILE" ] || { echo "ERROR: .env not found at $ENV_FILE"; exit 1; }
command -v jq  >/dev/null || { echo "ERROR: jq not installed (apt install -y jq)"; exit 1; }
command -v curl >/dev/null || { echo "ERROR: curl not installed"; exit 1; }

# ── Colour helpers ─────────────────────────────────────────────────────────────
c_red() { printf "\033[31m%s\033[0m\n" "$*"; }
c_grn() { printf "\033[32m%s\033[0m\n" "$*"; }
c_yel() { printf "\033[33m%s\033[0m\n" "$*"; }
step()  { printf "\n\033[36m==> %s\033[0m\n" "$*"; }

# ── Read a single var from .env, stripping inline comments + whitespace ────────
get_var() {
    local val
    val=$(grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-)
    # Strip trailing inline comment and surrounding whitespace
    val="${val%%#*}"
    val="${val#"${val%%[![:space:]]*}"}"   # ltrim
    val="${val%"${val##*[![:space:]]}"}"   # rtrim
    printf '%s' "$val"
}

# ── Write KEY=VALUE only when the current value is blank (or blank + comment) ──
# Mirrors the Python approach in gen-secrets.sh for safe special-char handling.
env_set() {
    local key="$1" val="$2"
    python3 - "$ENV_FILE" "$key" "$val" <<'PYEOF'
import sys, re
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r') as f:
    content = f.read()
# Match: KEY=<optional whitespace><optional # comment><EOL>
pattern = rf'^({re.escape(key)}=)\s*(#[^\n]*)?\s*$'
new, count = re.subn(pattern, lambda m: f'{m.group(1)}{val}', content, flags=re.MULTILINE)
if count:
    with open(path, 'w') as f:
        f.write(new)
    print(f"  wrote  {key}")
else:
    print(f"  skip   {key} (already set)")
PYEOF
}

# ── Load required vars ─────────────────────────────────────────────────────────
PUBLIC_FQDN=$(get_var PUBLIC_FQDN)
TAILNET_FQDN=$(get_var TAILNET_FQDN)
AUTHENTIK_SUBDOMAIN=$(get_var AUTHENTIK_SUBDOMAIN)
TOKEN=$(get_var AUTHENTIK_BOOTSTRAP_TOKEN)

[ -n "$PUBLIC_FQDN" ]      || { c_red "PUBLIC_FQDN not set in $ENV_FILE";            exit 1; }
[ -n "$TOKEN" ]             || { c_red "AUTHENTIK_BOOTSTRAP_TOKEN not set in $ENV_FILE"; exit 1; }
[ -n "$AUTHENTIK_SUBDOMAIN" ] || AUTHENTIK_SUBDOMAIN=auth

AUTHENTIK_URL="https://${AUTHENTIK_SUBDOMAIN}.${PUBLIC_FQDN}"

# Service subdomain vars (fall back to defaults matching .env.example)
NC_SUB=$(get_var NEXTCLOUD_SUBDOMAIN); NC_SUB="${NC_SUB:-cloud}"
TD_SUB=$(get_var TANDOOR_SUBDOMAIN);  TD_SUB="${TD_SUB:-food}"
VK_SUB=$(get_var VIKUNJA_SUBDOMAIN);  VK_SUB="${VK_SUB:-todo}"
AF_SUB=$(get_var AFFINE_SUBDOMAIN);   AF_SUB="${AF_SUB:-note}"

# ── Authentik API helper ───────────────────────────────────────────────────────
ak() {
    local method="$1" path="$2"; shift 2
    curl -fsSL --max-time 15 \
        -X "$method" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "${AUTHENTIK_URL}/api/v3/${path}" \
        "$@"
}

# ── Verify Authentik is reachable ──────────────────────────────────────────────
step "Verifying Authentik is reachable at $AUTHENTIK_URL"
ak GET "core/users/?page_size=1" > /dev/null \
    || { c_red "Cannot reach Authentik API — is the stack healthy?"; exit 1; }
c_grn "  Authentik API OK"

# ── Fetch shared prerequisites ─────────────────────────────────────────────────
step "Fetching authorization flow and signing key"

# Prefer implicit-consent flow; fall back to first available authorization flow.
AUTH_FLOW=$(ak GET "flows/instances/?designation=authorization&ordering=slug" \
    | jq -re '
        (.results[] | select(.slug | test("implicit")) | .pk) // .results[0].pk
    ') || { c_red "No authorization flow found in Authentik"; exit 1; }
c_grn "  authorization flow: $AUTH_FLOW"

SIGNING_KEY=$(ak GET "crypto/certificatekeypairs/?has_key=true&ordering=name" \
    | jq -re '.results[0].pk') \
    || { c_red "No signing key found — generate one in Authentik admin first"; exit 1; }
c_grn "  signing key: $SIGNING_KEY"

# ── Provider + application factory ────────────────────────────────────────────
# Args: <slug> <display_name> <redirect_uris_json> <client_id_var> <client_secret_var>
# redirect_uris_json: JSON array of {"matching_mode":"strict"|"regex","url":"..."}
create_provider_and_app() {
    local slug="$1" name="$2" redirect_uris_json="$3" id_var="$4" secret_var="$5"

    # Skip if CLIENT_ID is already populated
    local existing; existing=$(get_var "$id_var")
    if [ -n "$existing" ]; then
        c_yel "${name}: ${id_var} already set — skipping provider creation"
        return
    fi

    step "${name}: creating OAuth2/OIDC provider"

    local provider
    provider=$(ak POST "providers/oauth2/" -d "$(jq -n \
        --arg  name  "$name" \
        --arg  flow  "$AUTH_FLOW" \
        --arg  key   "$SIGNING_KEY" \
        --argjson uris "$redirect_uris_json" \
        '{
            name:                       $name,
            authorization_flow:         $flow,
            client_type:                "confidential",
            redirect_uris:              $uris,
            signing_key:                $key,
            sub_mode:                   "hashed_user_id",
            include_claims_in_id_token: true
        }')") || { c_red "${name}: provider creation failed"; exit 1; }

    local pk client_id client_secret
    pk=$(            echo "$provider" | jq -re '.pk')
    client_id=$(     echo "$provider" | jq -re '.client_id')
    client_secret=$( echo "$provider" | jq -re '.client_secret')
    c_grn "  provider pk=${pk}  client_id=${client_id}"

    step "${name}: creating application (slug=${slug})"
    ak POST "core/applications/" -d "$(jq -n \
        --arg  name "$name" \
        --arg  slug "$slug" \
        --argjson prov "$pk" \
        '{name: $name, slug: $slug, provider: $prov}')"\
        > /dev/null || { c_red "${name}: application creation failed"; exit 1; }
    c_grn "  application created"

    env_set "$id_var"     "$client_id"
    env_set "$secret_var" "$client_secret"
}

# ── Nextcloud ─────────────────────────────────────────────────────────────────
create_provider_and_app "nextcloud" "Nextcloud" \
    "$(jq -n \
        --arg u1 "https://${NC_SUB}.${PUBLIC_FQDN}/apps/user_oidc/code" \
        --arg u2 "https://${NC_SUB}.${TAILNET_FQDN}/apps/user_oidc/code" \
        '[{matching_mode:"strict",url:$u1},{matching_mode:"strict",url:$u2}]')" \
    NEXTCLOUD_OIDC_CLIENT_ID NEXTCLOUD_OIDC_CLIENT_SECRET

env_set NEXTCLOUD_OIDC_DISCOVERY_URL \
    "https://${AUTHENTIK_SUBDOMAIN}.${PUBLIC_FQDN}/application/o/nextcloud/.well-known/openid-configuration"

# ── Tandoor ───────────────────────────────────────────────────────────────────
create_provider_and_app "tandoor" "Tandoor" \
    "$(jq -n \
        --arg u "https://${TD_SUB}.${PUBLIC_FQDN}/accounts/oidc/authentik/login/callback/" \
        '[{matching_mode:"strict",url:$u}]')" \
    TANDOOR_OIDC_CLIENT_ID TANDOOR_OIDC_CLIENT_SECRET

env_set TANDOOR_OIDC_DISCOVERY_URL \
    "https://${AUTHENTIK_SUBDOMAIN}.${PUBLIC_FQDN}/application/o/tandoor/.well-known/openid-configuration"

# ── Vikunja ───────────────────────────────────────────────────────────────────
create_provider_and_app "vikunja" "Vikunja" \
    "$(jq -n \
        --arg u1 "https://${VK_SUB}.${PUBLIC_FQDN}/auth/openid/authentik" \
        --arg u2 "https://${VK_SUB}.${TAILNET_FQDN}/auth/openid/authentik" \
        --arg u3 '^http://127\.0\.0\.1:[0-9]+/auth/openid/authentik$' \
        '[{matching_mode:"strict",url:$u1},{matching_mode:"strict",url:$u2},{matching_mode:"regex",url:$u3}]')" \
    VIKUNJA_OIDC_CLIENT_ID VIKUNJA_OIDC_CLIENT_SECRET

env_set VIKUNJA_OIDC_AUTH_URL \
    "https://${AUTHENTIK_SUBDOMAIN}.${PUBLIC_FQDN}/application/o/vikunja/"

# ── AFFiNE ────────────────────────────────────────────────────────────────────
create_provider_and_app "affine" "AFFiNE" \
    "$(jq -n \
        --arg u "https://${AF_SUB}.${PUBLIC_FQDN}/oauth/callback" \
        '[{matching_mode:"strict",url:$u}]')" \
    AFFINE_OIDC_CLIENT_ID AFFINE_OIDC_CLIENT_SECRET

env_set AFFINE_OIDC_ISSUER \
    "https://${AUTHENTIK_SUBDOMAIN}.${PUBLIC_FQDN}/application/o/affine/"

# ── Restart services that are currently running ────────────────────────────────
step "Restarting services to apply new credentials"
for svc in nextcloud tandoor vikunja affine; do
    if docker inspect "$svc" &>/dev/null \
       && [ "$(docker inspect "$svc" --format '{{.State.Status}}')" = "running" ]; then
        (cd "$REPO_DIR" && docker compose --env-file "$ENV_FILE" \
            up -d --no-deps --force-recreate "$svc") \
            && c_grn "  restarted $svc" \
            || c_yel "  $svc restart failed — restart manually"
    else
        c_yel "  $svc not running — start it after setting credentials"
    fi
done

# ── Print remaining manual steps ───────────────────────────────────────────────
cat <<EOF

$(printf "\033[36m==> Two manual steps still required:\033[0m")

  1. NEXTCLOUD — install the 'user_oidc' app in Nextcloud admin → Apps, then run:
       docker exec --user www-data nextcloud sh -c '
         php occ user_oidc:provider "\$NEXTCLOUD_OIDC_PROVIDER_NAME" \\
           --clientid="\$NEXTCLOUD_OIDC_CLIENT_ID" \\
           --clientsecret="\$NEXTCLOUD_OIDC_CLIENT_SECRET" \\
           --discoveryuri="\$NEXTCLOUD_OIDC_DISCOVERY_URL" \\
           --check-bearer'

  2. AFFINE — go to Admin Panel → Settings → OAuth → OIDC provider config and paste:
       {"args":{},"issuer":"$(get_var AFFINE_OIDC_ISSUER)","clientId":"$(get_var AFFINE_OIDC_CLIENT_ID)","clientSecret":"$(get_var AFFINE_OIDC_CLIENT_SECRET)"}

EOF
c_grn "setup-oidc.sh complete."
