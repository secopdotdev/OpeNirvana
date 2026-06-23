#!/usr/bin/env bash
# unified-stack/run.sh — Bootstrap, update, and deploy the unified Docker Compose stack.
#
# Locates the git repository on this machine (or clones it if missing), pulls
# the latest code or release tag, then runs docker compose. Optional setup
# helpers are invoked interactively or driven entirely by flags.
#
# Invoked via the repo-root ./run.sh shim, which exec's into this script.
#
# Usage:
#   bash run.sh [OPTIONS]                # from anywhere on the system (via repo root)
#   ./run.sh [OPTIONS]                   # from within unified-stack/
#
# OPTIONS:
#   -h, --help              Show this help and exit
#   -y, --yes               Auto-accept all optional steps (non-interactive/CI)
#   -n, --no-prompt         Skip all optional steps without asking
#
#   --repo URL              Git clone URL (default: auto-detected or prompted)
#   --dir PATH              Repository root to use or clone into
#   --branch BRANCH         Branch to deploy (default: main)
#   --tag TAG               Checkout this release tag; "latest" resolves newest
#
#   --profile PROFILE       Override STACK_PROFILES with this fine profile or bundle
#                           (repeatable). Valid: any profile/bundle (profiles.py --list).
#                           Default: read STACK_PROFILES from .env
#
#   --env SOURCE            Copy SOURCE file as .env before deploying
#   --copy-env              Copy .env.example → .env if .env is missing
#   --gen-secrets           Run scripts/gen-secrets.py [--apply if stack is up]
#   --sync-env              Run scripts/sync-env.py to pull new vars into .env
#   --fix-perms             Run scripts/fix-permissions.sh (requires sudo/root)
#   --tailscale             Run set-auth.py tailscale BEFORE deploying: push Tailscale ACL
#                           (non-destructive merge, preserves operator rules) and create a
#                           reusable auth key tagged tag:ingress,tag:docker if TAILSCALE_AUTHKEY
#                           is blank. Requires TAILSCALE_OAUTH_CLIENT_ID + TAILSCALE_OAUTH_API_KEY
#                           in .env. Auto-triggered by -y when TAILSCALE_OAUTH_CLIENT_ID is set.
#   --oidc                  Run set-auth.py oidc after deploying
#   --setup-authentik       Run set-auth.py authentik after deploying (safe non-interactively)
#   --nextcloud-oidc        Run set-auth.py nextcloud-oidc after deploying
#   --entra-sync            Run maintain.py entra-sync after deploying (safe non-interactively)
#   --entra-setup           Run set-auth.py entra-setup (interactive; never used by -y)
#
#   --check-stack           After deploy, run scripts/check-stack.py (health audit)
#   --audit-access          After deploy, run scripts/audit-user-access.py if
#                           AUTHENTIK_USER_ACCESS_TOKEN is set (access audit)
#   -d, --doctor            Diagnostics-only: skip git/env/deploy/auth-setup; run
#                           container status + check-stack + audit-user-access +
#                           log tails of any unhealthy containers, then exit.
#
#   --no-pull               Skip git pull/checkout (deploy current local state)
#   --build                 Pass --build to docker compose (rebuild images)
#   --down                  docker compose down before up (full redeploy)
#   --dry-run               Print what would run without executing deploy steps
#
# SAFE TO RE-RUN AT ANY TIME:
#   This script is fully idempotent and non-destructive at every stage of
#   deployment. Running it against a live stack will not interrupt running
#   containers, overwrite secrets, or reset configuration. "docker compose up -d"
#   is a no-op for services already up-to-date. Auth setup steps check before
#   writing. Re-running on a healthy stack is safe and leaves it unchanged.

set -euo pipefail

# ── Color helpers ───────────────────────────────────────────────────────────────
c_bold() { printf "\033[1m%s\033[0m\n"  "$*"; }
c_grn()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yel()  { printf "\033[33m%s\033[0m\n" "$*"; }
c_red()  { printf "\033[31m%s\033[0m\n" "$*" >&2; }
c_cyn()  { printf "\033[36m%s\033[0m\n" "$*"; }
c_hdr()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }

die()    { c_red "error: $*"; exit 1; }

# ── Privilege context ────────────────────────────────────────────────────────────
# Detect `sudo bash run.sh` and snapshot the real caller's identity. All git/gh/
# python/cp operations run via _as_user() to preserve SSH keys and GitHub auth
# tokens. docker compose and fix-permissions.sh deliberately stay at root.
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    _REAL_USER="$SUDO_USER"
    _REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    _REAL_UID="$(id -u "$SUDO_USER")"
    _SUDO_ELEVATED=true
    _REAL_PATH="${PATH}:${_REAL_HOME}/.local/bin"
else
    _REAL_USER="${USER:-$(id -un)}"
    _REAL_HOME="$HOME"
    _REAL_UID="$EUID"
    _SUDO_ELEVATED=false
    _REAL_PATH="$PATH"
fi
# gh stores auth tokens under the real user's home; force it here so root
# invocation (via sudo) still reads the correct credential store.
export GH_CONFIG_DIR="$_REAL_HOME/.config/gh"

_FAILED_STEPS=()

_run_optional_step() {
    local label="$1"; shift
    if $DRY_RUN; then c_yel "  [dry-run] $*"; return 0; fi
    if "$@"; then
        c_grn "  $label: OK"
    else
        c_yel "  WARNING: $label exited $?. Continuing deploy."
        _FAILED_STEPS+=("$label")
    fi
}

# Run a command as the real (non-root) calling user when the script is invoked
# via sudo. Preserves HOME, PATH, SSH_AUTH_SOCK, and GH_CONFIG_DIR so git/gh
# can resolve SSH keys and auth tokens. No-op passthrough when not under sudo.
_as_user() {
    if $_SUDO_ELEVATED; then
        sudo -u "$_REAL_USER" \
             HOME="$_REAL_HOME" \
             PATH="$_REAL_PATH" \
             GH_CONFIG_DIR="$_REAL_HOME/.config/gh" \
             XDG_CONFIG_HOME="$_REAL_HOME/.config" \
             SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}" \
             "$@"
    else
        "$@"
    fi
}

# Read a key=value from a .env file. Strips inline comments + surrounding ws.
_env_get() {
    local key="$1" path="$2"
    [[ -f "$path" ]] || { echo ""; return; }
    awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/,""); sub(/[[:space:]]*#.*$/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit }' "$path"
}

# Idempotent upsert KEY=VALUE in a .env file, but ONLY when the key is absent or its
# current value is blank — a human-set value always wins (authority: human > inference >
# blank). Returns 0 if it wrote, 1 if it left an existing non-blank value untouched.
_env_set_if_blank() {
    local key="$1" val="$2" path="$3"
    [[ -n "$(_env_get "$key" "$path")" ]] && return 1
    if grep -q "^${key}=" "$path" 2>/dev/null; then
        _as_user sed -i "s|^${key}=.*|${key}=${val}|" "$path"
    else
        printf '%s=%s\n' "$key" "$val" | _as_user tee -a "$path" >/dev/null
    fi
    return 0
}

# Detect host RAM tier from /proc/meminfo and write RESOURCE_TIER only-if-blank. Thresholds
# (GB) match README "Choose your deployment": ≤12 MICRO, ≤20 LOW, ≤44 MED, ≤96 HIGH, else
# MAX. Advisory only — the tier does NOT change which services deploy; it tells the operator
# which per-service *_MEM_LIMIT preset block (.env "PERFORMANCE TIERING") to uncomment.
detect_host_ram() {
    local mem_kb mem_gb tier existing
    mem_kb="$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)"
    if [[ -z "$mem_kb" ]]; then
        c_yel "  Could not read /proc/meminfo — skipping RESOURCE_TIER auto-detect."
        return
    fi
    mem_gb=$(( mem_kb / 1024 / 1024 ))
    if   (( mem_gb <= 12 )); then tier="MICRO"
    elif (( mem_gb <= 20 )); then tier="LOW"
    elif (( mem_gb <= 44 )); then tier="MED"
    elif (( mem_gb <= 96 )); then tier="HIGH"
    else                          tier="MAX"; fi

    existing="$(_env_get RESOURCE_TIER "$ENV_FILE")"
    if [[ -n "$existing" ]]; then
        c_grn "  RESOURCE_TIER=$existing (operator-set; auto-detect skipped — host ~${mem_gb} GB → $tier)"
    elif $DRY_RUN; then
        c_yel "  [dry-run] would set RESOURCE_TIER=$tier (host ~${mem_gb} GB)"
        existing="$tier"
    else
        _env_set_if_blank RESOURCE_TIER "$tier" "$ENV_FILE" \
            && c_grn "  RESOURCE_TIER=$tier (auto-detected from ~${mem_gb} GB host RAM)"
        existing="$tier"
    fi

    # Advisory for genuinely small hosts still on the generous MAX/HIGH preset defaults.
    if [[ "$existing" == "MICRO" || "$existing" == "LOW" ]]; then
        c_yel "  Host RAM is ~${mem_gb} GB ($existing). Per-service memory limits default to the HIGH"
        c_yel "  preset — uncomment the matching tier block in .env and/or trim STACK_PROFILES to avoid OOM."
    fi
}

# Dump the last 30 log lines of every container whose health is not 'healthy'.
# Excludes init/migration sidecars that exit 0 by design.
_show_unhealthy_logs() {
    local rows
    rows=$(docker ps -a --filter "label=com.docker.compose.project" \
        --format '{{.Names}}|{{.State}}|{{.Status}}' 2>/dev/null)
    [[ -n "$rows" ]] || { c_yel "  no containers found"; return; }

    local any=false
    while IFS='|' read -r name state status; do
        [[ -z "$name" ]] && continue
        # Skip clean exits from init/migration sidecars
        if [[ "$state" == "exited" && "$status" =~ ^Exited\ \(0\) ]]; then continue; fi
        # Skip healthy running containers
        if [[ "$state" == "running" && ( "$status" =~ \(healthy\) || ! "$status" =~ health ) ]]; then continue; fi
        any=true
        c_red "  ── $name ── ($status)"
        docker logs --tail 30 "$name" 2>&1 | sed 's/^/    /' || true
    done <<<"$rows"
    $any || c_grn "  no unhealthy containers"
}

# Show every container in the compose project, color-coded by state.
# Uses `docker ps -a` with the project label — bypasses Docker Compose's TTY
# row limit and includes Exited(0) init/migration containers with a green label.
_print_container_table() {
    local project
    project="$(_env_get COMPOSE_PROJECT_NAME "$ENV_FILE")"
    [[ -z "$project" ]] && project="$(basename "$STACK_DIR")"

    local rows
    rows=$(docker ps -a \
        --filter "label=com.docker.compose.project=$project" \
        --format '{{.Names}}|{{.State}}|{{.Status}}' 2>/dev/null) || true

    if [[ -z "$rows" ]]; then
        c_yel "  no containers found for project '$project'"
        return
    fi

    local total=0 n_ok=0 n_done=0 n_fail=0
    local -a fail_lines=() ok_lines=() done_lines=()

    while IFS='|' read -r name state status; do
        [[ -z "$name" ]] && continue
        ((total++)) || true
        # Init/migration containers that exit 0 are expected — mark green "completed"
        if [[ "$state" == "exited" && "$status" =~ ^Exited[[:space:]]\(0\) ]]; then
            ((n_done++)) || true
            done_lines+=("$(printf '  \033[32m✔\033[0m  %-42s Exited (0) — completed\n' "$name")")
        elif [[ "$state" == "running" ]]; then
            ((n_ok++)) || true
            ok_lines+=("$(printf '  \033[32m✔\033[0m  %-42s %s\n' "$name" "$status")")
        else
            ((n_fail++)) || true
            fail_lines+=("$(printf '  \033[31m✗\033[0m  %-42s %s\n' "$name" "$status")")
        fi
    done <<<"$rows"

    # Print failures first (most visible), then running, then completed
    for l in "${fail_lines[@]}";  do printf '%s' "$l"; done
    for l in "${ok_lines[@]}";    do printf '%s' "$l"; done
    for l in "${done_lines[@]}";  do printf '%s' "$l"; done

    local healthy=$(( n_ok + n_done ))
    if [[ $n_fail -gt 0 ]]; then
        printf '\n  \033[33m[+] %d/%d healthy  (%d failed)\033[0m\n' \
               "$healthy" "$total" "$n_fail"
    else
        printf '\n  \033[32m[+] %d/%d — all healthy\033[0m\n' \
               "$healthy" "$total"
    fi
}

# ── Defaults ────────────────────────────────────────────────────────────────────
REPO_URL=""
REPO_DIR=""
BRANCH="main"
TAG=""
PROFILES=()
ENV_SOURCE=""
DO_COPY_ENV=false
DO_GEN_SECRETS=false
DO_SYNC_ENV=false
DO_FIX_PERMS=false
DO_TAILSCALE=false
DO_OIDC=false
DO_SETUP_AUTHENTIK=false
DO_NEXTCLOUD_OIDC=false
DO_ENTRA_SETUP=false
DO_ENTRA_SYNC=false
DO_CHECK_STACK=false
DO_AUDIT_ACCESS=false
DOCTOR_MODE=false
DO_PULL=true
DO_BUILD=false
DO_DOWN=false
DRY_RUN=false
YES_MODE=false
NO_PROMPT=false

# ── Argument parsing ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            awk '/^set -euo/{exit} NR>1 && /^#/ {sub(/^#[[:space:]]?/,""); print}' "$0"
            exit 0 ;;
        -y|--yes)           YES_MODE=true ;;
        -n|--no-prompt)     NO_PROMPT=true ;;
        --repo)             REPO_URL="$2"; shift ;;
        --dir)              REPO_DIR="$2"; shift ;;
        --branch)           BRANCH="$2"; shift ;;
        --tag)              TAG="$2"; shift ;;
        --profile)          PROFILES+=("$2"); shift ;;
        --env)              ENV_SOURCE="$2"; shift ;;
        --copy-env)         DO_COPY_ENV=true ;;
        --gen-secrets)      DO_GEN_SECRETS=true ;;
        --sync-env)         DO_SYNC_ENV=true ;;
        --fix-perms)        DO_FIX_PERMS=true ;;
        --tailscale)        DO_TAILSCALE=true ;;
        --oidc)             DO_OIDC=true ;;
        --setup-authentik)  DO_SETUP_AUTHENTIK=true ;;
        --nextcloud-oidc)   DO_NEXTCLOUD_OIDC=true ;;
        --entra-sync)       DO_ENTRA_SYNC=true ;;
        --entra-setup)      DO_ENTRA_SETUP=true ;;
        --check-stack)      DO_CHECK_STACK=true ;;
        --audit-access)     DO_AUDIT_ACCESS=true ;;
        -d|--doctor)        DOCTOR_MODE=true ;;
        --no-pull)          DO_PULL=false ;;
        --build)            DO_BUILD=true ;;
        --down)             DO_DOWN=true ;;
        --dry-run)          DRY_RUN=true ;;
        *) die "Unknown option: $1. Run '$0 --help' for usage." ;;
    esac
    shift
done

# ── Prompt helper ───────────────────────────────────────────────────────────────
# prompt_yn "Question?" [default_y=false] → returns 0 (yes) or 1 (no)
prompt_yn() {
    local msg="$1" default="${2:-false}"
    if $NO_PROMPT; then return 1; fi
    if $YES_MODE;  then return 0; fi
    local hint; $default && hint="[Y/n]" || hint="[y/N]"
    local reply
    read -r -p "$(printf "\033[33m  %s %s \033[0m" "$msg" "$hint")" reply
    reply="${reply:-}"
    if [[ -z "$reply" ]]; then $default && return 0 || return 1; fi
    [[ "$reply" =~ ^[Yy] ]]
}

# ── Dependency check ─────────────────────────────────────────────────────────────
require_cmd() {
    command -v "$1" &>/dev/null || die "'$1' is required but not found. Install it and retry."
}

require_cmd git

# ── Fresh-host detection ──────────────────────────────────────────────────────────
# On a brand-new host docker is not yet installed. Detect that and run the full
# host-bootstrap before proceeding (installs Docker, creates /dock tree, etc.).
# The bootstrap requires root; we re-exec under sudo if we're not already root.
if ! command -v docker &>/dev/null; then
    c_hdr "Fresh host detected — running docker-host-config.sh bootstrap"
    HOST_CONFIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/docker-host-config.sh"
    if [[ ! -f "$HOST_CONFIG" ]]; then
        # Script is running from a curl pipe before the repo exists — clone first,
        # then re-exec so BASH_SOURCE resolves correctly.
        die "docker-host-config.sh not found. Run: git clone <repo> && sudo bash run.sh"
    fi
    if [[ $EUID -ne 0 ]]; then
        c_yel "  Bootstrap requires root. Re-running with sudo..."
        exec sudo bash "$0" "$@"
    fi
    bash "$HOST_CONFIG" main
    # Re-exec as the real user to continue the deploy with the freshly installed Docker.
    exec bash "$0" "$@"
fi

require_cmd docker

# ── Repository discovery ─────────────────────────────────────────────────────────
c_hdr "Locating repository"

_locate_repo() {
    # 1. Caller specified --dir
    if [[ -n "$REPO_DIR" ]]; then
        if [[ -d "$REPO_DIR/.git" ]]; then echo "$REPO_DIR"; return; fi
        die "--dir '$REPO_DIR' is not a git repository."
    fi

    # 2. Script lives inside the repo
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local git_root
    git_root="$(_as_user git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null)" || true
    if [[ -n "$git_root" ]]; then echo "$git_root"; return; fi

    # 3. Common paths
    local -a candidates=(
        "$_REAL_HOME/git/openirvana"
        "$_REAL_HOME/openirvana"
        "/home/admin/git/openirvana"
        "/opt/openirvana"
    )
    for p in "${candidates[@]}"; do
        if [[ -d "$p/.git" ]]; then echo "$p"; return; fi
    done

    # 4. Search home directory (max depth 6, match by remote URL)
    local found
    found=$(find "$_REAL_HOME" -maxdepth 6 -name ".git" -type d 2>/dev/null \
        | while read -r dot_git; do
            local root="${dot_git%/.git}"
            if _as_user git -C "$root" remote get-url origin 2>/dev/null \
                    | grep -qi "openirvana"; then
                echo "$root"; break
            fi
        done)
    if [[ -n "$found" ]]; then echo "$found"; return; fi

    echo ""
}

REPO_ROOT="$(_locate_repo)"

if [[ -z "$REPO_ROOT" ]]; then
    c_yel "  Repository not found on this machine."

    # Determine clone URL
    if [[ -z "$REPO_URL" ]]; then
        if command -v gh &>/dev/null && _as_user gh auth status &>/dev/null 2>&1; then
            REPO_URL="$(_as_user gh repo view your-org/openirvana --json sshUrl -q .sshUrl 2>/dev/null \
                        || echo "https://github.com/your-org/openirvana.git")"
        else
            REPO_URL="https://github.com/your-org/openirvana.git"
        fi
    fi

    # Determine target directory
    local_dir="${REPO_DIR:-$_REAL_HOME/git/openirvana}"
    if ! $YES_MODE && ! $NO_PROMPT; then
        read -r -p "$(printf "\033[33m  Clone %s into %s? [Y/n] \033[0m" "$REPO_URL" "$local_dir")" _reply
        [[ -z "$_reply" || "$_reply" =~ ^[Yy] ]] || die "Aborted — provide --dir to use an existing repo."
    fi

    if $DRY_RUN; then
        c_yel "  [dry-run] git clone $REPO_URL $local_dir"
    else
        c_cyn "  Cloning $REPO_URL → $local_dir"
        _as_user mkdir -p "$(dirname "$local_dir")"
        _as_user git clone "$REPO_URL" "$local_dir"
    fi
    REPO_ROOT="$local_dir"
fi

c_grn "  Repository: $REPO_ROOT"

# Detect REPO_URL from remote if not set
if [[ -z "$REPO_URL" ]]; then
    REPO_URL="$(_as_user git -C "$REPO_ROOT" remote get-url origin 2>/dev/null)" || REPO_URL="(unknown)"
fi

# Parse owner/repo from URL for GitHub API calls
_GH_SLUG=""
if [[ "$REPO_URL" =~ github\.com[:/]([^/]+/[^/]+?)(\.git)?$ ]]; then
    _GH_SLUG="${BASH_REMATCH[1]}"
fi

# Stack lives in unified-stack/ subdirectory
STACK_DIR="$REPO_ROOT/unified-stack"
[[ -f "$STACK_DIR/docker-compose.yml" ]] \
    || die "docker-compose.yml not found in $STACK_DIR — is this the right repo?"

ENV_FILE="$STACK_DIR/.env"

# ── Doctor mode: diagnostics-only short-circuit ──────────────────────────────────
if $DOCTOR_MODE; then
    require_cmd python3

    c_hdr "Container status"
    _print_container_table

    c_hdr "Stack health audit (check-stack.py)"
    if [[ -f "$ENV_FILE" ]]; then
        _as_user python3 "$STACK_DIR/scripts/check-stack.py" || true
    else
        c_yel "  .env not found at $ENV_FILE — check-stack skipped"
    fi

    c_hdr "User access audit (audit-user-access.py)"
    if [[ ! -f "$ENV_FILE" ]]; then
        c_yel "  .env not found — audit-user-access skipped"
    elif [[ -z "$(_env_get AUTHENTIK_USER_ACCESS_TOKEN "$ENV_FILE")" ]]; then
        c_yel "  AUTHENTIK_USER_ACCESS_TOKEN not set in .env — audit-user-access skipped"
    else
        _as_user python3 "$STACK_DIR/scripts/audit-user-access.py" --env "$ENV_FILE" --no-log || true
    fi

    c_hdr "Unhealthy container logs (last 30 lines each)"
    _show_unhealthy_logs

    c_hdr "Doctor complete"
    exit 0
fi

# ── Git: pull latest or checkout release tag ─────────────────────────────────────
c_hdr "Updating code"

if $DO_PULL; then
    if [[ -n "$TAG" ]]; then
        # Resolve "latest" tag via GitHub API or gh CLI
        if [[ "$TAG" == "latest" ]]; then
            resolved=""
            if command -v gh &>/dev/null && _as_user gh auth status &>/dev/null 2>&1 && [[ -n "$_GH_SLUG" ]]; then
                resolved="$(_as_user gh release view --repo "$_GH_SLUG" --json tagName -q .tagName 2>/dev/null)" || true
            fi
            if [[ -z "$resolved" ]] && [[ -n "$_GH_SLUG" ]]; then
                resolved="$(curl -sf "https://api.github.com/repos/$_GH_SLUG/releases/latest" \
                            | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null)" || true
            fi
            if [[ -z "$resolved" ]]; then
                # Fall back to latest local tag
                resolved="$(_as_user git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null)" || true
            fi
            if [[ -z "$resolved" ]]; then
                c_yel "  No release tags found — falling back to branch pull ($BRANCH)."
                TAG=""
            else
                TAG="$resolved"
                c_grn "  Latest release tag: $TAG"
            fi
        fi
    fi

    # Detect local edits to tracked files. A deploy box should mirror origin
    # exactly; local edits indicate an operator mistake or an interrupted merge.
    # We fail-closed rather than silently discarding — use --no-pull to skip
    # git sync if you intentionally have local changes.
    local_changes="$(_as_user git -C "$REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null || true)"
    if [[ -n "$local_changes" ]]; then
        c_red "  Local edits to tracked files detected:"
        printf '%s\n' "$local_changes" | sed 's/^/      /' >&2
        die "Aborting — deploy box must not have local tracked changes. Stash or commit them, or pass --no-pull to skip git sync."
    fi

    if [[ -n "$TAG" ]]; then
        c_cyn "  Fetching and checking out tag $TAG"
        if ! $DRY_RUN; then
            _as_user git -C "$REPO_ROOT" fetch --tags origin
            _as_user git -C "$REPO_ROOT" checkout -f "$TAG"
        else
            c_yel "  [dry-run] git fetch --tags origin && git checkout -f $TAG"
        fi
    else
        c_cyn "  Updating $BRANCH from origin"
        if ! $DRY_RUN; then
            _as_user git -C "$REPO_ROOT" fetch origin "$BRANCH"
            _as_user git -C "$REPO_ROOT" merge --ff-only "origin/$BRANCH"
        else
            c_yel "  [dry-run] git fetch origin $BRANCH && git merge --ff-only origin/$BRANCH"
        fi
    fi

    c_grn "  Code up to date."
else
    c_yel "  Skipping git pull (--no-pull)."
    c_grn "  Current: $(_as_user git -C "$REPO_ROOT" describe --always --tags 2>/dev/null || echo "unknown")"
fi

# ── Pre-deploy: .env ──────────────────────────────────────────────────────────────
c_hdr "Environment file"

# ENV_FILE was set earlier (right after STACK_DIR) so doctor mode can use it.

if [[ -n "$ENV_SOURCE" ]]; then
    # --env SOURCE explicitly given
    [[ -f "$ENV_SOURCE" ]] || die "--env '$ENV_SOURCE' not found."
    c_cyn "  Copying $ENV_SOURCE → $ENV_FILE"
    $DRY_RUN || _as_user cp "$ENV_SOURCE" "$ENV_FILE"
    c_grn "  .env copied from $ENV_SOURCE"
elif [[ ! -f "$ENV_FILE" ]]; then
    # No .env at all — must create one
    c_yel "  No .env found at $ENV_FILE"
    if $DO_COPY_ENV || prompt_yn "Copy .env.example to .env now?" true; then
        example="$STACK_DIR/.env.example"
        [[ -f "$example" ]] || die ".env.example not found at $example"
        $DRY_RUN || _as_user cp "$example" "$ENV_FILE"
        c_grn "  .env copied from .env.example — edit it before first deploy:"
        c_yel "    $ENV_FILE"
        if ! $YES_MODE && ! $NO_PROMPT && ! $DRY_RUN; then
            read -r -p "$(printf "\033[33m  Open in \$EDITOR (%s) now? [y/N] \033[0m" "${EDITOR:-vi}")" _e
            [[ "$_e" =~ ^[Yy] ]] && _as_user "${EDITOR:-vi}" "$ENV_FILE"
        fi
    else
        die ".env is required. Provide one via --env <path> or --copy-env."
    fi
else
    c_grn "  .env found: $ENV_FILE"
fi

# ── Pre-deploy: sync-env ─────────────────────────────────────────────────────────
_env_has_new_vars=false
if [[ -f "$STACK_DIR/.env.example" && -f "$ENV_FILE" ]]; then
    while IFS= read -r _l; do
        [[ "$_l" =~ ^[[:space:]]*(#|$) ]] && continue
        _k="${_l%%=*}"
        [[ -z "$_k" ]] && continue
        grep -qE "^${_k}=" "$ENV_FILE" || { _env_has_new_vars=true; break; }
    done < "$STACK_DIR/.env.example"
fi

if $DO_SYNC_ENV || ( $_env_has_new_vars && ! $NO_PROMPT && prompt_yn "Run sync-env.py to add new .env.example vars to .env?" ); then
    c_cyn "  Running sync-env.py"
    $DRY_RUN \
        && c_yel "  [dry-run] python3 $STACK_DIR/scripts/sync-env.py $ENV_FILE" \
        || _as_user python3 "$STACK_DIR/scripts/sync-env.py" "$ENV_FILE"
    c_grn "  sync-env.py complete."
elif ! $_env_has_new_vars && [[ -f "$STACK_DIR/.env.example" && -f "$ENV_FILE" ]]; then
    c_grn "  .env up to date — sync-env skipped."
fi

# ── Pre-deploy: gen-secrets ──────────────────────────────────────────────────────
if $DO_GEN_SECRETS || (! $NO_PROMPT && prompt_yn "Run gen-secrets.py to fill empty secret vars?"); then
    c_cyn "  Running gen-secrets.py"
    # Pass --apply only if the stack is already running (postgres reachable)
    apply_flag=""
    if docker compose -f "$STACK_DIR/docker-compose.yml" ps postgres --status running -q 2>/dev/null | grep -q .; then
        apply_flag="--apply"
        c_cyn "  Stack already running — passing --apply to update live credentials."
    fi
    if $DRY_RUN; then
        c_yel "  [dry-run] python3 $STACK_DIR/scripts/gen-secrets.py $ENV_FILE $apply_flag"
    else
        _run_optional_step "gen-secrets" _as_user python3 "$STACK_DIR/scripts/gen-secrets.py" "$ENV_FILE" $apply_flag
    fi
fi

# ── Pre-deploy: fix-permissions ──────────────────────────────────────────────────
if $DO_FIX_PERMS || (! $NO_PROMPT && prompt_yn "Run fix-permissions.sh to set bind-mount ownership?"); then
    c_cyn "  Running fix-permissions.sh (may require sudo)"
    if $DRY_RUN; then
        c_yel "  [dry-run] [sudo] bash $STACK_DIR/scripts/fix-permissions.sh"
    elif [[ $EUID -eq 0 ]]; then
        _run_optional_step "fix-permissions" bash "$STACK_DIR/scripts/fix-permissions.sh"
    else
        _run_optional_step "fix-permissions" sudo bash "$STACK_DIR/scripts/fix-permissions.sh"
    fi
fi

# ── Pre-deploy: Tailscale ACL + auth key provisioning ────────────────────────────────
# Must run BEFORE docker compose up so TAILSCALE_AUTHKEY is written to .env before
# tailscale-ingress reads it on first boot. Skipped silently when
# TAILSCALE_OAUTH_CLIENT_ID is not set (Tailscale control-plane integration is optional).
_ts_cid="$(_env_get TAILSCALE_OAUTH_CLIENT_ID "$ENV_FILE")"
_ts_key="$(_env_get TAILSCALE_AUTHKEY "$ENV_FILE")"

if $DO_TAILSCALE \
    || ( [[ -n "$_ts_cid" ]] \
         && ( $YES_MODE \
              || ( [[ -z "$_ts_key" ]] && ! $NO_PROMPT \
                   && prompt_yn "Run set-auth.py tailscale to provision Tailscale ACL + auth key?" ) ) ); then
    c_hdr "Tailscale ACL provisioning (pre-deploy)"
    if $DRY_RUN; then
        c_yel "  [dry-run] python3 $STACK_DIR/scripts/set-auth.py --env $ENV_FILE tailscale"
    else
        _run_optional_step "tailscale-acl" \
            _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" tailscale
    fi
elif [[ -n "$_ts_cid" && -z "$_ts_key" ]]; then
    c_yel "  TAILSCALE_OAUTH_CLIENT_ID is set but TAILSCALE_AUTHKEY is blank."
    c_yel "  Run before first deploy: python3 unified-stack/scripts/set-auth.py tailscale"
    c_yel "  Or pass --tailscale to this script to provision automatically."
fi

# ── Resource tier detection ────────────────────────────────────────────────────────
c_hdr "Resource tier"
detect_host_ram

# ── Service selection (resolver-driven, dependency-checked) — ADR-0015 ─────────────
# scripts/profiles.py (SSoT reader of profiles.toml) resolves STACK_PROFILES (fine
# profiles OR bundle names) + SERVICE_ENABLE − SERVICE_DISABLE into an explicit service
# list, fail-closed on HARD-dependency / core / unknown violations. run.sh then runs
# `docker compose up -d <list>` — an explicitly-named service starts regardless of active
# profiles. COMPOSE_PROFILES is persisted to .env as the resolved services' self-name
# profiles, so `--remove-orphans` and manual `docker compose` calls stay aligned to this
# exact set. RBAC categories are a separate concern (set-auth.py), NOT deployment profiles.
c_hdr "Service selection"

_stack_profiles="$(_env_get STACK_PROFILES "$ENV_FILE")"
_service_enable="$(_env_get SERVICE_ENABLE "$ENV_FILE")"
_service_disable="$(_env_get SERVICE_DISABLE "$ENV_FILE")"

# CLI --profile args override STACK_PROFILES when given.
if [[ ${#PROFILES[@]} -gt 0 ]]; then
    _stack_profiles="$(IFS=,; echo "${PROFILES[*]}")"
fi
# Default to the full functional set when nothing is configured (preserves the
# all-services OOTB / one-liner deploy).
if [[ -z "$_stack_profiles" ]]; then
    _stack_profiles="$(_as_user python3 -c 'import sys; sys.path.insert(0,"'"$STACK_DIR"'/scripts"); import profiles; print(",".join(p for p in profiles.PROFILES if p!="core"))')"
    c_yel "  STACK_PROFILES unset — defaulting to full stack."
fi

# Human-readable dependency report (effective set + HARD/SOFT/disable diagnostics).
_as_user python3 "$STACK_DIR/scripts/profiles.py" \
    --profiles "$_stack_profiles" --enable "$_service_enable" --disable "$_service_disable" || true

# Machine-readable resolve → the explicit service list. profiles.py --resolve exits
# non-zero (printing the offending name/pair to stderr) on HARD / disable-HARD / core /
# unknown violations — fail-closed: abort BEFORE any compose action (ADR-0015).
_resolved="$(_as_user python3 "$STACK_DIR/scripts/profiles.py" --resolve \
    --profiles "$_stack_profiles" --enable "$_service_enable" --disable "$_service_disable")" \
    || die "Service resolution failed (see above). Fix STACK_PROFILES / SERVICE_ENABLE / SERVICE_DISABLE in $ENV_FILE, then re-run."

# shellcheck disable=SC2206
RESOLVED_SVCS=( $_resolved )
[[ ${#RESOLVED_SVCS[@]} -gt 0 ]] || die "Resolver produced an empty service list — check STACK_PROFILES in $ENV_FILE."
c_grn "  Resolved ${#RESOLVED_SVCS[@]} services: ${RESOLVED_SVCS[*]}"

# Persist COMPOSE_PROFILES = the resolved services' self-name profiles (every service is
# tagged `profiles: [<fine-profile>, <self-name>]`). Keeping it equal to the resolved set
# means a SERVICE_DISABLE'd service (absent here) carries no active profile, so
# `--remove-orphans` prunes it on the next deploy and manual `docker compose` calls match.
# Idempotent upsert; .env is deploy-user owned.
COMPOSE_PROFILES="$(printf '%s\n' "${RESOLVED_SVCS[@]}" | sort -u | paste -sd,)"
if grep -q '^COMPOSE_PROFILES=' "$ENV_FILE" 2>/dev/null; then
    _as_user sed -i "s|^COMPOSE_PROFILES=.*|COMPOSE_PROFILES=$COMPOSE_PROFILES|" "$ENV_FILE"
else
    printf 'COMPOSE_PROFILES=%s\n' "$COMPOSE_PROFILES" | _as_user tee -a "$ENV_FILE" >/dev/null
fi

# ── Build docker compose base command ────────────────────────────────────────────
# Explicit-service-list driven: no --profile flags. The resolved list is passed to `up`
# below; explicit names start profiled services and --remove-orphans prunes the rest.
COMPOSE_CMD=(docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR")

# ── OpenBao bootstrap (pre-deploy) ──────────────────────────────────────────────
# Bring OpenBao up first (isolated compose up) so the secrets backend is ready
# before the rest of the stack starts. Sequence:
#   1. compose up openbao (detached)
#   2. wait for `bao status` rc 0 (active) or 2 (sealed — expected on fresh start)
#   3. bao-bootstrap.py — idempotent init + Shamir unseal/escrow + AppRole provision
#   4. gen-secrets.py --target bao — seed KV write-if-absent (generated secrets)
#   4a. komodo-creds.py seed — seed operator-provided Komodo/OIDC secrets (if KOMODO_PASSKEY set)
#   5. bao-sync.py — AppRole login → read KV → compile .env (write-if-blank)
# Idempotent: re-running on a live stack is safe; all scripts check before writing.
# BAO_ADDR uses openbao's static Docker network IP (security net 192.0.2.10) because
# the openbao service has no host ports: published — docker exec is used for the
# readiness poll (inside-container 127.0.0.1:8200) to avoid any network dependency.
c_hdr "OpenBao secrets backend bootstrap"

# openbao is core (always in the resolved set) — bring it up by explicit name; an
# explicitly-named service starts regardless of active profiles, so no --profile is needed.
_bao_up_cmd=(docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR")

if $DRY_RUN; then
    c_yel "  [dry-run] ${_bao_up_cmd[*]} up -d openbao"
    c_yel "  [dry-run] wait for bao status rc 0|2"
    c_yel "  [dry-run] python3 $STACK_DIR/scripts/bao-bootstrap.py"
    c_yel "  [dry-run] python3 $STACK_DIR/scripts/gen-secrets.py $ENV_FILE --target bao"
    c_yel "  [dry-run] python3 $STACK_DIR/scripts/komodo-creds.py seed (if KOMODO_PASSKEY set)"
    c_yel "  [dry-run] python3 $STACK_DIR/scripts/bao-sync.py $ENV_FILE"
else
    c_cyn "  Starting openbao container..."
    "${_bao_up_cmd[@]}" up -d openbao

    c_cyn "  Waiting for OpenBao API (up to 60 s)..."
    _bao_ready=false
    for _i in $(seq 1 30); do
        _bao_rc=$(docker exec openbao bao status -address=http://127.0.0.1:8200 >/dev/null 2>&1; echo $?)
        if [[ "$_bao_rc" == "0" || "$_bao_rc" == "2" ]]; then
            _bao_ready=true
            break
        fi
        sleep 2
    done
    if ! $_bao_ready; then
        die "OpenBao did not become ready after 60 s (last bao status rc: $_bao_rc). Check: docker logs openbao"
    fi
    c_grn "  OpenBao API ready (bao status rc=$_bao_rc)."

    c_cyn "  Running bao-bootstrap.py (init + unseal escrow + AppRole)..."
    # bao-bootstrap writes the unseal-key + root-token escrow (init.json) into
    # ${DOCK_CONF}/openbao, which lives under /dock (owner svc-user:media, mode 770).
    # The deploy user has NO access to /dock by design — init.json is root-only escrow
    # the openbao container must never see — so this one step runs as ROOT (sudo), unlike
    # the .env-writing steps below. `sudo` is a no-op when run.sh is already root-elevated.
    # bao-bootstrap.py takes no positional .env arg — it locates STACK_DIR/.env itself
    # (its only flag is --store; default 'env' escrows to init.json, correct on Linux
    # where DPAPI is unavailable). Passing $ENV_FILE made argparse exit 2, so the vault
    # was never initialized/unsealed and every downstream secret step failed.
    _run_optional_step "bao-bootstrap" \
        sudo env BAO_ADDR=http://192.0.2.10:8200 python3 "$STACK_DIR/scripts/bao-bootstrap.py"
    # bao-bootstrap also appends the least-privilege AppRole creds (BAO_SYNC_ROLE_ID/
    # SECRET_ID) to .env as root; restore .env to the deploy user so the admin-run
    # gen-secrets/bao-sync steps below — and the running stack — can read it.
    if [[ -f "$ENV_FILE" ]]; then sudo chown "$_REAL_UID:$_REAL_UID" "$ENV_FILE" || true; fi

    c_cyn "  Running gen-secrets.py --target bao (seed KV write-if-absent)..."
    # Runs as ROOT (like bao-bootstrap above): seeding the KV needs the OpenBao
    # root token, which lives in the root-only init.json escrow the deploy user
    # cannot read. --target bao writes only to the KV (network); it creates no
    # on-disk artifacts, so running as root leaves no root-owned files behind.
    # (A least-privilege RW AppRole is the future refinement — the BAO_SYNC_ROLE
    # used by bao-sync is read-only by policy, so it cannot seed KV.)
    _run_optional_step "gen-secrets-bao" \
        sudo env BAO_ADDR=http://192.0.2.10:8200 python3 "$STACK_DIR/scripts/gen-secrets.py" "$ENV_FILE" --target bao

    c_cyn "  Running bao-sync.py (compile .env from KV)..."
    _run_optional_step "bao-sync" \
        _as_user env BAO_ADDR=http://192.0.2.10:8200 python3 "$STACK_DIR/scripts/bao-sync.py" "$ENV_FILE"
fi

# ── Pre-deploy: preflight validator ─────────────────────────────────────────────
# Fail fast before touching running containers.
c_hdr "Preflight checks"
if $DRY_RUN; then
    c_yel "  [dry-run] python3 $STACK_DIR/scripts/preflight.py --env $ENV_FILE"
elif [[ -f "$STACK_DIR/scripts/preflight.py" ]]; then
    _as_user python3 "$STACK_DIR/scripts/preflight.py" --env "$ENV_FILE" \
        || die "Preflight failed — fix the issues above before deploying."
fi

# ── Deploy ───────────────────────────────────────────────────────────────────────
c_hdr "Deploying stack"

if $DO_DOWN; then
    c_cyn "  Stopping existing containers (--down)"
    down_cmd=("${COMPOSE_CMD[@]}" down --remove-orphans)
    c_cyn "  $ ${down_cmd[*]}"
    $DRY_RUN || "${down_cmd[@]}"
fi

up_cmd=("${COMPOSE_CMD[@]}" up -d "${RESOLVED_SVCS[@]}" --remove-orphans)
$DO_BUILD && up_cmd+=(--build)

# --wait: block until every service with a healthcheck reports healthy.
# Supported in Docker Compose v2.1+. Fall back gracefully on older installs.
if docker compose up --help 2>/dev/null | grep -q '\-\-wait'; then
    up_cmd+=(--wait --wait-timeout 300)
fi

# Snapshot which services are already running before this deploy, so a
# failed up can roll back only the newly started services.
_pre_deploy_svcs=()
if ! $DRY_RUN; then
    while IFS= read -r _svc; do
        [[ -n "$_svc" ]] && _pre_deploy_svcs+=("$_svc")
    done < <(docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR" \
        ps --services --status running 2>/dev/null || true)
fi

c_cyn "  $ ${up_cmd[*]}"
if $DRY_RUN; then
    c_yel "  [dry-run] skipping deploy."
else
    if ! "${up_cmd[@]}"; then
        c_red "  docker compose up failed — rolling back newly started services"
        # Determine which services are new (running now but were not before).
        _new_svcs=()
        while IFS= read -r _svc; do
            [[ -z "$_svc" ]] && continue
            _was_running=false
            for _pre in "${_pre_deploy_svcs[@]}"; do
                [[ "$_pre" == "$_svc" ]] && { _was_running=true; break; }
            done
            $_was_running || _new_svcs+=("$_svc")
        done < <(docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR" \
            ps --services --status running 2>/dev/null || true)

        if [[ ${#_new_svcs[@]} -gt 0 ]]; then
            c_yel "  Stopping newly started services: ${_new_svcs[*]}"
            docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR" \
                stop "${_new_svcs[@]}" 2>/dev/null || true
        fi
        die "Deploy failed; newly started services rolled back. Check logs: docker compose logs --tail=50"
    fi

    # Write run-state file on success (used by doctor mode and future rollback).
    _state_dir="/dock/conf"
    if [[ -d "$_state_dir" ]]; then
        _git_sha="$(_as_user git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
        printf '{"deployed_at":"%s","branch":"%s","git_sha":"%s","services":[%s]}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "${TAG:-$BRANCH}" \
            "$_git_sha" \
            "$(printf '"%s",' "${RESOLVED_SVCS[@]}" | sed 's/,$//')" \
            > "$_state_dir/.run-state.json" 2>/dev/null || true
    fi
fi

# ── Post-deploy: status ──────────────────────────────────────────────────────────
if ! $DRY_RUN; then
    c_hdr "Container status"
    _print_container_table
fi

# ── Post-deploy: fix-perms again if containers created new dirs ──────────────────
if $DO_FIX_PERMS && ! $DRY_RUN; then
    c_cyn "  Re-running fix-permissions.sh (post-deploy, for newly created data dirs)"
    if [[ $EUID -eq 0 ]]; then
        _run_optional_step "fix-permissions-post" bash "$STACK_DIR/scripts/fix-permissions.sh"
    else
        _run_optional_step "fix-permissions-post" sudo bash "$STACK_DIR/scripts/fix-permissions.sh"
    fi
fi

# ── Post-deploy: set-auth.py oidc ────────────────────────────────────────────────
if $DO_OIDC || $YES_MODE || (! $NO_PROMPT && prompt_yn "Run set-auth.py oidc to provision OIDC providers in Authentik?"); then
    c_cyn "  Running set-auth.py oidc"
    _run_optional_step "set-auth-oidc" \
        _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" oidc
fi

# ── Post-deploy: set-auth.py authentik ───────────────────────────────────────────
if $DO_SETUP_AUTHENTIK || ($YES_MODE && ! $NO_PROMPT); then
    c_cyn "  Running set-auth.py authentik"
    _run_optional_step "set-auth-authentik" \
        _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" authentik

    # Revoke the bootstrap token now that authentik provisioning is complete.
    # Idempotent — no-ops if already revoked. Runs immediately after authentik
    # setup so the token is never left live longer than necessary (M006).
    c_cyn "  Revoking Authentik bootstrap token (post-provisioning)"
    _run_optional_step "revoke-bootstrap-token" \
        _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" revoke-bootstrap-token
fi

# ── Post-deploy: ntfy ACL provisioning (M002) ────────────────────────────────────
# Grants write-only access to alerting topics; probes for 200 (not 403).
# No-op when the ntfy container is not in the active profile.
if [[ -f "$STACK_DIR/scripts/ntfy-setup.py" ]]; then
    c_cyn "  Provisioning ntfy ACL"
    _run_optional_step "ntfy-setup" \
        _as_user python3 "$STACK_DIR/scripts/ntfy-setup.py"
fi

# ── Post-deploy: set-auth.py nextcloud-oidc ──────────────────────────────────────
if $DO_NEXTCLOUD_OIDC || ($YES_MODE && ! $NO_PROMPT); then
    c_cyn "  Running set-auth.py nextcloud-oidc"
    _run_optional_step "set-auth-nextcloud-oidc" \
        _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" nextcloud-oidc
fi

# ── Post-deploy: Entra ID ────────────────────────────────────────────────────────
# --entra-setup: interactive Azure device-code login; never triggered by -y
if $DO_ENTRA_SETUP && ! $YES_MODE; then
    c_cyn "  Running set-auth.py entra-setup (interactive)"
    $DRY_RUN \
        && c_yel "  [dry-run] python3 $STACK_DIR/scripts/set-auth.py --env $ENV_FILE entra-setup" \
        || _as_user python3 "$STACK_DIR/scripts/set-auth.py" --env "$ENV_FILE" entra-setup
    c_grn "  set-auth.py entra-setup complete."
fi

# --entra-sync (or -y): non-interactive policy sync via maintain.py
if $DO_ENTRA_SYNC || ($YES_MODE && ! $NO_PROMPT); then
    c_cyn "  Running maintain.py entra-sync"
    _run_optional_step "entra-sync" \
        _as_user python3 "$STACK_DIR/scripts/maintain.py" entra-sync
fi

# Always-on, fast, idempotent: enforce a long Cloudflare HSTS policy so
# Nextcloud's setupcheck stops flagging the edge-overridden 30-day value.
# No-op when already at target; only fires when CLOUDFLARE_API_TOKEN is set.
_run_optional_step "cloudflare-hsts" \
    _as_user python3 "$STACK_DIR/scripts/maintain.py" cloudflare-hsts

# Regenerate the Dashy + Grafana dashboards from current discovery. These write
# into /dock/conf (root-owned), so they run as root via the docker-host-config
# render functions — NOT _as_user (the deploy user can't write /dock/conf).
# `sudo -n` fails fast (instead of prompting) when passwordless sudo is absent;
# the host bootstrap (sudo docker-host-config.sh) and nightly cron also render
# these, so a skipped step here is non-fatal.
_run_optional_step "render-dashy" \
    sudo -n bash "$STACK_DIR/scripts/docker-host-config.sh" render_dashy
_run_optional_step "render-grafana" \
    sudo -n bash "$STACK_DIR/scripts/docker-host-config.sh" render_grafana

# Concise report of images with newer upstream versions available. (The JSONL
# snapshot for the Grafana table is written by the root cron `maintain.py
# versions`, which can write /dock/conf; this deploy step only prints.)
_run_optional_step "image-versions" \
    _as_user python3 "$STACK_DIR/scripts/check-versions.py"

# SSO lockdown: disable local login where safe so Authentik/Entra is the sole
# interactive login. Idempotent + OIDC-verified (fail-safe); honors
# SSO_LOCKDOWN_ENABLED in .env. Revert: docs/runbooks/local-login-recovery.md.
_run_optional_step "sso-lockdown" \
    _as_user python3 "$STACK_DIR/scripts/setup-sso-lockdown.py"

# ── Post-deploy: stack health audit (check-stack.py) ─────────────────────────────
if $DO_CHECK_STACK || ($YES_MODE && ! $NO_PROMPT) \
        || (! $NO_PROMPT && ! $YES_MODE && prompt_yn "Run check-stack.py to audit service health?" true); then
    c_hdr "Stack health audit"
    if $DRY_RUN; then
        c_yel "  [dry-run] python3 $STACK_DIR/scripts/check-stack.py"
    else
        _run_optional_step "check-stack" \
            _as_user python3 "$STACK_DIR/scripts/check-stack.py"
    fi
fi

# ── Post-deploy: user access audit (audit-user-access.py) ────────────────────────
# Skipped silently when AUTHENTIK_USER_ACCESS_TOKEN is not set — the script requires it.
if $DO_AUDIT_ACCESS || ($YES_MODE && ! $NO_PROMPT) \
        || (! $NO_PROMPT && ! $YES_MODE && prompt_yn "Run audit-user-access.py to audit user access?"); then
    if [[ -z "$(_env_get AUTHENTIK_USER_ACCESS_TOKEN "$ENV_FILE")" ]]; then
        c_yel "  AUTHENTIK_USER_ACCESS_TOKEN not set in .env — audit-user-access skipped"
    else
        c_hdr "User access audit"
        if $DRY_RUN; then
            c_yel "  [dry-run] python3 $STACK_DIR/scripts/audit-user-access.py --env $ENV_FILE"
        else
            _run_optional_step "audit-user-access" \
                _as_user python3 "$STACK_DIR/scripts/audit-user-access.py" --env "$ENV_FILE"
        fi
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────────
c_hdr "Done"
c_grn "  Stack deployed from: $STACK_DIR"
[[ -n "$TAG" ]] && c_grn "  Version: $TAG" || c_grn "  Branch: $BRANCH"
if [[ ${#PROFILES[@]} -gt 0 ]]; then
    c_grn "  Active profiles: ${PROFILES[*]}"
fi
if ! $DRY_RUN; then
    c_cyn "  Re-run with -d (--doctor) any time for read-only stack diagnostics."
fi

# ── Optional step summary ─────────────────────────────────────────────────────────
if [[ ${#_FAILED_STEPS[@]} -gt 0 ]]; then
    c_red ""
    c_red "  The following optional steps failed:"
    for s in "${_FAILED_STEPS[@]}"; do
        c_red "    - $s"
    done
    c_yel "  Re-run these steps manually once the underlying issue is resolved."
fi
