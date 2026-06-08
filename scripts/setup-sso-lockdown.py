#!/usr/bin/env python3
"""setup-sso-lockdown.py — disable local password login where safe so
Authentik/Entra is the sole interactive login. Idempotent; each service
verifies OIDC works BEFORE disabling local (fail-safe — never lock a door
without confirming the key). Honors SSO_LOCKDOWN_ENABLED in .env.

Covered here: nextcloud (occ hide_login_form), immich (system-config API).
Env-driven services (grafana, vikunja) are handled in compose/.env.
Documented exceptions: jellyfin (native clients need local), *arr (already
AuthenticationMethod=None, gated by forward-auth). See
docs/runbooks/local-login-recovery.md to revert.
"""
from __future__ import annotations
import copy, json, os, subprocess, sys
from pathlib import Path

_STACK = Path(__file__).resolve().parent.parent
GREEN, RED, YEL, RST = "\033[92m", "\033[91m", "\033[93m", "\033[0m"
def ok(s):   print(f"{GREEN}  ok{RST} {s}")
def err(s):  print(f"{RED}  !! {s}{RST}")
def warn(s): print(f"{YEL}  ~~ {s}{RST}")


def load_env(path: Path) -> dict:
    env: dict[str, str] = {}
    if not Path(path).exists():
        return env
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.split("#")[0].strip().strip('"').strip("'")
    return env


def _occ(args: list[str], timeout: int = 60) -> tuple[int, str]:
    r = subprocess.run(
        ["docker", "exec", "--user", "www-data", "nextcloud", "php", "occ", *args],
        capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def lockdown_nextcloud() -> None:
    """Hide the local login form so only the 'Login with Authentik' button shows.
    Break-glass: https://cloud.<fqdn>/login?direct=1 still renders the form."""
    rc, _ = _occ(["status"])
    if rc != 0:
        warn("nextcloud not reachable — skipping")
        return
    # Fail-safe: confirm a user_oidc provider exists before hiding local login.
    rc, out = _occ(["user_oidc:provider"])
    if rc != 0 or not out.strip():
        err("nextcloud: no user_oidc provider configured — NOT hiding local login")
        return
    rc, cur = _occ(["config:system:get", "hide_login_form"])
    if cur.strip() == "true":
        ok("nextcloud: local login already hidden")
        return
    rc, out = _occ(["config:system:set", "hide_login_form", "--value", "true", "--type", "boolean"])
    if rc == 0:
        ok("nextcloud: local login form hidden (break-glass: /login?direct=1)")
    else:
        err(f"nextcloud: failed to set hide_login_form: {out}")


def immich_locked_config(cfg: dict) -> dict | None:
    """Return a copy of immich system-config with passwordLogin disabled, or
    None if OAuth isn't enabled (fail-safe — disabling would lock everyone out).
    Does not mutate the input."""
    if not cfg.get("oauth", {}).get("enabled"):
        return None
    out = copy.deepcopy(cfg)
    out.setdefault("passwordLogin", {})["enabled"] = False
    return out


def _immich_api(method: str, key: str, body: dict | None = None) -> dict | None:
    """Call the Immich system-config API from INSIDE the immich-server container
    (the host can't resolve docker network names). The API key is passed via the
    container env (-e), never interpolated into the command text. Body (for PUT)
    is piped on stdin so it isn't exposed in the process list either."""
    url = "http://localhost:2283/api/system-config"
    cmd = ["docker", "exec", "-i", "-e", f"IMM_KEY={key}", "immich-server", "sh", "-c"]
    if body is None:
        shell = (f'curl -s --max-time 20 -H "x-api-key: $IMM_KEY" '
                 f'-H "Accept: application/json" {url}')
        inp = None
    else:
        shell = (f'curl -s --max-time 20 -X PUT -H "x-api-key: $IMM_KEY" '
                 f'-H "Content-Type: application/json" --data @- {url}')
        inp = json.dumps(body)
    try:
        r = subprocess.run(cmd + [shell], input=inp, capture_output=True, text=True, timeout=40)
        if r.returncode != 0 or not r.stdout.strip():
            err(f"immich API {method} failed: {(r.stderr or r.stdout).strip()[:160]}")
            return None
        return json.loads(r.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        err(f"immich API {method} failed: {e}")
        return None


def lockdown_immich(env: dict) -> None:
    key = env.get("IMMICH_API_KEY", "")
    if not key:
        warn("immich: IMMICH_API_KEY not set — skipping")
        return
    cfg = _immich_api("GET", key)
    if not cfg:
        return
    if cfg.get("passwordLogin", {}).get("enabled") is False:
        ok("immich: password login already disabled")
        return
    locked = immich_locked_config(cfg)
    if locked is None:
        err("immich: OAuth not enabled — NOT disabling password login (would lock out)")
        return
    if _immich_api("PUT", key, locked) is not None:
        ok("immich: password login disabled (OAuth enforced)")


def main() -> int:
    env = load_env(_STACK / ".env")
    if env.get("SSO_LOCKDOWN_ENABLED", "").lower() not in ("true", "1", "yes"):
        print("SSO_LOCKDOWN_ENABLED not true — skipping SSO lockdown")
        return 0
    print("== SSO lockdown ==")
    lockdown_nextcloud()
    lockdown_immich(env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
