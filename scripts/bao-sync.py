"""bao-sync.py — compile .env secret values from OpenBao KV v2 via AppRole (hvac client)."""
import argparse, os, shlex, sys
from pathlib import Path
from bao_client import BaoClient
from utils import EnvFile, green, red, yellow


def _needs_quoting(value: str) -> bool:
    """Return True if value must be quoted to survive a .env round-trip."""
    return any(c in value for c in ('#', ' ', '"', "'", '\\', '\n', '\t'))


def sync(addr: str, env: EnvFile, mount: str, force: bool) -> int:
    role_id, secret_id = env.get("BAO_SYNC_ROLE_ID"), env.get("BAO_SYNC_SECRET_ID")
    if not role_id or not secret_id:
        red("BAO_SYNC_ROLE_ID/SECRET_ID not set — run bao-bootstrap.py first"); return 2
    bao = BaoClient(addr)
    try:
        bao.token = bao.approle_login(role_id, secret_id)
    except Exception as exc:
        red(f"AppRole login failed — check BAO_SYNC_ROLE_ID and BAO_SYNC_SECRET_ID: {exc}")
        return 1
    # List KV keys via the adapter's public list_keys, then read each.
    keys = bao.list_keys(mount)
    n = 0
    for k in keys:
        value = bao.kv_get(k, mount=mount).get("value", "")
        if value == "":
            yellow(f"  skip {k} (no 'value' field)"); continue
        env_key = k.upper()
        safe_value = shlex.quote(value) if _needs_quoting(value) else value
        (env.force_set if force else env.set_if_blank)(env_key, safe_value)
        n += 1
    green(f"  synced {n} secret(s) from bao → .env")
    return 0

def main() -> None:
    base = Path(__file__).resolve().parent.parent
    env = EnvFile(base / ".env")
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="overwrite existing .env values (rotation)")
    args = ap.parse_args()
    addr = os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")
    sys.exit(sync(addr, env, env.get("BAO_KV_MOUNT") or "secret", args.force))

if __name__ == "__main__":
    main()
