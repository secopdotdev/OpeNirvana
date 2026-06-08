"""bao-bootstrap.py — initialize, escrow, unseal, and provision OpenBao. Idempotent (hvac client)."""
import json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path
from bao_client import BaoClient
from utils import EnvFile, red, green, yellow, step

_ENV_SYNC_POLICY = '''
path "secret/data/*"     { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
'''.strip()


def _atomic_secret_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text); fh.flush(); os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)                       # atomic; perms 0600 before it lands


def _escrow(init_path: Path, age_recipient: str) -> None:
    if not age_recipient:
        return
    if shutil.which("age") is None:
        yellow(f"  age not installed — cannot write {init_path}.age escrow copy"); return
    enc = init_path.with_suffix(".json.age")
    subprocess.run(["age", "-r", age_recipient, "-o", str(enc), str(init_path)], check=True)
    os.chmod(enc, 0o600)
    green(f"  escrow written: {enc}")


def _warn_no_escrow() -> None:
    red("  ┌─────────────────────────────────────────────────────────────┐")
    red("  │ WARNING: OpenBao recovery keys exist ONLY on this host.       │")
    red("  │ No BAO_ESCROW_AGE_RECIPIENT and no BAO_AKV_* configured.       │")
    red("  │ If this host is lost, ALL stack secrets are UNRECOVERABLE.     │")
    red("  │ Copy ${DOCK_CONF}/openbao/init.json off-box NOW, or set        │")
    red("  │ BAO_ESCROW_AGE_RECIPIENT / BAO_AKV_* and re-run. (ADR 0001)    │")
    red("  └─────────────────────────────────────────────────────────────┘")


def bootstrap(addr: str, env: EnvFile, conf_dir: Path) -> None:
    bao = BaoClient(addr)
    init_path = conf_dir / "openbao" / "init.json"
    status = bao.seal_status()

    if not status.get("initialized"):
        step("Initializing OpenBao (first run)")
        res = bao.init(shares=1, threshold=1)        # Shamir 1/1; AKV seal supersedes if configured
        _atomic_secret_write(init_path, json.dumps(res, indent=2))
        green(f"  init material stored: {init_path} (0600)")
        _escrow(init_path, env.get("BAO_ESCROW_AGE_RECIPIENT"))
        if not env.get("BAO_ESCROW_AGE_RECIPIENT") and not env.get("BAO_AKV_VAULT_NAME"):
            _warn_no_escrow()
    else:
        green("  already initialized — skipping init")
        if not init_path.exists():
            # Vault has persistent state but we hold no unseal keys / root token.
            # This is the break-glass scenario — fail fast with a clear pointer rather
            # than a cryptic "Vault is sealed" further down.
            red(f"  vault is initialized but {init_path} is missing.")
            red("  Restore it from escrow (init.json.age or your off-box copy) before re-running.")
            red("  Without the unseal keys + root token this vault cannot be unsealed or managed.")
            red("  See docs/openbao-runbook.md (host-loss / lost-keys procedures).")
            raise SystemExit(2)
        res = json.loads(init_path.read_text(encoding="utf-8"))

    # Unseal (no-op if AKV auto-unseal already unsealed it, or already unsealed).
    if bao.seal_status().get("sealed", True):
        for key in (res.get("keys_base64") or res.get("keys") or []):
            if not bao.unseal(key).get("sealed", True):
                break
        if bao.seal_status().get("sealed", True):
            red("  still sealed after submitting stored unseal keys — init.json may be stale.")
            raise SystemExit(3)
        green("  unsealed")
    else:
        green("  already unsealed")

    root = res.get("root_token")
    bao.token = root
    # Idempotent provisioning — ignore "already enabled" 400s.
    # NOTE: audit is NOT enabled here. OpenBao 2.x forbids enabling audit devices via
    # the API ("cannot enable audit device via API; use declarative, config-based audit
    # device management instead"). The file audit device is declared in openbao.hcl and
    # created by the server on startup. See ADR 0001 + docs/openbao-runbook.md.
    for label, fn in [("kv v2", lambda: bao.enable_kv_v2(env.get("BAO_KV_MOUNT") or "secret")),
                      ("approle", bao.enable_approle)]:
        try: fn(); green(f"  enabled {label}")
        except RuntimeError as e:
            if "already" in str(e).lower() or "path is already in use" in str(e).lower():
                green(f"  {label} already enabled")
            else: raise

    role = env.get("BAO_APPROLE_NAME") or "env-sync"
    bao.put_policy("env-sync", _ENV_SYNC_POLICY)
    bao.create_approle(role, ["env-sync"])
    if not env.get("BAO_SYNC_ROLE_ID"):
        env.set_if_blank("BAO_SYNC_ROLE_ID", bao.read_role_id(role))
    else:
        print("  skip   BAO_SYNC_ROLE_ID (already set)")
    if not env.get("BAO_SYNC_SECRET_ID"):
        env.set_if_blank("BAO_SYNC_SECRET_ID", bao.gen_secret_id(role))
    else:
        print("  skip   BAO_SYNC_SECRET_ID (already set)")
    green("  AppRole 'env-sync' provisioned; creds written to .env (if blank)")


def main() -> None:
    base = Path(__file__).resolve().parent.parent
    env = EnvFile(base / ".env")
    addr = os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")
    conf = Path(env.get("DOCK_CONF") or "/dock/conf")
    bootstrap(addr, env, conf)


if __name__ == "__main__":
    main()
