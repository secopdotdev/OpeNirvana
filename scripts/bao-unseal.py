"""bao-unseal.py — re-unseal an initialized OpenBao from escrowed init.json (hvac client)."""
import json, os, sys
from pathlib import Path
from bao_client import BaoClient
from utils import EnvFile, green, red

def unseal_from_escrow(addr: str, init_path: Path) -> int:
    bao = BaoClient(addr)
    if not bao.seal_status().get("sealed", True):
        green("already unsealed"); return 0
    if not init_path.exists():
        red(f"init material not found: {init_path} — restore from escrow first"); return 2
    res = json.loads(init_path.read_text(encoding="utf-8"))
    for key in res.get("keys_base64", res.get("keys", [])):
        if not bao.unseal(key).get("sealed", True):
            green("unsealed"); return 0
    red("still sealed after submitting all keys"); return 3

def main() -> None:
    base = Path(__file__).resolve().parent.parent
    env = EnvFile(base / ".env")
    conf = Path(env.get("DOCK_CONF") or "/dock/conf")
    addr = os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")
    sys.exit(unseal_from_escrow(addr, conf / "openbao" / "init.json"))

if __name__ == "__main__":
    main()
