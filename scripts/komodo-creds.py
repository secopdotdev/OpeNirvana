#!/usr/bin/env python3
"""komodo-creds.py — Seed and manage Komodo operator-provided secrets.

Unlike gen-secrets.py (random-value generation), these secrets are operator-provided:
a passkey the operator chooses, and OIDC client credentials issued by Authentik.

Subcommands
-----------
store  (Windows only)  — interactively prompt + store in DPAPI keyring
seed   (homelab)       — read from env vars, write-if-absent into OpenBao KV
show   (any platform)  — audit: list key names that are SET/MISSING (no values)

Deploy flow
-----------
1. Operator (Windows): python3 scripts/komodo-creds.py store
2. deploy.ps1 reads from DPAPI, SSH SetEnv to homelab
3. run.sh: BAO_ADDR=... DOCK_CONF=... python3 scripts/komodo-creds.py seed
4. bao-sync.py compiles OpenBao KV -> .env; docker compose reads .env
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import sys
from pathlib import Path
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cred_store import KeyringStore  # noqa: E402
from secrets_provider import BaoProvider  # noqa: E402

if TYPE_CHECKING:
    from bao_client import BaoClient as _BaoClientType

_SERVICE_NAME = "openirvana"

_KOMODO_SECRETS: dict[str, str] = {
    "KOMODO_PASSKEY": "Komodo Core<->Periphery passkey (generate a random 32+ char string)",
    "KOMODO_OIDC_CLIENT_ID": "Authentik OAuth2 client ID for Komodo",
    "KOMODO_OIDC_CLIENT_SECRET": "Authentik OAuth2 client secret for Komodo",
}


def _resolve_bao_token(env_path: Path | None = None) -> str:
    tok = os.environ.get("BAO_TOKEN", "")
    if tok:
        return tok
    dock_conf = os.environ.get("DOCK_CONF", "")
    if dock_conf:
        candidate = Path(dock_conf) / "openbao" / "init.json"
        if candidate.exists():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            tok = data.get("root_token", "")
            if tok:
                return tok
    if env_path is not None:
        candidate2 = env_path.parent / "openbao" / "init.json"
        if candidate2.exists():
            data2 = json.loads(candidate2.read_text(encoding="utf-8"))
            tok = data2.get("root_token", "")
            if tok:
                return tok
    raise RuntimeError(
        "Cannot resolve OpenBao root token. "
        "Set BAO_TOKEN env var or ensure ${DOCK_CONF}/openbao/init.json exists."
    )


def _build_bao_provider() -> BaoProvider:
    try:
        from bao_client import BaoClient  # type: ignore[import-not-found]
    except ImportError:
        raise RuntimeError("bao_client / hvac not importable. Run: pip install hvac") from None
    addr = os.environ.get("BAO_ADDR", "http://127.0.0.1:8200")
    token = _resolve_bao_token()
    bao: _BaoClientType = BaoClient(addr=addr, token=token)
    return BaoProvider(bao)


def cmd_store(args: argparse.Namespace) -> int:
    try:
        store = KeyringStore(_SERVICE_NAME)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for key, label in _KOMODO_SECRETS.items():
        if store.exists(key) and not args.force:
            answer = input(f"  {key} already stored. Overwrite? [y/N] ").strip().lower()
            if answer != "y":
                print(f"  Skipped {key}.")
                continue
        val = getpass.getpass(f"  {label}\n  {key}: ")
        if not val.strip():
            print(f"  Empty input -- skipped {key}.")
            continue
        if not args.dry_run:
            store.store(key, val)
        print(f"  {'[dry-run] ' if args.dry_run else ''}Stored {key}.")
    return 0


def cmd_seed(args: argparse.Namespace) -> int:
    missing = [k for k in _KOMODO_SECRETS if not os.environ.get(k, "")]
    if missing:
        print(
            f"error: missing env vars: {', '.join(missing)}\n"
            "  These must be passed from deploy.ps1 via SSH SetEnv.\n"
            "  Operator: run 'python3 scripts/komodo-creds.py store' on Windows first.",
            file=sys.stderr,
        )
        return 1
    if args.dry_run:
        for key in _KOMODO_SECRETS:
            print(f"  [dry-run] would seed {key} into OpenBao KV (write-if-absent)")
        return 0
    try:
        provider = _build_bao_provider()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for key in _KOMODO_SECRETS:
        val = os.environ[key]
        try:
            written = provider.set_if_blank(key, val)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        status = "SET " if written else "SKIP"
        label = "(written to OpenBao KV)" if written else "(already in OpenBao -- not overwritten)"
        print(f"  {status}  {key}  {label}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:  # noqa: ARG001
    if platform.system() != "Windows":
        print(
            "  (keyring not available on this platform -- check OpenBao KV directly)\n"
            "  Hint: docker exec openbao bao kv list secret/"
        )
        return 0
    try:
        store = KeyringStore(_SERVICE_NAME)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for key in _KOMODO_SECRETS:
        status = "SET    " if store.exists(key) else "MISSING"
        print(f"  {status}  {key}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="komodo-creds.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_store = sub.add_parser("store", help="Store secrets in DPAPI keyring (Windows)")
    p_store.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing values without prompting",
    )
    p_store.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview without writing to the keyring",
    )
    p_seed = sub.add_parser(
        "seed",
        help="Seed secrets from env vars into OpenBao KV (homelab deploy path)",
    )
    p_seed.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview without writing to OpenBao",
    )
    sub.add_parser("show", help="List which key names are SET/MISSING in the keyring")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    dispatch = {"store": cmd_store, "seed": cmd_seed, "show": cmd_show}
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
