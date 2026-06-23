#!/usr/bin/env python3
"""
set-auth.py — Unified auth setup driver for the stack.

Subcommands (one of these is required; if none given, runs the interactive menu):
  authentik        Provision Authentik forward-auth proxy providers/apps
  oidc             Provision Authentik OAuth2 providers for native-OIDC services
  nextcloud-oidc   Install + register Nextcloud user_oidc provider AND Talk HPB signaling
  entra-setup      Interactive: federate Authentik with Microsoft Entra
  entra-nesting    Provision Entra nested groups (Global Access + category → service groups)
  entra-sync       Non-interactive: sync Entra group members into Authentik
  entra-report     Read-only: access-control table
  entra-policies   Patch Authentik expression policies (service-group-only, no OR-logic)
  tailscale        Provision Tailscale ACL policy + tagged auth key (RBAC-aligned)
  all              Run authentik -> oidc -> nextcloud-oidc -> entra-nesting -> entra-sync -> tailscale

Without a subcommand and on a TTY, an interactive menu prompts the user.
Without a subcommand and NOT on a TTY, exits 2 with usage.
"""

import argparse
import sys
from pathlib import Path

from utils import EnvFile, red, green, yellow, step
import utils_authentik_proxy
import utils_authentik_oidc
import utils_entra
import utils_nextcloud
import utils_tailscale

_STACK_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_ENV = _STACK_DIR / ".env"

_SUBCOMMANDS = [
    ("authentik",       "Provision Authentik forward-auth proxy apps"),
    ("oidc",            "Provision Authentik OAuth2 providers for native-OIDC services"),
    ("nextcloud-oidc",  "Install + register user_oidc provider AND Talk HPB signaling"),
    ("entra-setup",     "Interactive: federate Authentik with Entra"),
    ("entra-nesting",   "Provision Entra nested groups (Global Access + category → service groups)"),
    ("entra-sync",      "Sync Entra group members into Authentik"),
    ("entra-report",    "Access-control report (read-only)"),
    ("entra-policies",  "Patch Authentik expression policies (service-group-only, no OR-logic)"),
    ("tailscale",       "Provision Tailscale ACL policy + tagged auth key (RBAC-aligned)"),
    ("all",             "Run authentik -> oidc -> nextcloud-oidc -> entra-nesting -> entra-sync -> tailscale"),
    ("revoke-bootstrap-token", "Clear AUTHENTIK_BOOTSTRAP_TOKEN and mark it revoked (idempotent)"),
]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="set-auth.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", default=str(_DEFAULT_ENV), metavar="PATH",
                   help=f"Path to .env (default: {_DEFAULT_ENV})")
    p.add_argument("--submit", action="store_true",
                   help="Execute live Entra/Authentik writes. Without it, the mutating "
                        "entra-* subcommands only STAGE (preview) and change nothing.")
    sub = p.add_subparsers(dest="cmd", metavar="SUBCOMMAND")

    sp_a = sub.add_parser("authentik", help=_SUBCOMMANDS[0][1])
    sp_a.add_argument("--caddyfile",
                      default=str(_STACK_DIR / "templates" / "caddy" / "Caddyfile"))
    sp_a.add_argument("--authentik-url", default="http://localhost:9000")
    sp_a.add_argument("--output-dir", default=str(_STACK_DIR / "scripts" / "output"))
    sp_a.add_argument("--dry-run", action="store_true")

    sp_o = sub.add_parser("oidc", help=_SUBCOMMANDS[1][1])
    sp_o.add_argument("--sync", action="store_true",
                      help="Refresh group bindings only; do not create providers")

    sub.add_parser("nextcloud-oidc", help=_SUBCOMMANDS[2][1])
    sub.add_parser("entra-setup",    help=_SUBCOMMANDS[3][1])
    sub.add_parser("entra-nesting",  help=_SUBCOMMANDS[4][1])
    sub.add_parser("entra-sync",     help=_SUBCOMMANDS[5][1])
    sub.add_parser("entra-report",   help=_SUBCOMMANDS[6][1])
    sub.add_parser("entra-policies", help=_SUBCOMMANDS[7][1])

    sp_ts = sub.add_parser("tailscale", help=_SUBCOMMANDS[8][1])
    sp_ts.add_argument(
        "--skip-entra", action="store_true",
        help="Skip Entra user group sync; ACL uses autogroup:member fallback",
    )

    sp_all = sub.add_parser("all",   help=_SUBCOMMANDS[9][1])
    sp_all.add_argument("--caddyfile",
                        default=str(_STACK_DIR / "templates" / "caddy" / "Caddyfile"))
    sp_all.add_argument("--authentik-url", default="http://localhost:9000")
    sp_all.add_argument("--output-dir", default=str(_STACK_DIR / "scripts" / "output"))
    sp_all.add_argument("--dry-run", action="store_true")

    sub.add_parser("revoke-bootstrap-token", help=_SUBCOMMANDS[10][1])
    return p


def _interactive_pick(env: EnvFile) -> str:
    """Prompt the user to choose a subcommand. Returns the subcommand string."""
    print("Available subcommands:\n")
    for i, (name, desc) in enumerate(_SUBCOMMANDS, 1):
        print(f"  {i}. {name:<16} {desc}")
    print()
    while True:
        raw = input(f"Choose [1-{len(_SUBCOMMANDS)}]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(_SUBCOMMANDS):
            return _SUBCOMMANDS[int(raw) - 1][0]
        yellow(f"  invalid selection: {raw!r}")


# Subcommands that issue live, non-trivially-reversible writes against the
# PRODUCTION Entra / Authentik control plane. These are gated behind --submit
# (STAGE -> PAUSE -> SUBMIT, per global doctrine §5 and Rec 5). entra-report is
# read-only and intentionally excluded. The fine-grained per-API dry-run inside
# utils_entra is tracked as a follow-up (see plans/<id>-impl.md, Rec 5 phase 2).
_ENTRA_MUTATING = {"entra-setup", "entra-nesting", "entra-sync", "entra-policies", "all"}


def _stage_notice(cmd: str, env: EnvFile) -> None:
    desc = dict(_SUBCOMMANDS).get(cmd, cmd)
    tenant = env.get("ENTRA_TENANT_ID") or "(ENTRA_TENANT_ID unset)"
    yellow("=" * 68)
    yellow(f"  STAGE MODE — '{cmd}' would perform LIVE control-plane writes.")
    yellow(f"    Operation     : {desc}")
    yellow(f"    Entra tenant  : {tenant}")
    yellow("    Nothing was executed. Re-run with --submit to apply.")
    yellow("=" * 68)


def _dispatch(cmd: str, args: argparse.Namespace, env: EnvFile) -> int:
    if cmd in _ENTRA_MUTATING and not getattr(args, "submit", False):
        _stage_notice(cmd, env)
        return 0
    if cmd == "authentik":
        return utils_authentik_proxy.run(args, env)
    if cmd == "oidc":
        return utils_authentik_oidc.run(args, env, sync_only=args.sync)
    if cmd == "nextcloud-oidc":
        return utils_nextcloud.run(args, env)
    if cmd == "entra-setup":
        return utils_entra.run_setup(env)
    if cmd == "entra-nesting":
        return utils_entra.run_nesting(env)
    if cmd == "entra-sync":
        return utils_entra.run_sync(env)
    if cmd == "entra-report":
        return utils_entra.run_report(env)
    if cmd == "entra-policies":
        return utils_entra.run_update_policies(env)
    if cmd == "tailscale":
        return utils_tailscale.run(env, sync_entra=not args.skip_entra)
    if cmd == "all":
        for fn_name in (
            "run_all_authentik", "run_all_oidc", "run_all_nextcloud_oidc",
            "run_all_entra_nesting", "run_all_entra_sync", "run_all_tailscale",
        ):
            rc = _dispatch_all_step(fn_name, args, env)
            if rc != 0:
                return rc
        return 0
    if cmd == "revoke-bootstrap-token":
        return _revoke_bootstrap_token(env)
    red(f"unknown subcommand: {cmd}")
    return 2


def _dispatch_all_step(name: str, args: argparse.Namespace, env: EnvFile) -> int:
    """Sequential 'all' runner. Each step is best-effort idempotent; first non-zero RC aborts."""
    if name == "run_all_authentik":
        step("set-auth: authentik")
        return utils_authentik_proxy.run(args, env)
    if name == "run_all_oidc":
        step("set-auth: oidc")
        return utils_authentik_oidc.run(args, env, sync_only=False)
    if name == "run_all_nextcloud_oidc":
        step("set-auth: nextcloud-oidc")
        return utils_nextcloud.run(args, env)
    if name == "run_all_entra_nesting":
        step("set-auth: entra-nesting")
        return utils_entra.run_nesting(env)
    if name == "run_all_entra_sync":
        step("set-auth: entra-sync")
        return utils_entra.run_sync(env)
    if name == "run_all_tailscale":
        step("set-auth: tailscale")
        return utils_tailscale.run(env, sync_entra=True)
    raise ValueError(f"unknown dispatch step: {name!r}")


def _revoke_bootstrap_token(env: EnvFile) -> int:
    """Atomically revoke the Authentik bootstrap token.

    Sets AUTHENTIK_BOOTSTRAP_TOKEN_REVOKED=true FIRST (marker-first order), then
    clears AUTHENTIK_BOOTSTRAP_TOKEN= to empty. This ordering is deliberate: if the
    process dies between the two writes, the marker is already set so gen-secrets will
    not re-generate the token on the next run — the safe intermediate state.
    Reverse order (clear token first) would leave a blank token + no marker, which
    causes gen-secrets to re-mint a new token on the next run, re-opening the desync
    hole that motivated this subcommand.

    Idempotent: safe to run multiple times.
    """
    revoked = env.get("AUTHENTIK_BOOTSTRAP_TOKEN_REVOKED")
    token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN")

    if revoked.lower() == "true" and not token:
        green("  revoke-bootstrap-token: already revoked and token already cleared — no-op")
        return 0

    # Marker first: next gen-secrets run is now a no-op for this key even if we crash here.
    env.force_set("AUTHENTIK_BOOTSTRAP_TOKEN_REVOKED", "true")
    # Clear the token: removes the live credential from .env (token is now DB-side only).
    env.force_set("AUTHENTIK_BOOTSTRAP_TOKEN", "")

    green("  revoke-bootstrap-token: AUTHENTIK_BOOTSTRAP_TOKEN cleared")
    green("  revoke-bootstrap-token: AUTHENTIK_BOOTSTRAP_TOKEN_REVOKED=true")
    green("  revoke-bootstrap-token: subsequent gen-secrets runs will skip this token")
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    env_path = Path(args.env)
    if not env_path.exists():
        red(f".env not found: {env_path}")
        return 1
    env = EnvFile(env_path)

    cmd = args.cmd
    if cmd is None:
        if not sys.stdin.isatty():
            parser.print_usage(sys.stderr)
            red("\nno subcommand and not a TTY -- refusing to prompt")
            return 2
        cmd = _interactive_pick(env)

    return _dispatch(cmd, args, env)


if __name__ == "__main__":
    sys.exit(main())
