#!/usr/bin/env python3
"""
undo-entra.py  —  Reverse Authentik-side changes made by set-auth.py entra-setup.

STAGE -> PAUSE -> SUBMIT (safe-by-default, per global doctrine §5 and Rec 5):
  This script issues live, destructive writes against the PRODUCTION Authentik /
  Entra control plane (deletes groups/policies/bindings, disables the federation
  source, restores login stages). It therefore defaults to STAGE mode: every
  mutation is printed as "[STAGE] WOULD: ..." and NOT executed. Re-run with
  --submit to actually apply. Reads always run, so the staged plan reflects the
  real current state.

Operations (full undo, no operation flags):
  1. Disable entra-id OAuth2 source
  2. Remove access-group expression policy binding from the authorization flow
  3. Restore the password login stage in the authentication flow

Flags:
  --submit              Execute the mutations. Without it, the script only STAGES
                        (previews) them and changes nothing.
  --just-binding        Remove only the legacy access-group policy binding from the
                        authorization flow. Leaves the Entra source enabled and the
                        password stage as-is. Use this to clean up a superseded
                        monolithic gate binding without rolling back federation.
  --delete-entra-groups     Delete Entra groups recorded in the manifest with
                            was_created_by_us=true. Requires --manifest.
  --delete-authentik-groups Delete Authentik groups, policies, and bindings recorded in
                            the manifest with was_created_by_us=true. Requires --manifest.
  --manifest PATH       Path to entra-setup-manifest.json written by entra-setup.
                        Default: <stack>/scripts/output/entra-setup-manifest.json

Does NOT delete the App Registration, synced users, or .env credentials.
Runnable any time. No Graph API calls for the core undo — works even when Entra is down.

Usage:
    python3 scripts/undo-entra.py [path/to/.env]                 # STAGE (preview only)
    python3 scripts/undo-entra.py [path/to/.env] --submit        # SUBMIT (apply)
    python3 scripts/undo-entra.py [path/to/.env] --just-binding [--submit] [--manifest PATH]
"""

import argparse
import json
import sys
from pathlib import Path

from utils import EnvFile, AuthentikClient, red, green, yellow, step, resolve_admin_token

_STACK_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_MANIFEST = _STACK_DIR / "scripts" / "output" / "entra-setup-manifest.json"


def _gate(submit: bool, desc: str) -> bool:
    """STAGE -> SUBMIT gate for a single destructive mutation.

    In submit mode, returns True so the caller executes the mutation.
    In stage mode (the default), prints the planned action as
    ``[STAGE] WOULD: <desc>`` and returns False so the caller skips it.
    Modelled on prod-host ``infra/backup/sync-backup.sh:run()``.
    """
    if submit:
        return True
    yellow(f"  [STAGE] WOULD: {desc}")
    return False


def _build_ak(env: EnvFile) -> "AuthentikClient | None":
    token = resolve_admin_token(env)
    if not token:
        red("No admin token in .env (AUTHENTIK_API_TOKEN or AUTHENTIK_BOOTSTRAP_TOKEN)")
        return None
    auth_sub = env.get("AUTHENTIK_SUBDOMAIN") or "auth"
    public_fqdn = env.get("PUBLIC_FQDN")
    if not public_fqdn:
        red("PUBLIC_FQDN not set in .env")
        return None
    base_url = f"https://{auth_sub}.{public_fqdn}"
    ak = AuthentikClient(base_url, token)
    step(f"Verifying Authentik at {base_url}")
    try:
        ak.get("core/users/", page_size="1")
        green("  Authentik reachable")
    except Exception as exc:
        red(f"Cannot reach Authentik: {exc}")
        return None
    return ak


def _remove_policy_binding_from_auth_flow(
    ak: AuthentikClient, policy_name: str, submit: bool = False
) -> bool:
    """Find the named expression policy and delete any bindings it has on the authorization flow.

    Returns True if at least one binding was removed (or, in stage mode, *would* be
    removed), False if there was nothing to remove. The count is independent of
    ``submit`` so the staged preview summary is accurate.
    """
    policies = ak.get("policies/expression/", name=policy_name).get("results", [])
    if not policies:
        yellow(f"  Policy '{policy_name}' not found — nothing to unbind")
        return False

    policy_pk = policies[0]["pk"]
    auth_flows = ak.get("flows/instances/", designation="authorization").get("results", [])
    auth_flow_pks = {f["pk"] for f in auth_flows}

    # Fetch all bindings for this policy, filter to authorization-flow targets
    page = 1
    removed = 0
    while True:
        resp = ak.get("policies/bindings/", policy=policy_pk, page=str(page), page_size="100")
        for b in resp.get("results", []):
            if str(b.get("target")) in auth_flow_pks:
                if _gate(submit, f"DELETE policies/bindings/{b['pk']}/ "
                                 f"(policy={policy_name} → authorization flow)"):
                    ak.delete(f"policies/bindings/{b['pk']}/")
                    green(f"  Removed binding pk={b['pk']} (policy={policy_name} → authorization flow)")
                removed += 1
        if not resp.get("pagination", {}).get("next"):
            break
        page += 1

    if removed == 0:
        yellow(f"  Policy '{policy_name}' exists but has no authorization-flow bindings — nothing removed")
    return removed > 0


def do_just_binding(ak: AuthentikClient, env: EnvFile, submit: bool = False) -> int:
    """Remove only the legacy monolithic access-group policy binding from the authorization flow."""
    step("--just-binding: removing legacy authorization-flow policy binding")
    access_group = env.get("ENTRA_ACCESS_GROUP") or ""
    removed_any = False

    if access_group:
        policy_name = f"entra-access-{access_group}"
        green(f"  Targeting policy: {policy_name!r} (from ENTRA_ACCESS_GROUP={access_group!r})")
        removed_any = _remove_policy_binding_from_auth_flow(ak, policy_name, submit)
    else:
        yellow("  ENTRA_ACCESS_GROUP not set — no specific policy to target")

    if not removed_any:
        yellow("  No bindings removed. Verify ENTRA_ACCESS_GROUP matches the policy you want to remove.")
    return 0


def do_delete_authentik_groups(ak: AuthentikClient, manifest_path: Path, submit: bool = False) -> int:
    """Delete Authentik groups, policies, and bindings recorded in the manifest as was_created_by_us."""
    if not manifest_path.exists():
        red(f"Manifest not found: {manifest_path}")
        red("Run 'set-auth.py entra-setup' first to generate the manifest.")
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = 0

    step("Deleting Authentik policy bindings (was_created_by_us=true)")
    for entry in manifest.get("authentik_policy_bindings", []):
        if not entry.get("was_created_by_us"):
            continue
        pk = entry.get("pk")
        if not pk:
            continue
        if not _gate(submit, f"DELETE policies/bindings/{pk}/"):
            continue
        try:
            ak.delete(f"policies/bindings/{pk}/")
            green(f"  Deleted policy binding pk={pk}")
        except Exception as exc:
            yellow(f"  Could not delete binding pk={pk}: {exc}")
            errors += 1

    step("Deleting Authentik expression policies (was_created_by_us=true)")
    for entry in manifest.get("authentik_expression_policies", []):
        if not entry.get("was_created_by_us"):
            continue
        pk = entry.get("pk")
        if not pk:
            continue
        if not _gate(submit, f"DELETE policies/expression/{pk}/ ({entry.get('name', '')})"):
            continue
        try:
            ak.delete(f"policies/expression/{pk}/")
            green(f"  Deleted expression policy pk={pk} ({entry.get('name', '')})")
        except Exception as exc:
            yellow(f"  Could not delete policy pk={pk}: {exc}")
            errors += 1

    step("Deleting Authentik groups (was_created_by_us=true)")
    for entry in manifest.get("authentik_groups", []):
        if not entry.get("was_created_by_us"):
            continue
        pk = entry.get("pk")
        if not pk:
            continue
        if not _gate(submit, f"DELETE core/groups/{pk}/ ({entry.get('name', '')})"):
            continue
        try:
            ak.delete(f"core/groups/{pk}/")
            green(f"  Deleted Authentik group pk={pk} ({entry.get('name', '')})")
        except Exception as exc:
            yellow(f"  Could not delete group pk={pk}: {exc}")
            errors += 1

    return 1 if errors else 0


def do_delete_entra_groups(manifest_path: Path, env: EnvFile, submit: bool = False) -> int:
    """Delete Entra groups recorded in the manifest as was_created_by_us. Requires Graph write creds."""
    if not manifest_path.exists():
        red(f"Manifest not found: {manifest_path}")
        red("Run 'set-auth.py entra-setup' first to generate the manifest.")
        return 1

    # Import lazily — only needed when actually deleting Entra groups
    try:
        from utils_entra import _graph_client_for  # type: ignore[import]
    except ImportError:
        red("utils_entra not importable — cannot delete Entra groups")
        return 1

    gc = _graph_client_for(env, "write")
    if gc is None:
        red("ENTRA_WRITE_CLIENT_ID/SECRET not configured — cannot delete Entra groups")
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = 0

    step("Deleting Entra groups (was_created_by_us=true)")
    for entry in manifest.get("entra_groups", []):
        if not entry.get("was_created_by_us"):
            continue
        group_id = entry.get("id")
        if not group_id:
            continue
        if not _gate(submit, f"DELETE graph.microsoft.com/v1.0/groups/{group_id} "
                             f"({entry.get('display_name', '')})"):
            continue
        try:
            gc._request("DELETE", f"https://graph.microsoft.com/v1.0/groups/{group_id}")
            green(f"  Deleted Entra group id={group_id} ({entry.get('display_name', '')})")
        except Exception as exc:
            yellow(f"  Could not delete Entra group id={group_id}: {exc}")
            errors += 1

    return 1 if errors else 0


def do_full_undo(ak: AuthentikClient, env: EnvFile, submit: bool = False) -> int:
    """Original three-step undo: disable source, remove binding, restore password stage."""
    # Step 1: Disable entra-id source
    step("Step 1 — Disabling entra-id OAuth2 source")
    sources = ak.get("sources/oauth/", slug="entra-id").get("results", [])
    if sources:
        source_pk = sources[0]["pk"]
        if _gate(submit, f"PATCH sources/oauth/{source_pk}/ enabled=False (disable entra-id source)"):
            ak.patch(f"sources/oauth/{source_pk}/", {"enabled": False})
            green("  entra-id source disabled (config preserved)")
    else:
        yellow("  entra-id source not found — nothing to disable")

    # Step 2: Remove access-group policy binding from authorization flow
    step("Step 2 — Removing access-group policy binding from authorization flow")
    access_group = env.get("ENTRA_ACCESS_GROUP") or ""
    if access_group:
        policy_name = f"entra-access-{access_group}"
        _remove_policy_binding_from_auth_flow(ak, policy_name, submit)
    else:
        yellow("  ENTRA_ACCESS_GROUP not set — skipping policy unbind")

    # Step 3: Restore password login stage in authentication flow
    step("Step 3 — Restoring password login stage to authentication flow")
    auth_flows = ak.get("flows/instances/", designation="authentication").get("results", [])
    if auth_flows:
        flow_pk = auth_flows[0]["pk"]
        bindings = ak.get("flows/bindings/", target=flow_pk).get("results", [])
        restored = False
        for binding in bindings:
            stage_pk = binding.get("stage")
            if not stage_pk:
                continue
            try:
                stage = ak.get(f"stages/identification/{stage_pk}/")
                if stage.get("pk") and stage.get("password_stage") is None:
                    pw_stages = ak.get("stages/password/").get("results", [])
                    patch: dict = {"user_fields": ["username", "email"]}
                    if pw_stages:
                        patch["password_stage"] = pw_stages[0]["pk"]
                    if _gate(submit, f"PATCH stages/identification/{stage_pk}/ "
                                     f"(restore password stage + user_fields)"):
                        if pw_stages:
                            green(f"  Restored password stage '{pw_stages[0]['name']}' to identification stage")
                        else:
                            yellow("  No password stage found to restore")
                        ak.patch(f"stages/identification/{stage_pk}/", patch)
                        green("  Restored user_fields to ['username', 'email']")
                    restored = True
                    break
            except RuntimeError:
                continue
        if not restored:
            yellow("  Identification stage not found or password_stage already set — no change")
    else:
        yellow("  No authentication flow found — skipping")

    if _gate(submit, "set ENTRA_LOCAL_LOGIN_RESTORED=true in .env"):
        env.force_set("ENTRA_LOCAL_LOGIN_RESTORED", "true")
        green("  ENTRA_LOCAL_LOGIN_RESTORED=true written to .env")

    admins_resp = ak.get("core/users/", is_superuser="true", is_active="true")
    admin_names = [u["username"] for u in admins_resp.get("results", [])]
    green(f"\nLocal logins restored.")
    green(f"Break-glass admin account(s): {', '.join(admin_names) if admin_names else '(none found!)'}")
    yellow("IMPORTANT: Verify you can log in with a local admin account before closing this terminal.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="undo-entra.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "env_path", nargs="?", default=None,
        metavar="PATH",
        help="Path to .env (default: <stack>/.env)",
    )
    parser.add_argument(
        "--submit", action="store_true",
        help="Execute mutations. Without it the script only STAGES (previews) them.",
    )
    parser.add_argument(
        "--just-binding", action="store_true",
        help="Remove only the legacy authorization-flow policy binding; leave source and password stage unchanged",
    )
    parser.add_argument(
        "--manifest", metavar="PATH", default=None,
        help=f"Path to entra-setup-manifest.json (default: {_DEFAULT_MANIFEST})",
    )
    parser.add_argument(
        "--delete-entra-groups", action="store_true",
        help="Delete Entra security groups recorded in the manifest with was_created_by_us=true",
    )
    parser.add_argument(
        "--delete-authentik-groups", action="store_true",
        help="Delete Authentik groups, policies, and bindings recorded in the manifest with was_created_by_us=true",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    submit = args.submit

    env_path = Path(args.env_path) if args.env_path else _STACK_DIR / ".env"
    if not env_path.exists():
        red(f".env not found: {env_path}")
        return 1
    env = EnvFile(env_path)

    manifest_path = Path(args.manifest) if args.manifest else _DEFAULT_MANIFEST

    if not submit:
        yellow("=" * 68)
        yellow("  STAGE MODE — destructive undo will be PLANNED, not executed.")
        yellow("  Review the [STAGE] WOULD lines, then re-run with --submit to apply.")
        yellow("=" * 68)

    ak = _build_ak(env)
    if ak is None:
        return 1

    rc = 0

    if args.just_binding:
        rc = do_just_binding(ak, env, submit)
    elif not (args.delete_entra_groups or args.delete_authentik_groups):
        rc = do_full_undo(ak, env, submit)

    if args.delete_authentik_groups:
        rc = max(rc, do_delete_authentik_groups(ak, manifest_path, submit))

    if args.delete_entra_groups:
        rc = max(rc, do_delete_entra_groups(manifest_path, env, submit))

    if not submit:
        yellow("\n  STAGE complete — nothing was changed. Re-run with --submit to apply.")

    return rc


if __name__ == "__main__":
    sys.exit(main())
