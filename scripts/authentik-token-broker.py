#!/usr/bin/env python3
"""
authentik-token-broker.py — Mint (or retrieve) a scoped Authentik service-account
API token bootstrap-independently and store it securely.

The broker uses the `ak shell` stdin-pipe pattern to call the Authentik Django ORM
directly inside the container — this is the ONLY way to obtain a non-expiring
INTENT_API token (the HTTP API forces expiring=True).

Run contexts
------------
Host (zero-touch / run.sh)          : local `docker exec -i` → --store env
Workstation (operator escrow)       : `--ssh-host admin@HOST` → --store keyring (auto on Windows)

Usage
-----
    python3 scripts/authentik-token-broker.py [env_path] \\
        --identifier claude-automation \\
        --store {auto,keyring,env,bao} \\
        [--ssh-host admin@192.0.2.10] \\
        [--apply]

    --apply  force_set AUTHENTIK_API_TOKEN in the (host) .env so set-auth picks it up.

Env var names (never print values, key names only)
---------------------------------------------------
  AUTHENTIK_API_TOKEN       : the scoped service token the broker mints  (force_set, re-mintable)
  AUTHENTIK_BOOTSTRAP_TOKEN : desynced admin token (immutable per ADR-0017; to be revoked)
  AUTHENTIK_OUTPOST_TOKEN   : proxy outpost token (managed by set-auth)
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

# Authentik token keys are base64url strings (secrets.token_urlsafe(40+)).
# They contain mixed-case letters, digits, hyphens, and underscores — no spaces.
# This pattern filters out `ak shell` banner lines ("N objects imported…",
# "### authentik shell…") which always contain spaces or start with '#'.
_TOKEN_RE = re.compile(r"^[0-9A-Za-z_\-]{20,}$")

# ── Path bootstrap (mirrors gen-secrets.py:55) ────────────────────────────────
# Ensure siblings (utils, cred_store, immutable_keys, …) are importable when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils import EnvFile, red, green, yellow, step  # noqa: E402

import cred_store as _cs  # noqa: E402
from cred_store import EnvStore  # noqa: E402,F401 — re-exported; tests import via this module

# ── Defaults ───────────────────────────────────────────────────────────────────
_SCRIPTS_DIR = Path(__file__).resolve().parent
_STACK_DIR = _SCRIPTS_DIR.parent
_DEFAULT_ENV = _STACK_DIR / ".env"
_CONTAINER = "authentik-server"
_DEFAULT_IDENTIFIER = "claude-automation"
_SERVICE_NAME = "authentik-token-broker"

# ── Django snippet executed inside the container via `ak shell` stdin ──────────
# `Token.objects.get_or_create()` (standard manager) is used instead of the
# former `Token.objects.including_expired().get_or_create()` — the
# `including_expired()` custom manager method was removed in Authentik ≥2026.2.
# Non-expiring tokens (expiring=False) are not filtered by the default manager
# so this is equivalent for our use-case.  expiring=False bypasses the HTTP API
# restriction that forces expiring=True for INTENT_API tokens.
# sys.stdout.flush() is required: ak shell uses block-buffered stdout in pipe
# mode (Python 3.14+), so without an explicit flush the key is never captured.
_MINT_SNIPPET_TEMPLATE = """\
import sys
from authentik.core.models import Token, TokenIntents, User
u = User.objects.get(username="akadmin")
t, _ = Token.objects.get_or_create(
    identifier={identifier_repr},
    defaults={{
        "user": u,
        "intent": TokenIntents.INTENT_API,
        "expiring": False,
        "description": "claude automation service token",
    }},
)
sys.stdout.write(t.key + "\\n")
sys.stdout.flush()
"""


# ── Token mint ─────────────────────────────────────────────────────────────────

ExecFn = Callable[[str], str]
"""A callable that takes a Python snippet (str) and returns the raw stdout (str)."""


def _build_local_exec_fn() -> ExecFn:
    """Return an exec_fn that pipes the snippet to `docker exec -i <container> ak shell`."""
    def _exec(snippet: str) -> str:
        result = subprocess.run(
            ["docker", "exec", "-i", _CONTAINER, "ak", "shell"],
            input=snippet,
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Raise on nonzero exit unconditionally — banner text in stdout must not
        # mask a snippet exception.  The caller (mint_or_get_token) validates that
        # the output contains a real token key; if the snippet crashed the banner-
        # only stdout will produce no hex candidates and raise a descriptive error.
        if result.returncode != 0:
            raise RuntimeError(
                f"`ak shell` exited {result.returncode}; "
                f"stderr: {result.stderr.strip()[:300]}"
            )
        return result.stdout
    return _exec


def _build_ssh_exec_fn(ssh_host: str) -> ExecFn:
    """Return an exec_fn that tunnels through SSH then pipes to `docker exec -i`."""
    def _exec(snippet: str) -> str:
        # The snippet is passed via SSH stdin, forwarded to docker exec -i.
        # Quoting hell is avoided entirely — no shell interpolation of the snippet.
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                ssh_host,
                "docker", "exec", "-i", _CONTAINER, "ak", "shell",
            ],
            input=snippet,
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"SSH+`ak shell` exited {result.returncode}; "
                f"stderr: {result.stderr.strip()[:300]}"
            )
        return result.stdout
    return _exec


def mint_or_get_token(identifier: str, exec_fn: ExecFn) -> str:
    """Idempotently mint (or retrieve) the Authentik API token for *identifier*.

    Runs the Django ORM `get_or_create` snippet inside the container via *exec_fn*
    and returns the plaintext key.  The key is NEVER printed or logged by this
    function; callers decide what to do with it.

    Raises RuntimeError with a descriptive (non-secret) message on failure.
    """
    snippet = _MINT_SNIPPET_TEMPLATE.format(
        identifier_repr=json.dumps(identifier),  # safe quoting, no injection
    )
    raw_output = exec_fn(snippet)

    # Extract the token key by matching the expected hex format rather than relying
    # on line position.  `ak shell` emits a banner ("N objects imported…") that
    # may appear before OR after the snippet's print() depending on the Authentik /
    # Python version — positional heuristics ("last line") break across versions.
    lines = [l.strip() for l in raw_output.splitlines() if l.strip()]
    if not lines:
        raise RuntimeError(
            "mint_or_get_token: `ak shell` produced no output — "
            "snippet may have raised an exception (check container logs)"
        )
    token_candidates = [l for l in lines if _TOKEN_RE.match(l)]
    if not token_candidates:
        raise RuntimeError(
            "mint_or_get_token: no hex token key found in `ak shell` output — "
            "snippet may have raised an exception or `ak shell` format changed. "
            f"Non-empty output lines (first 5): {lines[:5]!r}"
        )
    token_key = token_candidates[-1]
    return token_key


# ── Credential stores ──────────────────────────────────────────────────────────
# EnvStore is imported directly from cred_store (stdlib-only, force-write semantics).
# KeyringStore wraps cred_store.KeyringStore with the broker's fixed service name
# and uses the broker's local `platform` reference so tests can monkeypatch it.


class KeyringStore(_cs.KeyringStore):
    """OS keyring wrapper hardwired to the authentik-token-broker service name.

    Uses the broker's ``platform`` reference so tests can monkeypatch
    ``authentik_token_broker.platform`` without also having to patch cred_store.
    """

    _SERVICE = _SERVICE_NAME

    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise RuntimeError(
                "KeyringStore: no headless backend available on Linux; "
                "use --store env|bao"
            )
        self._service = _SERVICE_NAME

    def store(self, key: str, token: str) -> None:
        self._kr().set_password(self._service, key, token)
        print(f"  stored {key} in OS keyring")


class BaoStore(_cs.CredStore):
    """OpenBao backend stub — not implemented in this broker CLI.

    A clean extension point for when the vault is operational.
    """

    def store(self, key: str, token: str) -> None:
        raise NotImplementedError(
            "BaoStore: OpenBao backend is not implemented yet. "
            "Use --store env (host/run.sh path) or --store keyring (Windows workstation)."
        )

    def retrieve(self, key: str) -> str | None:
        raise NotImplementedError("BaoStore: OpenBao backend is not implemented yet.")

    def delete(self, key: str) -> None:
        raise NotImplementedError("BaoStore: OpenBao backend is not implemented yet.")


def _auto_select_store(env_path: Path) -> _cs.CredStore:
    """Auto-select the best available store for the current platform.

    Windows  → ``KeyringStore`` (DPAPI)
    Linux    → ``EnvStore``     (headless-safe; never keyring on Linux)
    """
    if platform.system() == "Windows":
        return KeyringStore()
    return EnvStore(env_path)


def _make_store(name: str, env_path: Path) -> _cs.CredStore:
    """Instantiate the requested credential store backend by name."""
    if name == "auto":
        return _auto_select_store(env_path)
    if name == "keyring":
        return KeyringStore()
    if name == "env":
        return EnvStore(env_path)
    if name == "bao":
        return BaoStore()
    raise ValueError(f"Unknown store: {name!r}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authentik-token-broker.py",
        description=(
            "Mint (or retrieve) a scoped Authentik service-account API token "
            "bootstrap-independently and store it securely."
        ),
    )
    p.add_argument(
        "env_path",
        nargs="?",
        type=Path,
        default=_DEFAULT_ENV,
        metavar="ENV_PATH",
        help=f"Path to .env file (default: {_DEFAULT_ENV})",
    )
    p.add_argument(
        "--identifier",
        default=_DEFAULT_IDENTIFIER,
        help=f"Token identifier in Authentik DB (default: {_DEFAULT_IDENTIFIER!r})",
    )
    p.add_argument(
        "--store",
        choices=["auto", "keyring", "env", "bao"],
        default="auto",
        help=(
            "Secret storage backend: "
            "auto=Windows→keyring/Linux→env, "
            "keyring=OS keyring (Windows DPAPI), "
            "env=force_set into .env, "
            "bao=OpenBao (stub, raises NotImplementedError)"
        ),
    )
    p.add_argument(
        "--ssh-host",
        metavar="USER@HOST",
        default=None,
        help=(
            "Run docker exec via SSH (workstation context). "
            "Example: admin@192.0.2.10"
        ),
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help=(
            "force_set AUTHENTIK_API_TOKEN in the .env file after minting. "
            "Required for set-auth.py to pick up the new token."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns an exit code (0 = success, 1 = failure)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    env_path: Path = args.env_path.resolve()
    identifier: str = args.identifier
    store_name: str = args.store
    ssh_host: str | None = args.ssh_host
    apply: bool = args.apply

    # ── Validate env_path ──────────────────────────────────────────────────────
    if not env_path.exists():
        red(f"ERROR: .env not found: {env_path}")
        return 1

    # ── Build exec_fn ──────────────────────────────────────────────────────────
    if ssh_host:
        step(f"Run context: workstation → SSH {ssh_host} → docker exec")
        exec_fn = _build_ssh_exec_fn(ssh_host)
    else:
        step("Run context: host → local docker exec")
        exec_fn = _build_local_exec_fn()

    # ── Mint or retrieve token ─────────────────────────────────────────────────
    step(f"Minting/retrieving Authentik API token (identifier={identifier!r})")
    try:
        token_key = mint_or_get_token(identifier, exec_fn)
    except RuntimeError as exc:
        red(f"ERROR: {exc}")
        return 1

    green(f"  token key obtained (identifier={identifier!r}, length={len(token_key)})")

    # ── Store token ────────────────────────────────────────────────────────────
    step(f"Storing token via backend: {store_name!r}")
    try:
        store = _make_store(store_name, env_path)
        store.store("AUTHENTIK_API_TOKEN", token_key)
    except (RuntimeError, NotImplementedError) as exc:
        red(f"ERROR: {exc}")
        return 1

    # ── Apply to .env (force_set — always reconcile to live DB truth) ──────────
    # --apply writes AUTHENTIK_API_TOKEN into the host .env so set-auth picks it up.
    # force_set is ALWAYS used here — never set_if_blank — because the token is
    # re-mintable (e.g. after an Authentik DB reset) and must reconcile to live truth.
    if apply:
        step("Applying AUTHENTIK_API_TOKEN to .env (force_set)")
        try:
            env = EnvFile(env_path)
            env.force_set("AUTHENTIK_API_TOKEN", token_key)
        except Exception as exc:
            red(f"ERROR writing AUTHENTIK_API_TOKEN to .env: {exc}")
            return 1
        green("  AUTHENTIK_API_TOKEN written to .env")

    yellow(
        "\nNext steps:\n"
        "  1. Run: python3 scripts/set-auth.py authentik\n"
        "  2. Verify: docker ps → authentik-proxy is 'healthy'\n"
        "  3. After any Authentik DB reset: re-run this broker (--apply) to re-mint"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
