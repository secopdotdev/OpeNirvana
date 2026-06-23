"""cred_store.py — service-namespaced credential storage abstraction.

Canonical source: github.com/your-org/cloudflare-toolkit (private).
This is a LOCAL COPY — do not edit here; update the canonical and re-copy.
Migration: add cloudflare-toolkit to docker-host-config.sh:install_python_packages(),
  then replace `from cred_store import` with `from cloudflare_toolkit.cred_store import`.

Backends
--------
KeyringStore  — OS keyring (Windows DPAPI). Raises on non-Windows.
                service_name maps directly to the keyring service — no prefix.
                Preserves any legacy service names already in use.
EnvStore      — .env file (always available; force-write by default).
                stdlib-only; no dependency on utils.EnvFile.
BaoStore      — OpenBao KV v2 via duck-typed client (kv_put/kv_get/kv_delete).
                Compatible with bao_client.BaoClient or any hvac-based adapter.

Usage
-----
    from cred_store import make_store, auto_select_store

    store = make_store("auto", service_name="my-service", env_path=Path(".env"))
    store.store("MY_TOKEN", secret_value)
    token = store.retrieve("MY_TOKEN")  # str | None
    store.delete("MY_TOKEN")
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import tempfile
import time
from pathlib import Path


# ── Base class ─────────────────────────────────────────────────────────────────

class CredStore:
    """Abstract base for credential storage backends."""

    def store(self, key: str, value: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def retrieve(self, key: str) -> str | None:  # pragma: no cover
        raise NotImplementedError

    def delete(self, key: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        return self.retrieve(key) is not None


# ── KeyringStore ───────────────────────────────────────────────────────────────

class KeyringStore(CredStore):
    """OS keyring backend (Windows DPAPI on Windows).

    ``service_name`` maps directly to the keyring service — no wrapping prefix.
    This preserves existing credentials stored under legacy service names
    (e.g. ``"authentik-token-broker"``, ``"vcenter:192.0.2.10"``).

    ``keyring`` is imported lazily so this module loads cleanly on Linux/macOS
    hosts without the package installed; they cannot instantiate this backend
    (the constructor raises on non-Windows).

    delete() propagates ``keyring.errors.PasswordDeleteError`` to the caller;
    callers that want idempotent deletion must catch it themselves.

    Raises:
        RuntimeError: on non-Windows platforms.
    """

    def __init__(self, service_name: str) -> None:
        if platform.system() != "Windows":
            raise RuntimeError(
                "KeyringStore: no secure headless backend available on "
                "Linux/macOS — use EnvStore (deploy path) or BaoStore (vault)."
            )
        self._service = service_name

    def _kr(self):  # type: ignore[return]
        try:
            import keyring  # type: ignore[import-not-found]  # pyright: ignore
            return keyring
        except ImportError:
            raise RuntimeError(
                "KeyringStore: `keyring` package not installed — "
                "run: pip install keyring"
            ) from None

    def store(self, key: str, value: str) -> None:
        self._kr().set_password(self._service, key, value)

    def retrieve(self, key: str) -> str | None:
        return self._kr().get_password(self._service, key)

    def delete(self, key: str) -> None:
        # PasswordDeleteError propagates — idempotent wrappers must catch it.
        self._kr().delete_password(self._service, key)


# ── EnvStore ───────────────────────────────────────────────────────────────────

class EnvStore(CredStore):
    """Credential store backed by a .env file.

    stdlib-only — no dependency on utils.EnvFile — so this module is
    self-contained when copied across repos.

    store() always force-writes (credentials must reconcile to live truth).
    delete() writes an empty value (key is preserved but cleared).
    """

    _MAX_RETRIES = 10  # Windows antivirus/indexer lock resilience

    def __init__(self, env_path: Path) -> None:
        self._env_path = Path(env_path)

    def _read(self) -> str:
        if not self._env_path.exists():
            return ""
        return self._env_path.read_text(encoding="utf-8")

    def _atomic_write(self, content: str) -> None:
        fd, tmp = tempfile.mkstemp(
            dir=str(self._env_path.parent),
            prefix=".cred_store.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            for attempt in range(self._MAX_RETRIES):
                try:
                    os.replace(tmp, str(self._env_path))
                    return
                except PermissionError:
                    if attempt == self._MAX_RETRIES - 1:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    def store(self, key: str, value: str) -> None:
        content = self._read()
        new, count = re.subn(
            rf"^{re.escape(key)}=.*$",
            f"{key}={value}",
            content,
            flags=re.MULTILINE,
        )
        if not count:
            new = content.rstrip("\n") + f"\n{key}={value}\n"
        self._atomic_write(new)

    def retrieve(self, key: str) -> str | None:
        content = self._read()
        m = re.search(rf"^{re.escape(key)}=(.*)$", content, re.MULTILINE)
        if not m:
            return None
        val = m.group(1).rstrip("\r").strip()
        # Strip surrounding single or double quotes.
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        return val if val else None

    def delete(self, key: str) -> None:
        self.store(key, "")


# ── BaoStore ───────────────────────────────────────────────────────────────────

class BaoStore(CredStore):
    """OpenBao KV v2 backend.

    Accepts any object with ``kv_put``, ``kv_get``, and ``kv_delete`` methods.
    Compatible with ``bao_client.BaoClient`` and any hvac-based adapter.

    KV layout::

        <path_prefix>/<key.lower()>  →  {"value": "<secret>"}

    Args:
        client:      Duck-typed client (kv_put / kv_get / kv_delete).
        mount:       KV v2 mount point (default: ``"secret"``).
        path_prefix: KV path prefix for credentials (default: ``"creds"``).
    """

    def __init__(
        self,
        client: object,
        mount: str = "secret",
        path_prefix: str = "creds",
    ) -> None:
        self._client = client
        self._mount = mount
        self._path_prefix = path_prefix.strip("/")

    def _kv_path(self, key: str) -> str:
        return f"{self._path_prefix}/{key.lower()}"

    def store(self, key: str, value: str) -> None:
        self._client.kv_put(  # type: ignore[union-attr]
            self._kv_path(key), {"value": value}, mount=self._mount
        )

    def retrieve(self, key: str) -> str | None:
        data = self._client.kv_get(  # type: ignore[union-attr]
            self._kv_path(key), mount=self._mount
        )
        return data.get("value") or None

    def delete(self, key: str) -> None:
        self._client.kv_delete(  # type: ignore[union-attr]
            self._kv_path(key), mount=self._mount
        )


# ── Convenience helpers ────────────────────────────────────────────────────────

def auto_select_store(
    service_name: str,
    env_path: Path | None = None,
    *,
    prefer_bao: bool = False,
) -> CredStore:
    """Return the best available CredStore for the current platform.

    * Windows → ``KeyringStore(service_name)`` (DPAPI).
    * Linux/macOS + *env_path* → ``EnvStore(env_path)``.
    * Linux/macOS, no *env_path* → ``RuntimeError``.

    If *prefer_bao* is ``True`` and ``BAO_ADDR`` + ``BAO_TOKEN`` are present in
    the environment, attempts to return a ``BaoStore`` backed by ``bao_client.BaoClient``.
    Falls through to platform defaults on import failure or connection error.

    .. warning::
        Never set *prefer_bao=True* in scripts that write vault credentials during
        OpenBao bootstrap — doing so creates a circular dependency.
    """
    if prefer_bao:
        bao_addr = os.environ.get("BAO_ADDR", "")
        bao_token = os.environ.get("BAO_TOKEN", "")
        if bao_addr and bao_token:
            try:
                from bao_client import BaoClient  # type: ignore[import-not-found]
                return BaoStore(BaoClient(addr=bao_addr, token=bao_token))
            except (ImportError, Exception):
                pass  # Fall through to platform defaults.
    if platform.system() == "Windows":
        return KeyringStore(service_name)
    if env_path is not None:
        return EnvStore(env_path)
    raise RuntimeError(
        "auto_select_store: no secure backend on Linux/macOS without env_path — "
        "provide --env-path or use --store bao."
    )


def make_store(
    name: str,
    service_name: str,
    env_path: Path | None = None,
    bao_client: object | None = None,
) -> CredStore:
    """Instantiate a CredStore backend by name.

    Args:
        name:        ``"auto"`` | ``"keyring"`` | ``"env"`` | ``"bao"``
        service_name: Keyring namespace (``KeyringStore`` only).
        env_path:    Path to .env file (``EnvStore`` and Linux auto-select).
        bao_client:  Duck-typed BaoClient (``BaoStore`` only).

    Raises:
        ValueError:   Unknown *name* or missing required arg.
        RuntimeError: Platform constraint (e.g. ``KeyringStore`` on Linux).
    """
    if name == "auto":
        return auto_select_store(service_name, env_path)
    if name == "keyring":
        return KeyringStore(service_name)
    if name == "env":
        if env_path is None:
            raise ValueError("make_store: env_path required for --store env")
        return EnvStore(env_path)
    if name == "bao":
        if bao_client is None:
            raise ValueError("make_store: bao_client required for --store bao")
        return BaoStore(bao_client)
    raise ValueError(f"make_store: unknown store name {name!r}")


# ── CredBroker ─────────────────────────────────────────────────────────────────

class CredBroker:
    """Lightweight scaffolding for credential broker scripts.

    Provides parser helpers and store construction. Existing brokers
    (authentik-token-broker, zot-cred-broker) predate this class and are not
    migrated. New broker scripts should use these helpers.
    """

    @staticmethod
    def add_store_args(parser: argparse.ArgumentParser) -> None:
        """Add ``--store``, ``--env-path``, and ``--dry-run`` to *parser*."""
        parser.add_argument(
            "--store",
            choices=["auto", "keyring", "env", "bao"],
            default="auto",
            help="Credential store backend (default: auto).",
        )
        parser.add_argument(
            "--env-path",
            type=Path,
            default=None,
            metavar="PATH",
            help="Path to .env file (required for --store env or auto on Linux).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview actions without writing files or storing credentials.",
        )

    @staticmethod
    def build_store(
        args: argparse.Namespace,
        service_name: str,
        bao_client: object | None = None,
    ) -> CredStore | None:
        """Return the CredStore described by *args*, or ``None`` if ``--dry-run``.

        Raises:
            ValueError:   Unknown store name or missing required arg.
            RuntimeError: Platform constraint (e.g. KeyringStore on Linux).
        """
        if getattr(args, "dry_run", False):
            return None
        return make_store(
            args.store,
            service_name=service_name,
            env_path=getattr(args, "env_path", None),
            bao_client=bao_client,
        )
