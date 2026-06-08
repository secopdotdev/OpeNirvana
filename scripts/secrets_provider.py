"""secrets_provider.py — pluggable secrets backend (ADR 0011).

Provides the SecretsProvider protocol and two implementations:
  EnvFileProvider — wraps utils.EnvFile (the existing write-only-if-blank .env writer)
  BaoProvider     — wraps bao_client.BaoClient (OpenBao KV v2)

Both normalize env-var keys: callers use UPPER_SNAKE_CASE; BaoProvider stores as
lower_snake_case in KV (matching what bao-sync.py compiles back to .env).
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from utils import EnvFile

if TYPE_CHECKING:
    from bao_client import BaoClient


@runtime_checkable
class SecretsProvider(Protocol):
    """Minimal interface for a read/write secrets store."""

    def get(self, key: str) -> str:
        """Return the current value for KEY, or '' if absent."""
        ...

    def set_if_blank(self, key: str, value: str) -> bool:
        """Write VALUE for KEY only if it is currently absent/empty.

        Returns True if the value was written, False if it was skipped.
        """
        ...


class EnvFileProvider:
    """SecretsProvider backed by a bash-style .env file (via utils.EnvFile)."""

    def __init__(self, path: Path) -> None:
        self._env = EnvFile(path)

    def get(self, key: str) -> str:
        return self._env.get(key)

    def set_if_blank(self, key: str, value: str) -> bool:
        # EnvFile.set_if_blank() returns None, not bool — check presence ourselves
        # so the Protocol's bool contract is honoured.
        if self.get(key):
            return False
        self._env.set_if_blank(key, value)
        return True


class BaoProvider:
    """SecretsProvider backed by OpenBao KV v2 (via bao_client.BaoClient).

    Keys are stored in lower_snake_case in KV (bao-sync.py convention).
    Callers pass UPPER_SNAKE_CASE; this class normalizes automatically.
    """

    def __init__(self, bao: "BaoClient", mount: str = "secret") -> None:
        self._bao = bao
        self._mount = mount

    def _kv_key(self, key: str) -> str:
        return key.lower()

    def get(self, key: str) -> str:
        data = self._bao.kv_get(self._kv_key(key), mount=self._mount)
        return data.get("value", "")

    def set_if_blank(self, key: str, value: str) -> bool:
        if self.get(key):
            return False
        self._bao.kv_put(self._kv_key(key), {"value": value}, mount=self._mount)
        return True
