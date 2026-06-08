"""bao_client.py — OpenBao (Vault-compatible) client backed by hvac.

Thin adapter over hvac.Client preserving the historical BaoClient method surface
so consumer scripts (bao-bootstrap, bao-sync, bao-unseal, gen-secrets) and their
tests are unaffected by the transport swap. hvac exceptions are translated to the
contracts callers already expect:
  - a missing KV path (hvac.exceptions.InvalidPath) -> empty result (was HTTP 404 -> {})
  - mount/auth "already enabled" (hvac VaultError) -> RuntimeError(msg), so
    bao-bootstrap's idempotency check (`if "already" in str(e).lower()`) keeps working.

Dependency installed via docker-host-config.sh:install_python_packages (ADR 0002).
"""
from typing import Optional

import hvac
from hvac import exceptions as hvac_exc


class BaoClient:
    def __init__(self, addr: str, token: Optional[str] = None,
                 verify: bool = True) -> None:
        self.addr = addr.rstrip("/")
        # verify is honored for https endpoints; harmless for the loopback http default.
        self._client = hvac.Client(url=self.addr, token=token, verify=verify)

    # token lives on the hvac client; proxy it so callers can do `bao.token = root`.
    @property
    def token(self) -> Optional[str]:
        return self._client.token

    @token.setter
    def token(self, value: Optional[str]) -> None:
        # hvac stubs type Client.token as `str`, but None (clear the token) is valid
        # at runtime and part of this adapter's historical contract.
        self._client.token = value  # type: ignore[assignment]

    # --- seal lifecycle ---
    def health(self) -> dict:
        return self._client.sys.read_health_status(method="GET")

    def seal_status(self) -> dict:
        return self._client.sys.read_seal_status()

    def init(self, shares: int = 1, threshold: int = 1) -> dict:
        return self._client.sys.initialize(secret_shares=shares,
                                           secret_threshold=threshold)

    def unseal(self, key: str) -> dict:
        return self._client.sys.submit_unseal_key(key=key)

    # --- mounts / auth / audit / policy ---
    def enable_kv_v2(self, mount: str = "secret") -> None:
        try:
            self._client.sys.enable_secrets_engine(
                backend_type="kv", path=mount, options={"version": "2"})
        except hvac_exc.VaultError as exc:
            raise RuntimeError(str(exc)) from exc

    def enable_approle(self) -> None:
        try:
            self._client.sys.enable_auth_method(method_type="approle")
        except hvac_exc.VaultError as exc:
            raise RuntimeError(str(exc)) from exc

    def enable_audit_file(self, name: str = "file",
                          file_path: str = "/openbao/audit/audit.log") -> None:
        # Unused by consumers: audit is declared in openbao.hcl, not enabled via API
        # (OpenBao 2.x forbids API audit-device enable). Kept for surface parity.
        try:
            self._client.sys.enable_audit_device(
                device_type="file", path=name, options={"file_path": file_path})
        except hvac_exc.VaultError as exc:
            raise RuntimeError(str(exc)) from exc

    def put_policy(self, name: str, hcl: str) -> None:
        self._client.sys.create_or_update_policy(name=name, policy=hcl)

    # --- KV v2 ---
    def kv_put(self, path: str, data: dict, mount: str = "secret") -> dict:
        return self._client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data, mount_point=mount)

    def kv_get(self, path: str, mount: str = "secret") -> dict:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount, raise_on_deleted_version=False)
        except hvac_exc.InvalidPath:
            return {}                       # absent key — matches old 404 -> {}
        return resp.get("data", {}).get("data", {})

    def list_keys(self, mount: str = "secret") -> list[str]:
        try:
            resp = self._client.secrets.kv.v2.list_secrets(path="", mount_point=mount)
        except hvac_exc.InvalidPath:
            return []                       # no secrets yet — matches old 404 -> []
        return resp.get("data", {}).get("keys", [])

    # --- AppRole ---
    def create_approle(self, role: str, policies: list[str],
                       token_ttl: str = "20m", secret_id_ttl: str = "0") -> None:
        self._client.auth.approle.create_or_update_approle(
            role_name=role, token_policies=policies, token_ttl=token_ttl,
            secret_id_ttl=secret_id_ttl, secret_id_num_uses=0)

    def read_role_id(self, role: str) -> str:
        return self._client.auth.approle.read_role_id(
            role_name=role)["data"]["role_id"]

    def gen_secret_id(self, role: str) -> str:
        return self._client.auth.approle.generate_secret_id(
            role_name=role)["data"]["secret_id"]

    def approle_login(self, role_id: str, secret_id: str) -> str:
        resp = self._client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        auth = resp.get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise RuntimeError(f"AppRole login returned no client_token: {resp!r}")
        return token
