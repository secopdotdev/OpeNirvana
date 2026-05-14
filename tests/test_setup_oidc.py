import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


SCRIPT = Path(__file__).parent.parent / "scripts" / "setup-oidc.py"


def _load():
    """Load setup-oidc.py as a module, clean up after each test."""
    spec = importlib.util.spec_from_file_location("setup_oidc", str(SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    sys.modules.pop("setup_oidc", None)


# ── Task 1 tests ──────────────────────────────────────────────────────────────

def test_get_app_pk_returns_pk_when_found():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": [{"pk": "app-pk-abc"}]}

    result = mod._get_app_pk(ak, "nextcloud")

    ak.get.assert_called_once_with("core/applications/", slug="nextcloud")
    assert result == "app-pk-abc"


def test_get_app_pk_returns_none_when_not_found():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": []}

    result = mod._get_app_pk(ak, "doesnotexist")

    assert result is None


def test_provision_service_skips_and_returns_app_pk_when_id_already_set(tmp_path):
    mod = _load()
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NEXTCLOUD_OIDC_CLIENT_ID=existing-id\n"
        "NEXTCLOUD_OIDC_CLIENT_SECRET=existing-secret\n"
    )
    env = mod.EnvFile(env_file)
    ak = MagicMock()
    ak.get.return_value = {"results": [{"pk": "app-pk-xyz"}]}

    cid, csec, app_pk = mod.provision_service(
        ak, env,
        slug="nextcloud", name="Nextcloud",
        redirect_uris=[], auth_flow_pk="af", invalidation_flow_pk="if",
        signing_key_pk="sk", property_mappings=[],
        id_var="NEXTCLOUD_OIDC_CLIENT_ID", secret_var="NEXTCLOUD_OIDC_CLIENT_SECRET",
    )

    assert cid == "existing-id"
    assert csec == "existing-secret"
    assert app_pk == "app-pk-xyz"
    # Should not create provider or app
    ak.post.assert_not_called()


# ── Task 2 tests ──────────────────────────────────────────────────────────────

import subprocess


def test_missing_env_file_exits_1(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "nonexistent.env")],
        capture_output=True, text=True,
        cwd=str(SCRIPT.parent.parent),
        env={**os.environ, "PYTHONPATH": str(SCRIPT.parent)},
    )
    assert result.returncode == 1
    assert "not found" in result.stderr


def test_sync_flag_accepted_without_error_on_missing_env(tmp_path):
    """--sync is a valid flag (argparse should not exit 2 for unknown option)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "x.env"), "--sync"],
        capture_output=True, text=True,
        cwd=str(SCRIPT.parent.parent),
        env={**os.environ, "PYTHONPATH": str(SCRIPT.parent)},
    )
    # exits 1 (missing .env), NOT 2 (argparse unknown flag)
    assert result.returncode == 1
    assert "not found" in result.stderr


# ── Task 3 tests ──────────────────────────────────────────────────────────────

import json as _json
import urllib.error
from io import BytesIO
from unittest.mock import patch, MagicMock


def _make_http_response(body: dict, status: int = 200):
    """Return a fake urllib response object."""
    data = _json.dumps(body).encode()
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_graph_client_acquires_token_on_first_call():
    mod = _load()
    token_resp = _make_http_response({"access_token": "tok-123", "expires_in": 3600})
    get_resp   = _make_http_response({"value": []})

    with patch("urllib.request.urlopen", side_effect=[token_resp, get_resp]):
        gc = mod.GraphClient("tenant", "cid", "csec")
        result = gc.get("groups")

    assert result == {"value": []}
    assert gc._token == "tok-123"


def test_graph_client_reuses_cached_token():
    mod = _load()
    get_resp = _make_http_response({"value": [{"id": "g1"}]})

    gc = mod.GraphClient("t", "c", "s")
    gc._token = "already-cached"

    with patch("urllib.request.urlopen", return_value=get_resp) as mock_open:
        gc.get("groups")

    # Only one urlopen call (the GET) — token was cached, no POST to /token
    assert mock_open.call_count == 1


def test_graph_client_retries_on_429():
    mod = _load()
    token_resp = _make_http_response({"access_token": "t", "expires_in": 3600})

    err_429 = urllib.error.HTTPError(
        url="https://graph.microsoft.com/v1.0/groups",
        code=429, msg="Too Many Requests", hdrs=MagicMock(get=lambda k, d="10": "1"),
        fp=BytesIO(b"rate limited"),
    )
    ok_resp = _make_http_response({"value": []})

    with patch("urllib.request.urlopen", side_effect=[token_resp, err_429, ok_resp]), \
         patch("time.sleep") as mock_sleep:
        gc = mod.GraphClient("t", "c", "s")
        result = gc.get("groups")

    mock_sleep.assert_called_once_with(1)
    assert result == {"value": []}


def test_load_graph_client_returns_none_when_credentials_missing(tmp_path, capsys):
    mod = _load()
    env_file = tmp_path / ".env"
    env_file.write_text("PUBLIC_FQDN=example.com\n")
    env = mod.EnvFile(env_file)

    gc = mod._load_graph_client(env)

    assert gc is None
    captured = capsys.readouterr()
    assert "OIDC_ENTRA" in captured.out or "OIDC_ENTRA" in captured.err


def test_load_graph_client_returns_graph_client_when_all_credentials_set(tmp_path):
    mod = _load()
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OIDC_ENTRA_TENANT_ID=t1\n"
        "OIDC_ENTRA_CLIENT_ID=c1\n"
        "OIDC_ENTRA_CLIENT_SECRET=s1\n"
    )
    env = mod.EnvFile(env_file)

    gc = mod._load_graph_client(env)

    assert gc is not None
    assert gc._tenant_id == "t1"
    assert gc._client_id == "c1"
    assert gc._client_secret == "s1"


# ── Task 4 tests ──────────────────────────────────────────────────────────────

def test_discover_running_services_returns_names():
    mod = _load()
    fake_result = MagicMock()
    fake_result.stdout = "nextcloud\ntandoor\npostgres\n"
    fake_result.returncode = 0

    with patch("subprocess.run", return_value=fake_result):
        services = mod._discover_running_services()

    assert services == ["nextcloud", "tandoor", "postgres"]


def test_discover_running_services_returns_empty_on_error():
    mod = _load()
    with patch("subprocess.run", side_effect=FileNotFoundError):
        services = mod._discover_running_services()
    assert services == []


def test_discover_running_services_returns_empty_on_nonzero_exit(capsys):
    mod = _load()
    fake_result = MagicMock()
    fake_result.stdout = ""
    fake_result.returncode = 1
    with patch("subprocess.run", return_value=fake_result):
        services = mod._discover_running_services()
    assert services == []


def test_ensure_entra_group_returns_existing_id_without_post():
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {"value": [{"id": "entra-id-123"}]}

    gid = mod._ensure_entra_group(gc, "authentik-nextcloud")

    gc.get.assert_called_once_with(
        "groups",
        **{"$filter": "displayName eq 'authentik-nextcloud'", "$select": "id,displayName"},
    )
    gc.post.assert_not_called()
    assert gid == "entra-id-123"


def test_ensure_entra_group_creates_group_when_absent():
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {"value": []}
    gc.post.return_value = {"id": "new-entra-id"}

    gid = mod._ensure_entra_group(gc, "authentik-nextcloud")

    gc.post.assert_called_once_with("groups", {
        "displayName":     "authentik-nextcloud",
        "mailNickname":    "authentik-nextcloud",
        "securityEnabled": True,
        "mailEnabled":     False,
        "groupTypes":      [],
    })
    assert gid == "new-entra-id"


def test_ensure_authentik_group_returns_existing_pk_without_post():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": [{"pk": "ak-grp-pk"}]}

    pk = mod._ensure_authentik_group(ak, "entra-nextcloud")

    ak.post.assert_not_called()
    assert pk == "ak-grp-pk"


def test_ensure_authentik_group_creates_group_when_absent():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": []}
    ak.post.return_value = {"pk": "new-ak-pk"}

    pk = mod._ensure_authentik_group(ak, "entra-nextcloud")

    ak.post.assert_called_once_with("core/groups/", {"name": "entra-nextcloud"})
    assert pk == "new-ak-pk"


# ── Task 5 tests ──────────────────────────────────────────────────────────────

def test_ensure_policy_binding_skips_post_when_binding_exists():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": [{"pk": "binding-pk", "group": "grp-pk-456"}]}

    mod._ensure_policy_binding(ak, "app-pk-123", "grp-pk-456")

    ak.get.assert_called_once_with("policies/bindings/", target="app-pk-123")
    ak.post.assert_not_called()


def test_ensure_policy_binding_creates_binding_when_absent():
    mod = _load()
    ak = MagicMock()
    ak.get.return_value = {"results": []}

    mod._ensure_policy_binding(ak, "app-pk-123", "grp-pk-456")

    ak.get.assert_called_once_with("policies/bindings/", target="app-pk-123")
    ak.post.assert_called_once_with("policies/bindings/", {
        "target":  "app-pk-123",
        "group":   "grp-pk-456",
        "enabled": True,
        "order":   0,
    })


# ── Task 6 tests ──────────────────────────────────────────────────────────────

def test_sync_skips_member_with_no_email(capsys):
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {
        "value": [{"id": "e1", "displayName": "No Email User", "mail": None,
                   "userPrincipalName": "nomail@example.com"}],
    }
    ak = MagicMock()
    ak.get.return_value = {"users": []}

    mod._sync_group_membership(gc, ak, "entra-grp-id", "ak-grp-pk")

    ak.post.assert_not_called()
    captured = capsys.readouterr()
    assert "SKIPPED" in captured.out


def test_sync_adds_existing_authentik_user_to_group(capsys):
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {
        "value": [{"id": "e1", "displayName": "Jane", "mail": "jane@example.com",
                   "userPrincipalName": "jane@example.com"}],
    }
    ak = MagicMock()
    # group has no current members; user search finds existing user
    ak.get.side_effect = [
        {"users": []},          # group members
        {"results": [{"pk": 42}]},  # user lookup by email
    ]

    mod._sync_group_membership(gc, ak, "entra-grp-id", "ak-grp-pk")

    ak.post.assert_called_once_with(
        "core/groups/ak-grp-pk/add_user/", {"pk": 42}
    )
    captured = capsys.readouterr()
    assert "ADDED" in captured.out


def test_sync_skips_already_member(capsys):
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {
        "value": [{"id": "e1", "displayName": "Jane", "mail": "jane@example.com",
                   "userPrincipalName": "jane@example.com"}],
    }
    ak = MagicMock()
    ak.get.side_effect = [
        {"users": [42]},             # already a member
        {"results": [{"pk": 42}]},   # user lookup by email
    ]

    mod._sync_group_membership(gc, ak, "entra-grp-id", "ak-grp-pk")

    ak.post.assert_not_called()
    captured = capsys.readouterr()
    assert "ALREADY MEMBER" in captured.out


def test_sync_creates_user_when_not_in_authentik(capsys):
    mod = _load()
    gc = MagicMock()
    gc.get.return_value = {
        "value": [{"id": "e1", "displayName": "New User", "mail": "new@example.com",
                   "userPrincipalName": "new@example.com"}],
    }
    ak = MagicMock()
    ak.get.side_effect = [
        {"users": []},       # group has no members
        {"results": []},     # user not found by email
    ]
    ak.post.side_effect = [
        {"pk": 99},          # create user
        {},                  # add_user
    ]

    mod._sync_group_membership(gc, ak, "entra-grp-id", "ak-grp-pk")

    ak.post.assert_any_call("core/users/", {
        "username":  "new@example.com",
        "name":      "New User",
        "email":     "new@example.com",
        "type":      "external",
        "is_active": True,
    })
    assert ak.post.call_count == 2
    captured = capsys.readouterr()
    assert "CREATED+ADDED" in captured.out
