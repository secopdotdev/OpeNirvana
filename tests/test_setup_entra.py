import subprocess
import sys
import os
import pytest
from pathlib import Path


def test_graph_client_device_code_error_exits_1(tmp_path):
    """GraphClient.authenticate() exits 1 when MSAL returns an error dict."""
    # Fake msal: device flow succeeds but token acquisition fails
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
    def initiate_device_flow(self, scopes):
        return {"message": "Go to https://microsoft.com/devicelogin and enter CODE123"}
    def acquire_token_by_device_flow(self, flow):
        return {"error": "authorization_declined", "error_description": "User declined"}

class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
    def acquire_token_for_client(self, scopes):
        return {"error": "invalid_client"}
""")

    # Runner script: load setup-entra.py via importlib (avoids package import issues)
    # then call GraphClient.authenticate() which should exit 1
    script = Path(__file__).parent.parent / "scripts" / "setup-entra.py"
    runner = tmp_path / "run.py"
    runner.write_text(
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('setup_entra', r'{script}')\n"
        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
        "mod.GraphClient('fake-tenant').authenticate()\n"
    )

    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(tmp_path) + (os.pathsep + existing if existing else "")

    result = subprocess.run(
        [sys.executable, str(runner)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
        env=env,
    )
    assert result.returncode == 1
    assert "declined" in result.stderr or "Authentication failed" in result.stderr


def test_graph_client_credentials_error_exits_1(tmp_path):
    """GraphClient.from_client_credentials() exits 1 when MSAL returns an error dict."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
    def initiate_device_flow(self, scopes):
        return {"message": "Go to https://microsoft.com/devicelogin and enter CODE123"}
    def acquire_token_by_device_flow(self, flow):
        return {"access_token": "tok"}

class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
    def acquire_token_for_client(self, scopes):
        return {"error": "invalid_client"}
""")

    script = Path(__file__).parent.parent / "scripts" / "setup-entra.py"
    runner = tmp_path / "run.py"
    runner.write_text(
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('setup_entra', r'{script}')\n"
        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
        "mod.GraphClient.from_client_credentials('fake-tenant', 'fake-client-id', 'fake-secret')\n"
    )

    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(tmp_path) + (os.pathsep + existing if existing else "")

    result = subprocess.run(
        [sys.executable, str(runner)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
        env=env,
    )
    assert result.returncode == 1
    assert "invalid_client" in result.stderr or "Client credentials failed" in result.stderr


def test_msal_guard_exits_when_missing(tmp_path):
    """Script must exit 1 if msal is not installed."""
    # Run the script with a fake PYTHONPATH that shadows msal with a broken module
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("raise ImportError('msal not installed')\n")

    env = os.environ.copy()
    # Prepend tmp_path and strip any existing PYTHONPATH to ensure fake msal takes precedence
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = str(tmp_path) + os.pathsep + existing_pythonpath
    else:
        env["PYTHONPATH"] = str(tmp_path)

    result = subprocess.run(
        [sys.executable, "scripts/setup-entra.py", "--setup"],
        capture_output=True, text=True, env=env,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 1
    assert "pip install msal" in result.stderr


def test_find_or_create_app_returns_existing_without_post(tmp_path):
    """_find_or_create_app returns existing app without POSTing if one is found."""
    # This test imports the module directly using importlib
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "setup_entra",
        str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
    )
    # We need msal to be importable — use the fake from test 1
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys
    _sys.path.insert(0, str(tmp_path))
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        gc = MagicMock()
        gc.get.return_value = {"value": [{"id": "app-id-123", "appId": "client-id-abc", "web": {"redirectUris": ["https://existing.com/"]}}]}

        obj_id, client_id = mod._find_or_create_app(gc, "Authentik-Sync", ["https://existing.com/"])
        gc.post.assert_not_called()
        assert obj_id == "app-id-123"
        assert client_id == "client-id-abc"
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)  # clean up fake msal from module cache
        # Also clean up the loaded module itself
        _sys.modules.pop("setup_entra", None)


def test_find_or_create_group_returns_existing(tmp_path):
    """_find_or_create_group returns existing group without POSTing."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys, importlib.util
    _sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location(
            "setup_entra",
            str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        gc = MagicMock()
        gc.get.return_value = {"value": [{"id": "group-id-xyz", "displayName": "openirvana-homies"}]}

        gid = mod._find_or_create_group(gc, "openirvana-homies")
        gc.post.assert_not_called()
        assert gid == "group-id-xyz"
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)
        _sys.modules.pop("setup_entra", None)


def test_find_or_create_authentik_source_skips_post_if_existing(tmp_path):
    """_find_or_create_authentik_source returns existing pk without POST."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys, importlib.util
    _sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location(
            "setup_entra",
            str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        ak = MagicMock()
        ak.get.return_value = {"results": [{"pk": "src-pk-1", "slug": "entra-id"}]}

        pk = mod._find_or_create_authentik_source(
            ak, "fake-tenant", "entra-client-id", "entra-client-secret"
        )
        ak.post.assert_not_called()
        assert pk == "src-pk-1"
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)
        _sys.modules.pop("setup_entra", None)


def test_find_or_create_expression_policy_skips_post_if_existing(tmp_path):
    """_find_or_create_expression_policy returns existing pk without POST."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys, importlib.util
    _sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location(
            "setup_entra",
            str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        ak = MagicMock()
        policy_name = "entra-access-openirvana-homies"
        ak.get.return_value = {"results": [{"pk": "pol-pk-1", "name": policy_name}]}

        pk = mod._find_or_create_expression_policy(ak, "openirvana-homies")
        ak.post.assert_not_called()
        assert pk == "pol-pk-1"
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)
        _sys.modules.pop("setup_entra", None)


def test_verify_break_glass_exits_when_no_admin(tmp_path):
    """_verify_break_glass_account exits 1 when no active superuser exists."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys, importlib.util
    _sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location(
            "setup_entra",
            str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        ak = MagicMock()
        ak.get.return_value = {"results": []}  # no superusers

        with pytest.raises(SystemExit) as exc:
            mod._verify_break_glass_account(ak)
        assert exc.value.code == 1
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)
        _sys.modules.pop("setup_entra", None)


def test_upsert_authentik_user_creates_missing_user(tmp_path):
    """_upsert_authentik_user creates a new user when no match found by email."""
    fake_msal = tmp_path / "msal.py"
    fake_msal.write_text("""
class PublicClientApplication:
    def __init__(self, *a, **kw): pass
class ConfidentialClientApplication:
    def __init__(self, *a, **kw): pass
""")
    import sys as _sys, importlib.util
    _sys.path.insert(0, str(tmp_path))
    try:
        spec = importlib.util.spec_from_file_location(
            "setup_entra",
            str(Path(__file__).parent.parent / "scripts" / "setup-entra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from unittest.mock import MagicMock
        ak = MagicMock()
        ak.get.return_value = {"results": []}  # no existing user
        ak.post.return_value = {"pk": "new-user-pk", "username": "john.doe"}

        action, pk = mod._upsert_authentik_user(ak, {
            "id": "entra-id-123",
            "displayName": "John Doe",
            "mail": "john.doe@example.com",
            "userPrincipalName": "john.doe@example.com",
            "accountEnabled": True,
        })
        assert action == "created"
        assert pk == "new-user-pk"
        ak.post.assert_called_once()
    finally:
        _sys.path.remove(str(tmp_path))
        _sys.modules.pop("msal", None)
        _sys.modules.pop("setup_entra", None)


def test_undo_entra_exits_1_when_no_token(tmp_path):
    """undo-entra.py must exit 1 if AUTHENTIK_BOOTSTRAP_TOKEN is absent."""
    env_file = tmp_path / ".env"
    env_file.write_text("PUBLIC_FQDN=example.com\n")

    result = subprocess.run(
        [sys.executable, "scripts/undo-entra.py", str(env_file)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 1
    assert "AUTHENTIK_BOOTSTRAP_TOKEN" in result.stderr
