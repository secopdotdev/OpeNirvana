"""List Authentik scope mappings and AFFiNE provider property_mappings."""
import json
import urllib.request
from pathlib import Path

env_file = Path(__file__).parent.parent / ".env"
env_text = env_file.read_text()
token = [l.split("=", 1)[1].strip() for l in env_text.splitlines()
         if l.startswith("AUTHENTIK_BOOTSTRAP_TOKEN=")][0]
base = "https://example.com/api/v3"


def req(method, path, body=None):
    url = base + "/" + path.lstrip("/")
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(url, data=data, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=20) as resp:
        return json.loads(resp.read())


mappings = req("GET", "propertymappings/scope/")
print("All scope mappings:")
for m in mappings["results"]:
    print("  pk=%s  scope=%s  name=%s" % (m["pk"], m.get("scope_name", ""), m["name"]))

# AFFiNE provider details (provider ID 4 — update if provider ID changes)
provider = req("GET", "providers/oauth2/4/")
print("\nAFFiNE provider property_mappings:", provider.get("property_mappings", []))
