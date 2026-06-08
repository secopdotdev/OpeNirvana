"""Inspect n8n container security configuration via docker inspect."""
import subprocess
import json

r = subprocess.run(["docker", "inspect", "n8n"], capture_output=True, text=True)
d = json.loads(r.stdout)[0]
print("Mounts:")
for m in d["Mounts"]:
    print(f"  {m['Source']} -> {m['Destination']} RW={m['RW']} Mode={m['Mode']}")
print("\nUser:", d["Config"].get("User", "(none)"))
print("SecurityOpt:", d["HostConfig"].get("SecurityOpt"))
print("CapDrop:", d["HostConfig"].get("CapDrop"))
print("ReadonlyRootfs:", d["HostConfig"].get("ReadonlyRootfs"))
