#!/usr/bin/env python3
"""
ntfy-setup.py — Idempotent ntfy ACL provisioner.

Grants anonymous write-only access to the alert topics consumed by
Alertmanager (alerts) and Falco Sidekick (falco), then probes each
topic to confirm publish succeeds (HTTP 200, not 403).

ntfy runs with NTFY_AUTH_DEFAULT_ACCESS=deny-all so these ACL entries
are required before Alertmanager or Falco can deliver notifications.

Usage:
    python3 ntfy-setup.py [--container NAME]

Safe to re-run: ntfy silently succeeds when access is already granted.
"""

import argparse
import subprocess
import sys

_TOPICS = ["alerts", "falco"]
_DEFAULT_CONTAINER = "ntfy"


def _ntfy_exec(container: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, "ntfy", *args],
        capture_output=True,
        text=True,
    )


def _provision_acl(container: str, topic: str) -> None:
    r = _ntfy_exec(container, "access", "*", topic, "write-only")
    if r.returncode != 0:
        # ntfy prints "access control entry for ... already exists" to stdout
        # on duplicate; that is not an error.
        combined = (r.stdout + r.stderr).lower()
        if "already" in combined or "exists" in combined:
            print(f"  OK   {topic} (ACL already set)")
            return
        raise RuntimeError(
            f"ntfy access {topic!r} failed (rc={r.returncode}): {r.stderr.strip()}"
        )
    print(f"  GRANT {topic} write-only")


def _probe_topic(container: str, topic: str) -> None:
    """Publish a minimal test message from inside the container and verify 200."""
    r = subprocess.run(
        [
            "docker", "exec", container,
            "wget", "-qO-", "--post-data=preflight", f"http://localhost/{topic}",
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"probe to {topic!r} failed (403 or connection error). "
            f"ACL may not have applied yet. stderr: {r.stderr.strip()}"
        )
    print(f"  PROBE {topic} OK")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--container", default=_DEFAULT_CONTAINER,
                   help=f"ntfy container name (default: {_DEFAULT_CONTAINER})")
    args = p.parse_args()

    container = args.container

    # Verify the container is running before attempting exec.
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or r.stdout.strip() != "true":
        print(f"ntfy-setup: container {container!r} is not running — skipping", file=sys.stderr)
        return 0  # Non-fatal: ntfy may not be in the active profile.

    print(f"\n==> ntfy ACL provisioning ({container})")
    for topic in _TOPICS:
        _provision_acl(container, topic)
    for topic in _TOPICS:
        _probe_topic(container, topic)

    print("  ntfy ACL provisioning complete.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
