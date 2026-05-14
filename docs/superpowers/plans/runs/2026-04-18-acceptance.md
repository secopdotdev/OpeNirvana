# Unified Stack Pilot — Acceptance Run (2026-04-18 → 2026-04-19)

**Target host:** `streamer` — Ubuntu 25.10, 6 cores, 15 GB RAM, Docker 29.4.0 + Compose v5.1.3, pre-existing Docker install.
**Tier used:** HIGH (user-selected; note: host is below HIGH-tier RAM recommendation of 64 GB+).
**Repo path:** `/srv/unified-stack` (not `/home/docktaetor/unified-stack` because `docktaetor` is created *by* the bootstrap, not before it).
**Runner:** Claude Code from Windows dev host via `ssh rooter@streamer`, sudo via temporary `NOPASSWD`.

## Result: PARTIAL — stack healthy, public ingress blocked on Tailscale ACL

15 of 15 stack services healthy after two sessions of fixes (including refactor to Wazuh 3-node indexer cluster per user direction). `tailscale-ingress` remains the sole blocker — new authkey still rejected by tailnet ACL (`tag:ingress` not permitted). Caddy depends on `tailscale-ingress` network, so public/tailnet ingress (Steps 4–9 browser login) is still untested.

## Current stack state (2026-04-19)

```
authentik-server   healthy
authentik-worker   healthy
autoheal           healthy
crowdsec           healthy
falco              healthy
postgres           healthy
redis              healthy
socket-proxy-ro    healthy
socket-proxy-rw    healthy
wazuh-dashboard    healthy
wazuh-indexer-1    healthy   (3-node cluster green)
wazuh-indexer-2    healthy
wazuh-indexer-3    healthy
wazuh-manager      healthy
zeek               healthy
wazuh-init             exited 0  (cert generator, one-shot)
wazuh-security-init    exited 0  (security plugin bootstrap, one-shot)
authentik-migration    exited 0  (DB migration, one-shot)
tailscale-ingress      stopped    BLOCKED on tailnet ACL
caddy                  never started (depends on tailscale-ingress)
```

## Verified

| Step | Result |
|---|---|
| 1 — Fresh-host bootstrap idempotence | PASS after 8 fix commits. 2nd run produces only UFW backup-timestamp diffs (cosmetic). |
| 2 — Cold-start timing | 17 s to `up -d` return (HIGH tier, xcaddy layers cached). |
| 3 — Service health | 15/15 running services healthy; 3 one-shot init containers exited 0. |
| Partial 10 — pg-backup dry-run | Can be exercised independently; Postgres up. |

## Bugs found and fixed (all committed to branch `media`)

Session 1 (initial run):

| # | Commit | Defect | Fix |
|---|---|---|---|
| 1 | `7e75f83` | `wazuh-agent-ingest.sh` checked `command -v wazuh-control`; binary at `/var/ossec/bin/`. | Check `[ -x /var/ossec/bin/wazuh-control ]`. |
| 2 | `d1e629b` | `generate_missing_secrets` pipe dies under `pipefail` when grep matches nothing. | `while … done < <(grep … \|\| true)`. |
| 3 | `aaef979` | Wazuh agent script chowned `root:ossec`; Ubuntu pkg uses `wazuh`. | `root:wazuh`. |
| 4 | `40c3ef0` | `sed -i` splicing `ossec.conf` broke on inline XML `<`. | `awk` splice. |
| 5 | `90e24f2` | `x-hardened` anchor's `security_opt: seccomp:default` — no such shorthand. | Dropped (Docker default seccomp applies when unset). |
| 6 | `51d0da0` | `x-hardened` anchor's uniform `user: "1010:1010"` broke indexer, socket-proxy, etc. | Removed from anchor; explicit `user:` per service. |

Session 2 (cold-start fixes):

| # | Commit | Defect | Fix |
|---|---|---|---|
| 7 | `15332dd` | `install -d /dock` left parents owned by root; recursive chown stopped short. | Recursive `chown -R docktaetor:media /dock`. |
| 8 | `28b2b4c` | Redis, crowdsec restart loops from per-service user perms; crowdsec template referenced offline `online_client`. | Per-service `user:` + cap overrides; strip `online_client` block. |
| 9 | `a57e196` | Crowdsec couldn't write to image-default dirs under `/etc/crowdsec`. | Bind full `/etc/crowdsec` + seed image defaults from `/staging`. |
| 10 | `33d5285` | Falco `rules_files` (not plural in template), missing `container` plugin, malformed `outputs_queue`; zeek `node.cfg` bad integer + `local.zeek` missing. | Correct falco.yaml schema; fix zeek worker-count integer and node file. |
| 11 | `a2a754d` | Wazuh refactored from single-node to 3-indexer cluster + 1 manager + 1 dashboard per user direction; custom entrypoint doesn't translate `node.name=X` env → config. | Added `node.name: ${NODE_NAME}` to `opensearch.yml` (OpenSearch native `${VAR}` substitution); added idempotent `wazuh-security-init` one-shot to bootstrap security plugin and patch reserved-user passwords via `securityadmin.sh` + `hash.sh`. |
| 12 | `6caeee3` | Authentik server/worker `PermissionError: /media/public` — container uid 1000 vs host `docktaetor(1010):media(1010)`. | `create_dock_tree` chowns `/dock/conf/authentik` + `/dock/data/authentik` to `1000:1000`. |

In addition, several empty secrets were backfilled in `.env` during cold-start (REDIS_PASSWORD, POSTGRES_SUPERUSER_PASSWORD, AUTHENTIK_SECRET_KEY, AUTHENTIK_DB_PASSWORD, AUTHENTIK_BOOTSTRAP_PASSWORD, AUTHENTIK_BOOTSTRAP_TOKEN, CROWDSEC_BOUNCER_KEY, CLOUDFLARE_API_TOKEN) — the secret-generation step in bootstrap now covers these but the first run's `.env` was written before the fix landed. Not a spec bug, just an artifact of fix-order during this run.

## Outstanding blocker

### `tailscale-ingress` — tag ACL rejection (NOT a key problem)

Both the original and the user-supplied replacement authkey (`tskey-auth-kHUr65XDKF11CNTRL-…`) produce:

```
Received error: requested tags [tag:ingress] are invalid or not permitted
health(warnable=login-state): error: You are logged out. The last login error was:
  requested tags [tag:ingress] are invalid or not permitted
```

The sidecar passes `TS_EXTRA_ARGS=--advertise-tags=tag:ingress`. The tailnet's ACL policy at login.tailscale.com doesn't define or permit that tag. The key itself is accepted by the control plane; the tag advertisement is what's rejected.

**User action required** — choose one:

1. **Add `tag:ingress` to tailnet ACL `tagOwners`** (recommended; permanent fix). In the Tailscale admin console → Access controls:
   ```json
   "tagOwners": {
     "tag:ingress": ["autogroup:admin"]
   }
   ```
   Then also grant the authkey-issuing user the right to assert the tag (the authkey must be issued by a user listed as a tag owner, OR the key generation UI must show `tag:ingress` as selectable). Re-run `docker compose up -d tailscale-ingress` — no new key needed.

2. **Remove tag from the stack's tailscale container.** In `unified-stack/docker-compose.yml`, strip `--advertise-tags=tag:ingress` from the tailscale-ingress `TS_EXTRA_ARGS`. The node comes up untagged, which means any ACL rules keyed on `tag:ingress` (for segmentation of the public ingress node) no longer apply — a security regression versus the spec.

3. **Issue an authkey from an admin-class user that owns `tag:ingress`** after step (1) is done. A regular-user key can't assert tags the user doesn't own, regardless of the key's "reusable" / "ephemeral" settings.

Until one of the above happens, Steps 4, 5, 6 (browser login), 7 (dashboard over ingress), 8 (Coraza WAF), 9 (Falco alert via UI), 11 (restart-cycle) remain untested. Steps 3, 10 can be exercised today.

## Resolved concerns from the Session-1 report

- **Wazuh multi-node fragility** — now automated. `wazuh-security-init` is idempotent (guarded by `/certs/.security-initialized` flag), generates bcrypt hashes via `hash.sh`, sed-patches a copy of `internal_users.yml`, and pushes via `securityadmin.sh -cd … -icl -h wazuh-indexer-1`. Reserved-user passwords can't be updated via the Security REST API (`PATCH` returns `Resource 'admin' is reserved`), so file-based patch is the only correct path.
- **x-hardened over-aggressive** — confirmed in Session 1 and now documented as design guidance: `user:` must never be in the anchor; hardening is per-service opt-in.
- **`/dock` permission model** — `create_dock_tree` now handles per-service UIDs that differ from `docktaetor`:`media` (currently Authentik at 1000:1000). As new services join the stack with baked-in UIDs different from docktaetor's, each needs an explicit chown line.

## Recommended next steps

1. **User**: Update tailnet ACL to permit `tag:ingress` (option 1 above). Single change; unblocks Steps 4–11.
2. Run `docker compose up -d tailscale-ingress caddy` and verify tailnet DNS resolves `ingress.neon-lenok.ts.net`.
3. Complete Steps 4–11 in one sweep against the running stack (all dependencies now healthy).
4. After Step 11 passes, mark Task 19 done.

---

**Session-1 bootstrap logs:** `/tmp/bootstrap-{1..5}.log` on streamer.
**Session-1 compose cold-start log:** `/tmp/cold-start.log` on streamer.
**Session-2 fix commits:** `15332dd`, `28b2b4c`, `a57e196`, `33d5285`, `a2a754d`, `6caeee3`.
