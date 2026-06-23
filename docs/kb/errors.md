---
type: reference
title: "errors"
tags: [type/reference]
created: 2026-06-11
updated: 2026-06-11
---

# Errors

## Exit code table

| Code | Meaning | Trigger | Fix |
|---|---|---|---|
| 0 | Success / normal exit | Validation passed, no findings, or script completed successfully. Also emitted by `validate.py` when `--fail-on=block` and all findings are warnings. | — |
| 1 | Generic failure | Most validation and script failures: missing dependencies, Docker socket unavailable, failed API calls, misconfigured stack, or unhandled exceptions throughout the scripts. | Check stderr for the specific error message; resolve the named dependency or misconfiguration and re-run. |
| 2 | OpenBao unsealing error | `bao-bootstrap.py` was invoked without `BAO_ADDR` set in the environment. | Set `BAO_ADDR` in `unified-stack/.env` before running `bao-bootstrap.py`. |
| 3 | OpenBao configuration error | `bao-bootstrap.py` could not find `BAO_KV_MOUNT` or the mount type does not match KV v2. | Verify OpenBao has a KV v2 mount at the path specified by `BAO_KV_MOUNT` in `.env`. |

## Error messages

| Message | Code | Notes |
|---|---|---|
| `BAO_ADDR environment variable not set` | 2 | Emitted by `bao-bootstrap.py`; set `BAO_ADDR` in `.env` |
| `BAO_KV_MOUNT not found or mount type mismatch` | 3 | Emitted by `bao-bootstrap.py`; verify KV v2 mount exists at `BAO_KV_MOUNT` |
| Script-specific runtime errors (missing deps, Docker socket, API failures) | 1 | Check stderr; all scripts emit descriptive messages before exit |
