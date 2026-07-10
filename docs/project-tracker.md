# OpeNirvana — Project Tracker

Own-content (no `.planning/` in this repo). Grounded in
`.planning/phases/03-tracker-vocabulary-rollout/fact-sheets/1.0-dev__OpeNirvana.md` (rollout project,
external to this repo). **Publish-class:** this repo is a public GitHub mirror — every line below is
publish-safe (nothing internal-only).

## Objective

A profile-gated, self-hosted **security + productivity** stack for a single Ubuntu host, providing
SSO (Authentik), hardened ingress (Caddy with CrowdSec + Coraza WAF + forward-auth), Tailscale
second-door networking, and ~30 opt-in services via compose profiles/bundles.

## Problem

Public mirror of a profile-gated, self-hosted security + productivity Docker stack, publish-synced
from the private `finnsbeincaddy` repo's `unified-stack/`. Gives operators a self-hostable,
security-hardened homelab platform without hand-wiring SSO/ingress/observability per service.

## Status

Active, live public mirror, actively publish-synced from finnsbeincaddy.

## Blocked

Working tree carries a large uncommitted diff spanning nearly every scripts/templates/docs file as of
the last documentation pass; not yet reconciled as intentional publish-sync vs. local drift. This
tracker's own commit does not touch that pre-existing diff.

## Next Action

Review and reconcile the large uncommitted diff before further edits — confirm it is intentional
finnsbeincaddy→OpeNirvana publish sync, not accidental local drift.

## Next Command

```
git diff --stat
```

## How-to Guides

- Zero-touch bring-up: `bash <(curl -fsSL <install-script-url>)` (README Quickstart).
- Manual bring-up: clone → `sudo unified-stack/docker-host-config.sh` → `cp .env.example .env` (fill
  required keys) → `python3 scripts/gen-secrets.py .env` → `bash run.sh`.
- Validate a service selection offline: `python3 scripts/profiles.py --check --profiles "<list>"`.
- Provision Authenticated Origin Pulls (AOP, ADR-0020 L1) — 7-step runbook driven by
  `scripts/cf-origin-pull.py`: generate origin-pull cert → `docker-host-config.sh
  provision_origin_pull` → verify `--status` → verify CF presents the cert in Caddy logs → flip
  `CLOUDFLARE_MTLS_MODE=require_and_verify` → verify enforcement → rollback path documented (README
  §Provisioning AOP).

## Uses

### Cloudflare

Runtime coupling: DNS-01 ACME plus Authenticated Origin Pulls (AOP) mTLS provisioning via the
vendored `scripts/cf-origin-pull.py`, called live against the Cloudflare API during deploy (reads the
token from `.env`).

### Tailscale

Runtime coupling: the `tailscale-ingress` container multi-homes the ingress network so every service
is reachable on the Tailnet as a second, private door alongside the public Cloudflare-fronted path.

## Related Projects

### finnsbeincaddy

Lineage/upstream origin, no deploy-time coupling from OpeNirvana's side: this repo is publish-synced
FROM finnsbeincaddy's private `unified-stack/` (periodic `publish: sync unified-stack from
finnsbeincaddy@<sha>` commits). OpeNirvana does not call back into finnsbeincaddy at runtime — it is
a one-way, point-in-time mirror.

### cloudflare-toolkit

Lineage/bundled-origin, no deploy-time coupling: `scripts/cf-origin-pull.py`'s canonical home is the
private `cloudflare-toolkit`; it is vendored here so the deploy — and this public mirror — stays
self-contained, rather than importing the toolkit package at runtime.
