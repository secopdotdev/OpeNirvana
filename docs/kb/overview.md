---
type: reference
title: "overview"
tags: [type/reference]
created: 2026-06-11
updated: 2026-06-11
---

# Overview

## Purpose

OpeNirvana is a unified, single-host, self-hosted homelab platform that brings up a complete, production-grade infrastructure stack with one `docker compose up` command. It delivers ingress hardening (Tailscale + Caddy with Coraza WAF + Crowdsec IP reputation), identity (Authentik SSO with optional Entra ID federation), shared data layer (Postgres 16 + pgvector, Redis 7), security observability (Wazuh SIEM, Falco runtime security, Zeek network monitoring), and optional media/productivity add-on profiles — all exposed on both a public Cloudflare-fronted domain and a private Tailnet, with forward-auth enforced on every route.

## Why it exists

Running a homelab typically means maintaining separate, independently-deployed services with inconsistent auth, ad-hoc TLS, and no unified observability. OpeNirvana collapses that into a single composable stack: one `.env`, one `docker-compose.yml`, and a small set of idempotent Python scripts that handle secrets generation, OIDC provisioning, maintenance tasks, and stack health auditing. The decision to use a custom-built Caddy binary (Crowdsec bouncer + Coraza WAF + Souin cache + forward-auth) rather than a vanilla proxy means every request passes through a single, auditable security chain without additional components.

## Architecture summary

The stack is organized in eight Docker networks corresponding to security boundaries: `ingress` (Caddy + Tailscale + Crowdsec), `auth-internal` (Authentik), `data` (Postgres + Redis), `security` (Wazuh + Falco + Crowdsec + OpenBao + socket-proxies), `media`, `apps`, `cloud`, and `oidc-clients`. Services are brought up in a defined bootstrap order — Tailscale ingress → data layer → Authentik migration → Authentik server/worker → Caddy — to avoid race conditions. All operator actions are mediated by the scripts in `scripts/`; no manual container or config edits are supported. See [architecture.md](architecture.md) for the full module breakdown, network topology, and security model.

## Key constraints

- **Single-host Docker Compose** — no Swarm, no Kubernetes. All services share one machine; resource limits per container are set in `docker-compose.yml`.
- **Digest-pinned images** for security-critical services (OpenBao 2.4.1); other images use version-pinned tags.
- **Non-root UID 1010:1010** (`svc-user:media`) everywhere; `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges: true`, seccomp default profile.
- **Idempotent scripts only** — re-running any script is safe; existing values are never overwritten.
- **OpenBao secrets backend** required for production secret storage; `.env` is acceptable for local development only.
- **No published ports** for data-layer or internal services; only Caddy (80/443), optional STUN/TURN (3478/5349 + media range), and Tailscale egress are exposed to the host network.
