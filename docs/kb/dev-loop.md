---
type: reference
title: "dev-loop"
tags: [type/reference]
created: 2026-06-11
updated: 2026-06-11
---

# Dev Loop

## Build

No compiled artifacts. The stack runs directly from Docker images and Python scripts. Image pulls happen on first `docker compose up`. Custom Caddy image is built from a `Dockerfile` in the repo.

```bash
# Validate docker-compose.yml syntax and env interpolation
docker compose --env-file unified-stack/.env -f unified-stack/docker-compose.yml config
```

## Test

Test suite covers Entra ID setup/sync guard logic with mocked unit tests. No live API calls or credentials required.

```bash
python3 -m pytest unified-stack/tests/test_setup_entra.py -v
```

Pass condition: all test functions exit 0.

## Lint / type-check

```bash
# Python scripts
ruff check scripts/

# Type checking (pyright)
pyright scripts/
```

## Run locally

Full validation gate (run before any commit or stack change):

```bash
python3 -m pytest unified-stack/tests/ -v && \
  docker compose --env-file unified-stack/.env -f unified-stack/docker-compose.yml config
```

Bring up core stack:

```bash
# Copy and populate .env
cp unified-stack/.env.example unified-stack/.env
python3 scripts/gen-secrets.py unified-stack/.env \
  --set HOST_PUBLIC_IP=<your-ip> \
  --set TAILSCALE_AUTHKEY=<authkey> \
  --set CLOUDFLARE_API_TOKEN=<token>

# Start core stack
docker compose --env-file unified-stack/.env -f unified-stack/docker-compose.yml up -d

# Fetch container-issued secrets (Crowdsec bouncer key, etc.) and restart
python3 scripts/gen-secrets.py unified-stack/.env --apply

# Audit stack health
python3 scripts/check-stack.py
```

With optional profiles:

```bash
docker compose --env-file unified-stack/.env \
  -f unified-stack/docker-compose.yml \
  --profile media --profile apps up -d
```

## Secret scanning

The `validation/linters/` directory contains a `no_secret_logging` linter. Git pre-commit hooks run secret scanning before every commit. Run the validation gate explicitly with:

```bash
python3 scripts/validate.py --changed-only
```

## CI mode

```bash
python3 scripts/validate.py --ci
```

Outputs SARIF by default (unless `--format` overrides). Exits non-zero on `block`-level findings (configurable with `--fail-on warn`).

## Release

No formal release process. Stack is deployed by pulling the branch and re-running `docker compose up -d --pull always`. Post-deploy:

1. Run `python3 scripts/check-stack.py` to audit service health.
2. Run `python3 scripts/gen-secrets.py --apply` if any new secret slots were added in `.env.example`.
3. Run `python3 scripts/set-auth.py oidc` if new OIDC applications were added.
4. Run `python3 scripts/maintain.py wazuh` if Wazuh rules/decoders changed.

## Preferred agentic loop

Standard change cycle for an agent working on scripts or configuration:

1. Read relevant `docs/kb/` files for context (overview, architecture, config).
2. Run `python3 scripts/validate.py --changed-only` — confirm no pre-existing block findings.
3. Make changes to `scripts/` or `unified-stack/` configuration.
4. Run `ruff check scripts/ && pyright scripts/` — fix any lint/type errors.
5. Run `python3 -m pytest unified-stack/tests/ -v` — confirm all tests pass.
6. Run `docker compose --env-file unified-stack/.env -f unified-stack/docker-compose.yml config` — confirm Compose syntax is valid.
7. Run `python3 scripts/validate.py` — confirm no new block findings.
8. Run `python3 scripts/check-stack.py --no-probe` — confirm config audit passes without requiring a live stack.
9. Commit with Conventional Commits message referencing the affected script or service.
