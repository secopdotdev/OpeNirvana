# OpenBao Break-Glass Runbook

**Scope:** Recovery procedures for the OpenBao secrets backend in the unified stack.
**ADR:** [0001 — Adopt OpenBao Secrets Backend](../../docs/superpowers/decisions/0001-adopt-openbao-secrets-backend.md)
**Service:** `openbao` container, static IP `192.0.2.10:8200` on the `security` Docker network (`192.0.2.10/24`). Note: `192.0.2.10` is the `n8n` service — do not point bao commands at it.
**Escrow:** `/dock/conf/openbao/init.json` (mode 0600, parent dir 0700) — contains unseal keys and initial root token. Guard this file.

> **Safety rule:** All procedures assume you are logged in to the Docker host as a user with `docker` group access or as root. Commands beginning with `sudo` require root or a user with `NOPASSWD` sudo. Never run these procedures on a production system while the service is handling live traffic — quiesce first where noted.
>
> **Prerequisite (since [ADR 0002](../../docs/superpowers/decisions/0002-adopt-hvac-openbao-client.md)):** The `bao-*.py` scripts now require the **`hvac`** Python package (the OpenBao client), installed automatically by `docker-host-config.sh:install_python_packages()` during host prep. Procedures here normally run on a bootstrapped host where `hvac` is already present (Procedure 3 runs `docker-host-config.sh` in Step 1, before any unseal). If you ever run `bao-unseal.py` / `bao-sync.py` **standalone on a host that never ran host-config** (a bare break-glass box), install it first: `pip install hvac` — otherwise the script fails with `ModuleNotFoundError: hvac`.

---

## Procedure 1 — Unsealing a Sealed Vault After a Reboot

**When:** OpenBao comes up sealed after a host reboot (expected without auto-unseal configured). `bao status` returns exit code 2.

**Symptom check:**

```bash
docker exec openbao bao status -address=http://127.0.0.1:8200
# Sealed: true  →  proceed with this procedure
# Sealed: false →  nothing to do
```

**Step 1 — Run the automated unseal script (normal path):**

```bash
BAO_ADDR=http://192.0.2.10:8200 \
  python3 /home/admin/openirvana/unified-stack/scripts/bao-unseal.py \
    /home/admin/openirvana/unified-stack/.env
```

`bao-unseal.py` reads the escrowed `init.json`, submits unseal key shares, and returns once the seal status is `false`. It is idempotent — safe to re-run if partially completed.

**Step 2 — Verify:**

```bash
docker exec openbao bao status -address=http://127.0.0.1:8200
# Sealed: false
# HA Enabled: false
```

**Step 3 — If the escrow file is missing or corrupted, restore from backup** and retry Step 1 (see Procedure 3).

**Step 4 — If no escrow and no backup,** you must re-initialise from scratch (see Procedure 3, host-loss path). All previously sealed secrets are unrecoverable without the unseal keys.

---

## Procedure 2 — Re-Deriving a Lost Root Token

**When:** The root token from `init.json` has been rotated, expired, or the escrow file was lost but the vault is unsealed and the unseal keys are available.

> The OpenBao root token is intentionally short-lived for day-to-day ops. The AppRole credentials (`BAO_SYNC_ROLE_ID` / `BAO_SYNC_SECRET_ID`) in `.env` are the normal operational credentials. Use this procedure only for admin recovery tasks.

**Step 1 — Generate a root token from unseal keys (online operator method):**

```bash
# Initiate root token generation
docker exec openbao bao operator generate-root -init \
  -address=http://127.0.0.1:8200
# Note the OTP and nonce printed to stdout.
```

**Step 2 — Provide each unseal key share (repeat per key share held):**

```bash
docker exec -i openbao bao operator generate-root \
  -address=http://127.0.0.1:8200 \
  -nonce=<NONCE_FROM_STEP_1> \
  -
# Paste one unseal key share, press Enter; repeat until threshold reached.
```

**Step 3 — Decode the encoded token:**

```bash
docker exec openbao bao operator generate-root \
  -address=http://127.0.0.1:8200 \
  -decode=<ENCODED_TOKEN_FROM_STEP_2> \
  -otp=<OTP_FROM_STEP_1>
# Prints the plaintext root token.
```

**Step 4 — Use the token for the recovery task, then revoke it:**

```bash
BAO_ADDR=http://192.0.2.10:8200 BAO_TOKEN=<ROOT_TOKEN> \
  docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=<ROOT_TOKEN> \
    openbao bao token revoke -self
```

**Note:** After completing the recovery task, update `.env` with fresh AppRole credentials if they were also lost (re-run `bao-bootstrap.py` with root token to reprovision).

---

## Procedure 3 — Host Loss: Full Restore from Backup

**When:** The Docker host is unrecoverable. You are rebuilding on new hardware or a new VM.

**Prerequisites:** Backup of `/dock/data/openbao/data/` (file storage) and `/dock/conf/openbao/init.json` (escrow).

**Step 1 — Provision the new host:**

```bash
# Run the full host bootstrap — creates /dock tree, installs Docker, etc.
sudo bash /home/admin/openirvana/unified-stack/scripts/docker-host-config.sh
```

**Step 2 — Restore file storage from backup:**

```bash
sudo rsync -a --delete /path/to/backup/openbao/data/ /dock/data/openbao/data/
sudo chmod -R 700 /dock/data/openbao/data
```

**Step 3 — Restore the escrow file:**

```bash
sudo install -m 0600 /path/to/backup/init.json /dock/conf/openbao/init.json
sudo chmod 700 /dock/conf/openbao
```

**Step 4 — Start OpenBao:**

```bash
cd /home/admin/openirvana
docker compose -f unified-stack/docker-compose.yml \
  --project-directory unified-stack \
  --profile security up -d openbao
```

**Step 5 — Unseal:**

```bash
BAO_ADDR=http://192.0.2.10:8200 \
  python3 unified-stack/scripts/bao-unseal.py unified-stack/.env
```

**Step 6 — Verify secrets are intact:**

```bash
BAO_TOKEN=$(python3 -c "import json; d=json.load(open('/dock/conf/openbao/init.json')); print(d['root_token'])")
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$BAO_TOKEN" \
  openbao bao kv list secret/
# Should print the KV paths seeded by gen-secrets.py
```

**Step 7 — Bring up the rest of the stack:**

```bash
bash unified-stack/run.sh -y
```

---

## Procedure 4 — Rotate a Secret End-to-End

**When:** A secret needs rotation (API key revoked, password leaked, scheduled rotation).

**Step 1 — Identify the KV path for the secret:**

```bash
# List top-level paths
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN="$(python3 -c "import json; print(json.load(open('/dock/conf/openbao/init.json'))['root_token'])")" \
  openbao bao kv list secret/
```

**Step 2 — Write the new value (write-if-set, creates a new KV version):**

```bash
BAO_TOKEN=<ROOT_OR_APPROLE_TOKEN>
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$BAO_TOKEN" \
  openbao bao kv put secret/<path> <key>=<new_value>
# Example:
# openbao bao kv put secret/postgres POSTGRES_PASSWORD=newpassword123
```

**Step 3 — Sync the updated secret to `.env`:**

```bash
BAO_ADDR=http://192.0.2.10:8200 \
  python3 unified-stack/scripts/bao-sync.py unified-stack/.env
# bao-sync.py is write-if-blank by default; to overwrite existing .env values,
# pass --force (check the script's --help for the current flag name).
```

**Step 4 — Restart affected services to pick up the new `.env` values:**

```bash
docker compose -f unified-stack/docker-compose.yml \
  --project-directory unified-stack \
  --profile <affected_profile> \
  up -d --force-recreate <service_name>
# Example: restart postgres after a password rotation
# docker compose ... up -d --force-recreate postgres
```

**Step 5 — Verify the service is healthy:**

```bash
docker compose -f unified-stack/docker-compose.yml \
  --project-directory unified-stack ps
# Confirm the service shows as "running" / "healthy".
```

**Step 6 — If the rotated secret was an external API key (Cloudflare, Entra, etc.), revoke the old key in the external system before this step.**

---

## Procedure 5 — Enable Azure Key Vault Auto-Unseal After the Fact (Seal Migration)

**When:** The stack started with Shamir unseal (default) and you want to migrate to AKV auto-unseal so OpenBao self-unseals after reboots. Reference: ADR 0001, re-evaluation trigger "AKV auto-unseal adoption".

**Prerequisites:**
- Azure Key Vault with a key (`openbao-unseal-key`) — RSA-HSM 2048+ or EC P-256+ — created and access policy granting the openbao managed identity (or service principal) `wrapKey` + `unwrapKey` + `get` permissions.
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (or MSI endpoint) available to the container.

**Step 1 — Update `openbao.hcl` to add the AKV seal stanza (alongside the existing `shamir` seal for migration):**

```hcl
# In /dock/conf/openbao/config/openbao.hcl
# Add BELOW the existing storage/listener blocks — do NOT remove shamir yet.
seal "azurekeyvault" {
    tenant_id     = "env://AZURE_TENANT_ID"
    client_id     = "env://AZURE_CLIENT_ID"
    client_secret = "env://AZURE_CLIENT_SECRET"
    vault_name    = "your-akv-name"
    key_name      = "openbao-unseal-key"
}
```

**Step 2 — Add AKV env vars to `.env` and `docker-compose.yml` environment block for the openbao service.**

**Step 3 — Restart OpenBao with the migration flag:**

```bash
# Unseal with existing Shamir keys first (must be unsealed to migrate)
BAO_ADDR=http://192.0.2.10:8200 python3 unified-stack/scripts/bao-unseal.py unified-stack/.env

# Restart with migration enabled
docker compose -f unified-stack/docker-compose.yml \
  --project-directory unified-stack \
  --profile security \
  up -d --force-recreate openbao
# OpenBao detects the new seal config and triggers migration automatically
# on the next unseal operation.
```

**Step 4 — Complete the migration (requires one final Shamir unseal):**

```bash
# OpenBao will report: "Entering migration mode" in logs
docker logs openbao --tail 30

# Provide Shamir unseal keys one last time to complete migration
BAO_ADDR=http://192.0.2.10:8200 python3 unified-stack/scripts/bao-unseal.py unified-stack/.env
# After successful migration, OpenBao reports: "Migration complete"
```

**Step 5 — Remove the `shamir` stanza from `openbao.hcl` and restart:**

```bash
# Edit /dock/conf/openbao/config/openbao.hcl — remove the `seal "shamir" {}` block
# (or ensure no explicit shamir stanza; AKV is now the active seal)
docker compose -f unified-stack/docker-compose.yml \
  --project-directory unified-stack \
  --profile security \
  up -d --force-recreate openbao

# Verify: OpenBao unseals automatically without any key shares
docker exec openbao bao status -address=http://127.0.0.1:8200
# Sealed: false  (auto-unsealed via AKV)
# Seal Type: azurekeyvault
```

**Step 6 — Update `bao-unseal.py` to be a no-op when AKV auto-unseal is active** (it should detect seal type and skip Shamir key submission). File a backlog item if not yet implemented.

**Step 7 — Rotate the Shamir unseal keys out of escrow** (they are no longer the active unseal mechanism) but retain `init.json` for the root token recovery path (Procedure 2).

---

*Last updated: 2026-06-06. Owned by: ops/security. See ADR 0001 (OpenBao adoption) and ADR 0002 (hvac client) for architectural decisions and re-evaluation triggers.*
