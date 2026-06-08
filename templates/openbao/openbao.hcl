ui            = true
# NOTE: OpenBao 2.x removed mlock support entirely — a `disable_mlock` line is now a
# FATAL config error. Protect unseal keys from swap at the host level instead
# (disable or encrypt swap; see docs/openbao-runbook.md + OpenBao post-install hardening).
api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"

storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  # TLS terminated upstream by Caddy (public) / Tailscale (tailnet). OpenBao listens
  # plaintext only on the internal `security` docker network (192.0.2.10/24), never host-exposed.
  tls_disable = true
}

# Audit device — DECLARATIVE (OpenBao 2.x): enabling audit via the API is rejected,
# so the file audit device is defined here and created by the server on startup
# (reprocessed on restart / SIGHUP). The audit dir must be writable by the container
# user — docker-host-config.sh provisions ${DOCK_DATA}/openbao/audit accordingly.
audit "file" "file" {
  description = "Primary file audit log"
  options = {
    file_path = "/openbao/audit/audit.log"
    log_raw   = "false"
  }
}

# OPTIONAL auto-unseal (opt-in). Uncomment + populate via .env when BAO_AKV_* are set.
# seal "azurekeyvault" {
#   tenant_id      = "${BAO_AKV_TENANT_ID}"
#   client_id      = "${BAO_AKV_CLIENT_ID}"
#   client_secret  = "${BAO_AKV_CLIENT_SECRET}"
#   vault_name     = "${BAO_AKV_VAULT_NAME}"
#   key_name       = "${BAO_AKV_KEY_NAME}"
# }
