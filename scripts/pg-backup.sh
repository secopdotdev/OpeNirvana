#!/usr/bin/env bash
# Nightly Postgres backup. Prunes old backups only after a successful new backup.
# Emits a Wazuh-pipeline alert on failure.
set -euo pipefail

# Source env for retention days + paths.
source /dock/conf/.env

BACKUP_DIR=/dock/backups/postgres
RETENTION_DAYS="${POSTGRES_BACKUP_RETENTION_DAYS:-14}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
NEW="$BACKUP_DIR/dump-${TIMESTAMP}.sql.zst"

mkdir -p "$BACKUP_DIR"

if docker exec postgres pg_dumpall -U "${POSTGRES_SUPERUSER}" 2>>/var/log/pg-backup.err \
    | zstd -T0 -19 > "${NEW}.tmp"; then
    mv "${NEW}.tmp" "${NEW}"
    find "$BACKUP_DIR" -name 'dump-*.sql.zst' -type f -mtime "+${RETENTION_DAYS}" -delete
    echo "$(date -Iseconds) pg_backup ok: $NEW (pruned >${RETENTION_DAYS}d)"
    exit 0
else
    rm -f "${NEW}.tmp"
    # Emit alert to Crowdsec decisions log — Wazuh agent picks it up as Channel B.
    printf '{"ts":"%s","source":"pg_backup","type":"pg_backup_failed","level":"CRITICAL","message":"pg_dumpall failed or zstd encoding failed","scenario":"ops:backup:failed","decisions":[]}\n' \
        "$(date -Iseconds)" >> /dock/conf/crowdsec/notifications/decisions.log
    echo "$(date -Iseconds) pg_backup FAILED" >&2
    exit 1
fi
