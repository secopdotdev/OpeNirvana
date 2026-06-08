#!/bin/bash
set -euo pipefail
ENV_FILE="$(dirname "$0")/../.env"
N8N_PASS=$(grep '^N8N_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2 | tr -d '\r')
echo "Provisioning n8n role and database (pass length: ${#N8N_PASS})..."

docker exec postgres psql -U postgres -d postgres -c "
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'n8n') THEN
    CREATE ROLE n8n LOGIN PASSWORD '${N8N_PASS}';
    RAISE NOTICE 'Role n8n created';
  ELSE
    ALTER USER n8n PASSWORD '${N8N_PASS}';
    RAISE NOTICE 'Role n8n password updated';
  END IF;
END
\$\$;
"

docker exec postgres psql -U postgres -d postgres -c "
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'n8n') THEN
    CREATE DATABASE n8n OWNER n8n;
    RAISE NOTICE 'Database n8n created';
  ELSE
    RAISE NOTICE 'Database n8n already exists';
  END IF;
END
\$\$;
" || docker exec postgres psql -U postgres -d postgres -c "CREATE DATABASE n8n OWNER n8n;" 2>/dev/null || true

docker exec postgres psql -U postgres -d n8n -c "GRANT ALL PRIVILEGES ON DATABASE n8n TO n8n;"
echo "Done. Verifying..."
docker exec postgres psql -U postgres -d postgres -c "SELECT rolname FROM pg_roles WHERE rolname='n8n'"
docker exec postgres psql -U postgres -d postgres -c "SELECT datname FROM pg_database WHERE datname='n8n'"
