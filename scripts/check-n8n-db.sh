#!/bin/bash
ENV_FILE="$(dirname "$0")/../.env"
N8N_PASS=$(grep '^N8N_DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2 | tr -d '\r')
echo "Password from .env: [$N8N_PASS]"

# Check if role exists
docker exec postgres psql -U postgres -d postgres -tAc "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname='n8n'" 2>&1
echo "---"
# Check if DB exists
docker exec postgres psql -U postgres -d postgres -tAc "SELECT datname FROM pg_database WHERE datname='n8n'" 2>&1
echo "---"
# Try to authenticate as n8n
docker exec postgres psql -U n8n -d n8n "host=localhost password=$N8N_PASS" -c "SELECT 1" 2>&1 || true
echo "---"
# Update password to ensure it matches .env
docker exec postgres psql -U postgres -d postgres -c "ALTER USER n8n PASSWORD '$N8N_PASS'" 2>&1
