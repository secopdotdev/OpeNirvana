#!/bin/bash
echo "=== Roles ==="
docker exec postgres psql -U postgres -d postgres -c "SELECT rolname FROM pg_roles ORDER BY rolname"
echo "=== Databases ==="
docker exec postgres psql -U postgres -d postgres -c "SELECT datname FROM pg_database ORDER BY datname"
