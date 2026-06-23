#!/bin/bash
# Create the PostgreSQL extensions Immich requires in its database.
#
# Immich connects as its own non-superuser LOGIN role (provisioned by
# 00-create-app-dbs.sh) and attempts `CREATE EXTENSION vector` itself on first
# boot — which fails with "permission denied to create extension / Must be
# superuser". So the superuser must pre-create the extensions during initdb,
# before Immich ever connects.
#
# Runs as part of the postgres initdb hook (only on a fresh data dir), AFTER
# 00-create-app-dbs.sh (alphabetical order) so the immich database already
# exists. The pgvector/pgvector image ships the `vector` extension; `cube` and
# `earthdistance` come from postgres contrib (used by Immich for geo features).
set -euo pipefail

db="${IMMICH_DB_NAME:-}"
if [ -z "$db" ]; then
    echo "Skipping immich extensions: IMMICH_DB_NAME unset"
    exit 0
fi

echo "Creating Immich extensions in database '$db'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d "$db" <<-'EOSQL'
	CREATE EXTENSION IF NOT EXISTS vector;
	CREATE EXTENSION IF NOT EXISTS cube;
	CREATE EXTENSION IF NOT EXISTS earthdistance;
EOSQL
echo "Immich extensions ready."
