#!/bin/bash
# Idempotently provision role + database for every APP with a
# complete triple of ${APP}_DB_NAME / ${APP}_DB_USER / ${APP}_DB_PASSWORD
# environment variables set.
#
# Runs inside the pgvector/pgvector container as part of its initdb
# hook (see docker-compose.yml for the mount target
# /docker-entrypoint-initdb.d/).
set -euo pipefail

env | grep -oE '^[A-Z0-9]+_DB_NAME=' | sed 's/_DB_NAME=//' | while read -r APP; do
    db_var="${APP}_DB_NAME"
    user_var="${APP}_DB_USER"
    pw_var="${APP}_DB_PASSWORD"

    db="${!db_var:-}"
    user="${!user_var:-}"
    pw="${!pw_var:-}"

    if [ -z "$db" ] || [ -z "$user" ] || [ -z "$pw" ]; then
        echo "Skipping $APP: incomplete triple (DB=$db, USER=$user, PW is $([ -z "$pw" ] && echo empty || echo set))"
        continue
    fi

    echo "Provisioning $APP -> database '$db' owned by '$user'"

    # Pass values as psql variables so format() can quote them correctly:
    # %I = identifier quoting (double-quotes), %L = literal quoting (single-quotes).
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
        -v "appdb=$db" -v "appuser=$user" -v "apppw=$pw" <<-EOSQL
	SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :appuser, :apppw)
	    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'appuser')\gexec
	SELECT format('CREATE DATABASE %I OWNER %I', :appdb, :appuser)
	    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'appdb')\gexec
	GRANT ALL PRIVILEGES ON DATABASE :"appdb" TO :"appuser";
EOSQL
done

echo "Provisioning complete."
