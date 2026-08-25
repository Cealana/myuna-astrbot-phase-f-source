#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

runuser -u postgres -- psql \
    --dbname postgres \
    --no-psqlrc \
    <"$DATABASE_DIR/bootstrap/bootstrap_dev.sql"

runuser -u postgres -- psql \
    --dbname myuna_dev \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --command "SELECT current_database(), current_setting('myuna.environment'), current_setting('myuna.synthetic_only');"
