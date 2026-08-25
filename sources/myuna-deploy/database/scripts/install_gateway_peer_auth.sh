#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

PG_MAJOR=${PG_MAJOR:-18}
CLUSTER=${PG_CLUSTER:-main}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
CONFIG_DIR="/etc/postgresql/$PG_MAJOR/$CLUSTER"
HBA_TARGET="$CONFIG_DIR/00-myuna-dev.pg_hba.conf"
IDENT_TARGET="$CONFIG_DIR/pg_ident.conf"
IDENT_MAPPING="myuna_dev_map    myuna-gateway     myuna_gateway_app"

if [[ ! -d $CONFIG_DIR ]]; then
    echo "PostgreSQL cluster config not found: $CONFIG_DIR" >&2
    exit 1
fi
if ! getent passwd myuna-gateway >/dev/null; then
    echo "Linux user myuna-gateway does not exist" >&2
    exit 1
fi
if ! runuser -u postgres -- psql --dbname myuna_dev --no-psqlrc --tuples-only \
    --no-align --command "SELECT 1 FROM pg_roles WHERE rolname = 'myuna_gateway_app'" \
    | grep -Fxq 1; then
    echo "PostgreSQL role myuna_gateway_app does not exist" >&2
    exit 1
fi

install -o postgres -g postgres -m 0640 \
    "$DATABASE_DIR/config/00-myuna-dev.pg_hba.conf" \
    "$HBA_TARGET"

if ! grep -Fqx "$IDENT_MAPPING" "$IDENT_TARGET"; then
    printf '%s\n' "$IDENT_MAPPING" >>"$IDENT_TARGET"
fi
chown postgres:postgres "$IDENT_TARGET"
chmod 0640 "$IDENT_TARGET"

runuser -u postgres -- psql --dbname postgres --no-psqlrc \
    --command 'SELECT pg_reload_conf()' >/dev/null
runuser -u postgres -- pg_isready --quiet

peer_user=$(runuser -u myuna-gateway -- psql \
    --dbname myuna_dev \
    --username myuna_gateway_app \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --command 'SELECT current_user')
if [[ $peer_user != myuna_gateway_app ]]; then
    echo "gateway peer authentication verification failed" >&2
    exit 1
fi

echo "gateway Unix peer authentication installed and verified"
