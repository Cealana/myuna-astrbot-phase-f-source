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

if [[ ! -d $CONFIG_DIR ]]; then
    echo "PostgreSQL cluster config not found: $CONFIG_DIR" >&2
    exit 1
fi
if ! grep -Eq "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf.d'" \
    "$CONFIG_DIR/postgresql.conf"; then
    echo "postgresql.conf does not include conf.d" >&2
    exit 1
fi

install -d -o postgres -g postgres -m 0750 "$CONFIG_DIR/conf.d"
install -o postgres -g postgres -m 0640 \
    "$DATABASE_DIR/config/99-myuna-memory.conf" \
    "$CONFIG_DIR/conf.d/99-myuna-memory.conf"
install -o postgres -g postgres -m 0640 \
    "$DATABASE_DIR/config/00-myuna-dev.pg_hba.conf" \
    "$CONFIG_DIR/00-myuna-dev.pg_hba.conf"

sed -i \
    -e "/^include_if_exists '00-myuna-dev\.pg_hba\.conf'$/d" \
    -e "/^include_if_exists = '00-myuna-dev\.pg_hba\.conf'$/d" \
    "$CONFIG_DIR/pg_hba.conf"
HBA_INCLUDE='include_if_exists "00-myuna-dev.pg_hba.conf"'
if ! grep -Fqx "$HBA_INCLUDE" "$CONFIG_DIR/pg_hba.conf"; then
    sed -i "1i$HBA_INCLUDE" "$CONFIG_DIR/pg_hba.conf"
fi

IDENT_MAPPING="myuna_dev_map    myuna             myuna_dev_app"
if ! grep -Fqx "$IDENT_MAPPING" "$CONFIG_DIR/pg_ident.conf"; then
    sed -i "\$a$IDENT_MAPPING" "$CONFIG_DIR/pg_ident.conf"
fi

chown postgres:postgres \
    "$CONFIG_DIR/pg_hba.conf" \
    "$CONFIG_DIR/pg_ident.conf"
chmod 0640 \
    "$CONFIG_DIR/pg_hba.conf" \
    "$CONFIG_DIR/pg_ident.conf"

pg_ctlcluster "$PG_MAJOR" "$CLUSTER" restart
runuser -u postgres -- pg_isready --quiet

runuser -u postgres -- psql --dbname postgres --no-psqlrc --tuples-only --no-align \
    --command "SELECT current_setting('listen_addresses'), current_setting('shared_buffers');"
