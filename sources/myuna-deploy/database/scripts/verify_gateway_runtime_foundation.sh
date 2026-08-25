#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

DATABASE=${MYUNA_DATABASE:-myuna_dev}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
temporary=$(mktemp -d /tmp/myuna-gateway-verify.XXXXXX)
trap 'rm -rf "$temporary"' EXIT
chown postgres:postgres "$temporary"
chmod 0700 "$temporary"

install -o postgres -g postgres -m 0600 \
    "$DATABASE_DIR/tests/verify_gateway_runtime_foundation.sql" \
    "$temporary/verify_gateway_runtime_foundation.sql"
install -o postgres -g postgres -m 0600 \
    "$DATABASE_DIR/tests/test_gateway_runtime_transaction.sql" \
    "$temporary/test_gateway_runtime_transaction.sql"
install -o postgres -g postgres -m 0600 \
    "$DATABASE_DIR/tests/rehearse_gateway_runtime_body.sql" \
    "$temporary/rehearse_gateway_runtime_body.sql"

runuser -u postgres -- psql \
    --dbname "$DATABASE" \
    --no-psqlrc \
    --set ON_ERROR_STOP=1 \
    --file "$temporary/verify_gateway_runtime_foundation.sql"

runuser -u postgres -- psql \
    --dbname "$DATABASE" \
    --no-psqlrc \
    --set ON_ERROR_STOP=1 \
    --file "$temporary/test_gateway_runtime_transaction.sql"

if runuser -u myuna-gateway -- psql \
    --dbname "$DATABASE" \
    --username myuna_gateway_app \
    --no-psqlrc \
    --command 'SELECT count(*) FROM gateway_runtime.inbound_event' \
    >/dev/null 2>&1; then
    echo "gateway runtime unexpectedly has direct table access" >&2
    exit 1
fi

runuser -u myuna-gateway -- psql \
    --dbname "$DATABASE" \
    --username myuna_gateway_app \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --command "SELECT has_function_privilege(current_user, 'gateway_runtime.claim_inbound_event(text,text,text,text,text,timestamptz,timestamptz)', 'EXECUTE')"

echo "gateway runtime foundation verified"
