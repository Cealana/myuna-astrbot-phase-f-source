#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

DATABASE=${MYUNA_DATABASE:-myuna_dev}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

runuser -u postgres -- psql \
    --dbname "$DATABASE" \
    --no-psqlrc \
    --set ON_ERROR_STOP=1 \
    <"$DATABASE_DIR/tests/verify_stage1.sql"

peer_result=$(
    runuser -u myuna -- psql \
        --dbname "$DATABASE" \
        --username myuna_dev_app \
        --no-password \
        --no-psqlrc \
        --tuples-only \
        --no-align \
        --command "SELECT current_user, count(*) FROM memory.memory_assertion GROUP BY current_user"
)

if [[ $peer_result != "myuna_dev_app|10009" ]]; then
    echo "unexpected peer-auth result: $peer_result" >&2
    exit 1
fi

echo "peer-auth verified: $peer_result"
