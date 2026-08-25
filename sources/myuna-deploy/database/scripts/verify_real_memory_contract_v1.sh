#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

database=${MYUNA_DATABASE:-myuna_dev}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
database_dir=$(cd -- "$script_dir/.." && pwd)

runuser -u postgres -- psql \
    --dbname "$database" \
    --no-psqlrc \
    --set ON_ERROR_STOP=1 \
    < "$database_dir/tests/verify_real_memory_contract_v1.sql"

printf 'real-memory-contract-v1 dev schema verified\n'
