#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

DATABASE=${MYUNA_DATABASE:-myuna_dev}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)

for migration in "$DATABASE_DIR"/migrations/*.sql; do
    version=$(basename -- "$migration" .sql)
    sha256=$(sha256sum "$migration" | awk '{print $1}')
    existing=$(
        runuser -u postgres -- psql \
            --dbname "$DATABASE" \
            --no-psqlrc \
            --tuples-only \
            --no-align \
            --command "SELECT migration_sha256 FROM myuna_admin.schema_migration WHERE migration_version = '$version'" \
            2>/dev/null || true
    )

    if [[ -n $existing ]]; then
        if [[ $existing != "$sha256" ]]; then
            echo "checksum mismatch for applied migration $version" >&2
            exit 1
        fi
        echo "already applied: $version"
        continue
    fi

    runuser -u postgres -- psql \
        --dbname "$DATABASE" \
        --no-psqlrc \
        --single-transaction \
        --set ON_ERROR_STOP=1 \
        --set "migration_version=$version" \
        --set "migration_sha256=$sha256" \
        <"$migration"
    echo "applied: $version $sha256"
done
