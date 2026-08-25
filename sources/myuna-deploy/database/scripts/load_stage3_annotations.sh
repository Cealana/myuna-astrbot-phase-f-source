#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

DATABASE=${MYUNA_DATABASE:-myuna_dev}
DATASET_ID=synthetic-zh-stage3-annotations-v1
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
FIXTURE="$DATABASE_DIR/fixtures/synthetic_stage3_annotations_v1.sql"
sha256=$(sha256sum "$FIXTURE" | awk '{print $1}')
existing=$(
    runuser -u postgres -- psql \
        --dbname "$DATABASE" \
        --no-psqlrc \
        --tuples-only \
        --no-align \
        --command "SELECT dataset_sha256 FROM myuna_admin.dataset_load WHERE dataset_id = '$DATASET_ID'" \
        2>/dev/null || true
)

if [[ -n $existing ]]; then
    if [[ $existing != "$sha256" ]]; then
        echo "checksum mismatch for loaded dataset $DATASET_ID" >&2
        exit 1
    fi
    echo "already loaded: $DATASET_ID $sha256"
    exit 0
fi

runuser -u postgres -- psql \
    --dbname "$DATABASE" \
    --no-psqlrc \
    --single-transaction \
    --set ON_ERROR_STOP=1 \
    --set "dataset_sha256=$sha256" \
    <"$FIXTURE"

echo "loaded: $DATASET_ID $sha256"

