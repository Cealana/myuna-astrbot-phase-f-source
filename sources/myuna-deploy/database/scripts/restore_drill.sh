#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi
if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/myuna_dev.dump" >&2
    exit 1
fi

DUMP=$1
DRILL_DATABASE=myuna_restore_drill
EXPECTED_ASSERTIONS=${MYUNA_EXPECTED_ASSERTIONS:-10009}
EXPECTED_SOURCES=${MYUNA_EXPECTED_SOURCES:-10009}
EXPECTED_EVENTS=${MYUNA_EXPECTED_EVENTS:-10009}
EXPECTED_EMBEDDINGS=${MYUNA_EXPECTED_EMBEDDINGS:-100}
EXPECTED_ANCHORS=${MYUNA_EXPECTED_ANCHORS:-2}
EXPECTED_AUDITS=${MYUNA_EXPECTED_AUDITS:-0}
EXPECTED_DATASET_LOADS=${MYUNA_EXPECTED_DATASET_LOADS:-1}

if [[ ! -f $DUMP ]]; then
    echo "dump not found: $DUMP" >&2
    exit 1
fi

cleanup() {
    runuser -u postgres -- psql \
        --dbname postgres \
        --no-psqlrc \
        --command "DROP DATABASE IF EXISTS $DRILL_DATABASE WITH (FORCE)" \
        >/dev/null
}
trap cleanup EXIT

cleanup
runuser -u postgres -- createdb \
    --owner myuna_dev_owner \
    --encoding UTF8 \
    --template template0 \
    "$DRILL_DATABASE"
runuser -u postgres -- pg_restore \
    --dbname "$DRILL_DATABASE" \
    --exit-on-error \
    "$DUMP"

assertions=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_assertion"
)
sources=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_source"
)
events=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_event"
)
embeddings=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_embedding"
)
anchors=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_anchor"
)
audits=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM memory.memory_access_audit"
)
dataset_loads=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align --command "SELECT count(*) FROM myuna_admin.dataset_load"
)
extensions=$(
    runuser -u postgres -- psql --dbname "$DRILL_DATABASE" --no-psqlrc \
        --tuples-only --no-align \
        --command "SELECT string_agg(extname, ',' ORDER BY extname) FROM pg_extension WHERE extname IN ('pg_trgm', 'vector')"
)

if [[ $assertions != "$EXPECTED_ASSERTIONS" || $sources != "$EXPECTED_SOURCES" || $events != "$EXPECTED_EVENTS" ]]; then
    echo "restore drill fact count mismatch" >&2
    exit 1
fi
if [[ $embeddings != "$EXPECTED_EMBEDDINGS" || $extensions != "pg_trgm,vector" ]]; then
    echo "restore drill extension/vector mismatch" >&2
    exit 1
fi
if [[ $anchors != "$EXPECTED_ANCHORS" || $audits != "$EXPECTED_AUDITS" || $dataset_loads != "$EXPECTED_DATASET_LOADS" ]]; then
    echo "restore drill metadata/audit count mismatch" >&2
    exit 1
fi

printf '{"database":"%s","assertions":%s,"sources":%s,"events":%s,' \
    "$DRILL_DATABASE" "$assertions" "$sources" "$events"
printf '"embeddings":%s,"anchors":%s,"audits":%s,"dataset_loads":%s,' \
    "$embeddings" "$anchors" "$audits" "$dataset_loads"
printf '"extensions":"%s","passed":true}\n' "$extensions"
