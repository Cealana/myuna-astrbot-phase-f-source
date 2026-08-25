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
DRILL_DATABASE=myuna_gateway_restore_drill
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DATABASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
MIGRATION="$DATABASE_DIR/migrations/0004_gateway_runtime_foundation.sql"
EXPECTED_SHA256=$(sha256sum "$MIGRATION" | awk '{print $1}')

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

result=$(runuser -u postgres -- psql \
    --dbname "$DRILL_DATABASE" \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --command "
        SELECT json_build_object(
            'migration_ok', EXISTS (
                SELECT 1
                FROM myuna_admin.schema_migration
                WHERE migration_version = '0004_gateway_runtime_foundation'
                  AND migration_sha256 = '$EXPECTED_SHA256'
            ),
            'inbound_table', to_regclass('gateway_runtime.inbound_event') IS NOT NULL,
            'outbox_table', to_regclass('gateway_runtime.outbound_delivery') IS NOT NULL,
            'inbound_rows', (SELECT count(*) FROM gateway_runtime.inbound_event),
            'outbox_rows', (SELECT count(*) FROM gateway_runtime.outbound_delivery),
            'real_principals', (
                SELECT count(*) FROM myuna_identity.principal
                WHERE principal_kind <> 'test' OR principal_id <> 'principal-synthetic'
            ),
            'real_bindings', (SELECT count(*) FROM myuna_identity.account_binding),
            'real_namespaces', (
                SELECT count(*) FROM memory.memory_namespace
                WHERE namespace_kind <> 'test' OR namespace_id <> 'ns-synthetic-dev'
            )
        )")

if ! grep -Eq '"migration_ok"[[:space:]]*:[[:space:]]*true' <<<"$result" \
   || ! grep -Eq '"inbound_table"[[:space:]]*:[[:space:]]*true' <<<"$result" \
   || ! grep -Eq '"outbox_table"[[:space:]]*:[[:space:]]*true' <<<"$result" \
   || ! grep -Eq '"inbound_rows"[[:space:]]*:[[:space:]]*0' <<<"$result" \
   || ! grep -Eq '"outbox_rows"[[:space:]]*:[[:space:]]*0' <<<"$result" \
   || ! grep -Eq '"real_principals"[[:space:]]*:[[:space:]]*0' <<<"$result" \
   || ! grep -Eq '"real_bindings"[[:space:]]*:[[:space:]]*0' <<<"$result" \
   || ! grep -Eq '"real_namespaces"[[:space:]]*:[[:space:]]*0' <<<"$result"; then
    echo "gateway backup restore verification failed: $result" >&2
    exit 1
fi

printf '%s\n' "$result"
echo "gateway backup restore verification passed"
