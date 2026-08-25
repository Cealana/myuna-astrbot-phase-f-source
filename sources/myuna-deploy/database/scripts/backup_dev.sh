#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

DATABASE=${MYUNA_DATABASE:-myuna_dev}
DESTINATION=${1:-/var/backups/postgresql/myuna/dev}
timestamp=$(date +%Y%m%dT%H%M%S%z)
filename="${DATABASE}-${timestamp}.dump"
temporary="$DESTINATION/.${filename}.partial"
final="$DESTINATION/$filename"

install -d -o postgres -g postgres -m 0700 "$DESTINATION"
rm -f "$temporary"
runuser -u postgres -- pg_dump \
    --dbname "$DATABASE" \
    --format custom \
    --compress 6 \
    --file "$temporary"
mv "$temporary" "$final"
chown postgres:postgres "$final"
chmod 0600 "$final"
sha256sum "$final" >"$final.sha256"
chown postgres:postgres "$final.sha256"
chmod 0600 "$final.sha256"

echo "$final"
