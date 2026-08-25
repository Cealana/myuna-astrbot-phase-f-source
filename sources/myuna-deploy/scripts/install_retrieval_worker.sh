#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE="$REPO_DIR/systemd/myuna-retrieval-worker-dev.service"
TARGET=/etc/systemd/system/myuna-retrieval-worker-dev.service

install -o root -g root -m 0644 "$SOURCE" "$TARGET"
systemctl daemon-reload
systemctl disable myuna-retrieval-worker-dev.service >/dev/null 2>&1 || true
systemctl reset-failed myuna-retrieval-worker-dev.service >/dev/null 2>&1 || true

echo "installed disabled unit: myuna-retrieval-worker-dev.service"

