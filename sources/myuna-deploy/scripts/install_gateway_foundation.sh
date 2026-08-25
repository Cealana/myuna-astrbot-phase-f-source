#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
UNIT_SOURCE="$REPO_DIR/systemd/myuna-channel-gateway-dev.service"
UNIT_TARGET=/etc/systemd/system/myuna-channel-gateway-dev.service
EXEC_SOURCE="$REPO_DIR/scripts/gateway_fail_closed.py"
EXEC_TARGET=/usr/local/libexec/myuna-gateway/fail-closed

if [[ -e /etc/myuna-gateway/activation-approved ]]; then
    echo "activation marker already exists; refusing foundation replacement" >&2
    exit 2
fi
if systemctl is-active --quiet myuna-channel-gateway-dev.service; then
    echo "gateway service is active; refusing foundation replacement" >&2
    exit 3
fi

if ! getent group myuna-gateway >/dev/null; then
    groupadd --system myuna-gateway
fi
if ! getent passwd myuna-gateway >/dev/null; then
    useradd \
        --system \
        --gid myuna-gateway \
        --home-dir /var/lib/myuna-gateway \
        --shell /usr/sbin/nologin \
        --comment "Myuna channel gateway" \
        myuna-gateway
fi

install -d -o root -g myuna-gateway -m 0750 /etc/myuna-gateway
install -d -o root -g root -m 0700 /etc/myuna-gateway/secrets
install -d -o myuna-gateway -g myuna-gateway -m 0750 /var/lib/myuna-gateway
install -d -o root -g root -m 0700 /var/lib/myuna-gateway/operator
install -d -o myuna-gateway -g myuna-gateway -m 0750 /var/log/myuna-gateway
install -d -o root -g root -m 0755 /usr/local/libexec/myuna-gateway

install -o root -g root -m 0755 "$EXEC_SOURCE" "$EXEC_TARGET"
install -o root -g root -m 0644 "$UNIT_SOURCE" "$UNIT_TARGET"

systemd-analyze verify "$UNIT_TARGET"
systemctl daemon-reload
systemctl disable myuna-channel-gateway-dev.service >/dev/null 2>&1 || true
systemctl reset-failed myuna-channel-gateway-dev.service >/dev/null 2>&1 || true

echo "gateway foundation installed: disabled, inactive, activation marker absent"
