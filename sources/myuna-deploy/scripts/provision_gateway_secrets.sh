#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

SECRET_DIR=/etc/myuna-gateway/secrets
install -d -o root -g root -m 0700 "$SECRET_DIR"

provision_secret() {
    local name=$1
    local destination="$SECRET_DIR/$name"
    local temporary

    if [[ -e $destination ]]; then
        if [[ $(stat -c '%U:%G:%a' "$destination") != root:root:600 ]]; then
            echo "unsafe existing secret permissions: $destination" >&2
            exit 2
        fi
        echo "existing secret retained: $name"
        return
    fi

    temporary=$(mktemp "$SECRET_DIR/.${name}.XXXXXX")
    chmod 0600 "$temporary"
    openssl rand -hex 32 >"$temporary"
    install -o root -g root -m 0600 "$temporary" "$destination"
    rm -f "$temporary"
    echo "provisioned root-only secret: $name"
}

provision_secret identity-pepper-v1
provision_secret channel-signing-v1
provision_secret payload-encryption-v1

echo "no secret value was printed, copied to Git, or exposed to a service"
