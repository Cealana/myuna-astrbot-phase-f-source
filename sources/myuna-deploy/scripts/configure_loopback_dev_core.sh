#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo=/srv/myuna/repos/deploy
core_repo=/srv/myuna/repos/core
release=/srv/myuna/repos/definition/releases/v5/2755db85ca7e-b1-dbc4b229-g9f993b18-a95b4a017-te2e33bb3
current=/srv/myuna/environments/dev/definition/current
environment_source="$repo/config/dev-loopback-v5.env"
environment_target=/etc/myuna/dev.env
unit_source="$repo/systemd/myuna-core@.service"
unit_target=/etc/systemd/system/myuna-core@.service
dropin_source="$repo/systemd/myuna-core-dev-credentials.conf"
dropin_dir=/etc/systemd/system/myuna-core@dev.service.d
dropin_target="$dropin_dir/credentials.conf"
secret_dir=/etc/myuna/secrets
provider_secret="$secret_dir/deepseek-api-key"
token_secret="$secret_dir/dev-loopback-token"

if systemctl is-active --quiet myuna-core@dev.service; then
  echo "refusing to replace configuration while myuna-core@dev is active" >&2
  exit 2
fi
if [[ ! -L "$current" || "$(readlink -f "$current")" != "$release" ]]; then
  echo "approved v5 dev Definition pointer is not active" >&2
  exit 3
fi
if [[ ! -f "$provider_secret" ]]; then
  echo "DeepSeek source credential is missing" >&2
  exit 4
fi
provider_mode=$(stat -c '%U:%G:%a' "$provider_secret")
if [[ "$provider_mode" != "root:root:600" ]]; then
  echo "DeepSeek source credential permissions are unsafe" >&2
  exit 5
fi

install -d -o root -g root -m 0700 "$secret_dir"
if [[ ! -e "$token_secret" ]]; then
  temporary=$(mktemp "$secret_dir/.dev-loopback-token.XXXXXX")
  trap 'rm -f "${temporary:-}"' EXIT
  chmod 0600 "$temporary"
  openssl rand -hex 32 >"$temporary"
  install -o root -g root -m 0600 "$temporary" "$token_secret"
fi
token_mode=$(stat -c '%U:%G:%a' "$token_secret")
if [[ "$token_mode" != "root:root:600" ]]; then
  echo "dev token source permissions are unsafe" >&2
  exit 6
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g root -m 0700 /var/backups/myuna/config
if [[ -f "$environment_target" ]]; then
  install -o root -g root -m 0600 "$environment_target" \
    "/var/backups/myuna/config/dev.env.$timestamp"
fi
install -o root -g myuna -m 0640 "$environment_source" "$environment_target"
install -o root -g root -m 0644 "$unit_source" "$unit_target"
install -d -o root -g root -m 0755 "$dropin_dir"
install -o root -g root -m 0644 "$dropin_source" "$dropin_target"

runuser -u myuna -- env PYTHONPATH="$core_repo/src" python3 -c \
  'from pathlib import Path; from myuna_core.capabilities import load_capability_manifest; load_capability_manifest(Path("/srv/myuna/repos/deploy/config/capabilities/dev-v3.json"))'
systemd-analyze verify "$unit_target"
systemctl daemon-reload
systemctl disable myuna-core@dev.service >/dev/null 2>&1 || true
systemctl reset-failed myuna-core@dev.service >/dev/null 2>&1 || true

echo "configured myuna-core@dev: loopback only, disabled at boot, not started"
echo "credential sources verified without reading them into output"
