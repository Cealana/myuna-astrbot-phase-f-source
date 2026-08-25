#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo_root=/srv/myuna/repos/deploy
compose_file=${repo_root}/channels/astrbot-qq/compose.dev.yml
env_file=/etc/myuna-gateway/astrbot-napcat-dev.env
gateway_user=myuna-gateway
plugin_source=${repo_root}/channels/astrbot-qq/plugin/myuna_gateway
plugin_root=/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/v1
secret_root=/etc/myuna-gateway/secrets
runtime_secret_root=/etc/myuna-gateway/runtime-secrets
runtime_secret_path=${runtime_secret_root}/channel-signing-v1
gateway_runtime_root=/usr/local/lib/myuna-gateway/core-v1/myuna_core
runner_source=${repo_root}/scripts/owner_challenge_gateway.py

for command_name in docker systemctl systemd-tmpfiles; do
  command -v "${command_name}" >/dev/null || {
    echo "missing required command: ${command_name}" >&2
    exit 1
  }
done

id "${gateway_user}" >/dev/null 2>&1 || {
  echo "missing Linux service account: ${gateway_user}" >&2
  exit 1
}

for required in \
  "${compose_file}" \
  "${env_file}" \
  "${secret_root}/channel-signing-v1" \
  "${plugin_source}/main.py" \
  "${plugin_source}/protocol.py" \
  "${plugin_source}/metadata.yaml" \
  "${plugin_source}/README.md" \
  "${runner_source}" \
  "${repo_root}/systemd/myuna-channel-gateway-dev.service" \
  "${repo_root}/systemd/myuna-channel-gateway-dev.socket" \
  "${repo_root}/tmpfiles/myuna-gateway.conf"; do
  [[ -f ${required} ]] || {
    echo "adapter deployment file is missing" >&2
    exit 1
  }
done

if systemctl is-active --quiet myuna-channel-gateway-dev.service \
  || systemctl is-active --quiet myuna-channel-gateway-dev.socket; then
  echo "refusing to replace an active owner challenge gateway" >&2
  exit 1
fi

install -d -o root -g "${gateway_user}" -m 0750 "$(dirname "${plugin_root}")" "${plugin_root}"
for plugin_file in main.py protocol.py metadata.yaml README.md; do
  install -o root -g root -m 0644 "${plugin_source}/${plugin_file}" "${plugin_root}/${plugin_file}"
done

install -d -o root -g "${gateway_user}" -m 0750 "${runtime_secret_root}"
install -o root -g "${gateway_user}" -m 0640 \
  "${secret_root}/channel-signing-v1" "${runtime_secret_path}"

install -d -o root -g root -m 0755 "$(dirname "${gateway_runtime_root}")" "${gateway_runtime_root}"
for core_file in __init__.py identity.py channel_gateway.py; do
  install -o root -g root -m 0644 \
    "/srv/myuna/repos/core/src/myuna_core/${core_file}" \
    "${gateway_runtime_root}/${core_file}"
done
install -d -o root -g root -m 0755 /usr/local/libexec/myuna-gateway
install -o root -g root -m 0755 "${runner_source}" \
  /usr/local/libexec/myuna-gateway/owner_challenge_gateway.py

install -o root -g root -m 0644 \
  "${repo_root}/systemd/myuna-channel-gateway-dev.service" \
  /etc/systemd/system/myuna-channel-gateway-dev.service
install -o root -g root -m 0644 \
  "${repo_root}/systemd/myuna-channel-gateway-dev.socket" \
  /etc/systemd/system/myuna-channel-gateway-dev.socket
install -o root -g root -m 0644 \
  "${repo_root}/tmpfiles/myuna-gateway.conf" \
  /etc/tmpfiles.d/myuna-gateway.conf
systemd-tmpfiles --create /etc/tmpfiles.d/myuna-gateway.conf
systemctl daemon-reload
systemctl disable myuna-channel-gateway-dev.socket >/dev/null 2>&1 || true
systemctl disable myuna-channel-gateway-dev.service >/dev/null 2>&1 || true

temporary_env=$(mktemp /etc/myuna-gateway/.astrbot-napcat-dev.env.XXXXXX)
trap 'rm -f "${temporary_env}"' EXIT
grep -Ev '^(CHANNEL_PLUGIN_ROOT|CHANNEL_RUNTIME_ROOT|CHANNEL_SIGNING_SECRET_PATH)=' \
  "${env_file}" >"${temporary_env}"
{
  printf 'CHANNEL_PLUGIN_ROOT=%s\n' "${plugin_root}"
  printf 'CHANNEL_RUNTIME_ROOT=%s\n' /run/myuna-gateway
  printf 'CHANNEL_SIGNING_SECRET_PATH=%s\n' "${runtime_secret_path}"
} >>"${temporary_env}"
chown root:root "${temporary_env}"
chmod 0600 "${temporary_env}"
mv -f "${temporary_env}" "${env_file}"
trap - EXIT

docker compose --env-file "${env_file}" -f "${compose_file}" config --quiet
docker compose --env-file "${env_file}" -f "${compose_file}" \
  up -d --no-deps --force-recreate astrbot >/dev/null

healthy=false
for _ in $(seq 1 40); do
  if [[ $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
      myuna-astrbot-dev 2>/dev/null || true) == healthy ]]; then
    healthy=true
    break
  fi
  sleep 3
done
[[ ${healthy} == true ]] || {
  echo "AstrBot did not become healthy after the boundary install" >&2
  exit 1
}

docker logs --since 5m myuna-astrbot-dev 2>&1 \
  | grep -q 'Myuna QQ fail-closed boundary initialized' || {
      echo "AstrBot is healthy but the Myuna boundary did not initialize" >&2
      exit 1
    }

echo "Fail-closed QQ boundary installed; owner challenge service remains disabled and inactive."
