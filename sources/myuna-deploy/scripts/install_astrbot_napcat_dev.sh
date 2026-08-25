#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo_root=/srv/myuna/repos/deploy
compose_file=${repo_root}/channels/astrbot-qq/compose.dev.yml
unit_source=${repo_root}/systemd/myuna-astrbot-qq-dev.service
unit_target=/etc/systemd/system/myuna-astrbot-qq-dev.service
gateway_unit_source=${repo_root}/systemd/myuna-channel-gateway-dev.service
gateway_socket_source=${repo_root}/systemd/myuna-channel-gateway-dev.socket
tmpfiles_source=${repo_root}/tmpfiles/myuna-gateway.conf
plugin_source=${repo_root}/channels/astrbot-qq/plugin/myuna_gateway
plugin_root=/srv/myuna/channel-adapters/astrbot_plugin_myuna_gateway/v1
runtime_secret_root=/etc/myuna-gateway/runtime-secrets
runtime_secret_path=${runtime_secret_root}/channel-signing-v1
gateway_runtime_root=/usr/local/lib/myuna-gateway/core-v1/myuna_core
gateway_runner_source=${repo_root}/scripts/owner_challenge_gateway.py
config_root=/etc/myuna-gateway
secret_root=${config_root}/secrets
env_file=${config_root}/astrbot-napcat-dev.env
channel_root=/srv/myuna/channels/astrbot-qq/dev
gateway_user=myuna-gateway

for command_name in docker openssl systemctl; do
  command -v "${command_name}" >/dev/null || {
    echo "missing required command: ${command_name}" >&2
    exit 1
  }
done

id "${gateway_user}" >/dev/null 2>&1 || {
  echo "missing Linux service account: ${gateway_user}" >&2
  exit 1
}

[[ -f ${compose_file} && -f ${unit_source} && -f ${gateway_unit_source} \
  && -f ${gateway_socket_source} && -f ${tmpfiles_source} \
  && -f ${plugin_source}/main.py && -f ${plugin_source}/protocol.py \
  && -f ${plugin_source}/metadata.yaml && -f ${gateway_runner_source} ]] || {
  echo "deployment files are incomplete" >&2
  exit 1
}

gateway_uid=$(id -u "${gateway_user}")
gateway_gid=$(id -g "${gateway_user}")

install -d -o root -g "${gateway_user}" -m 0750 /srv/myuna/channels
install -d -o root -g "${gateway_user}" -m 0750 /srv/myuna/channels/astrbot-qq
install -d -o root -g "${gateway_user}" -m 0750 "${channel_root}"
for directory in astrbot-data astrbot-data/home napcat-config napcat-qq shared-media backups; do
  install -d -o "${gateway_user}" -g "${gateway_user}" -m 0750 "${channel_root}/${directory}"
done

install -d -o root -g "${gateway_user}" -m 0750 "${config_root}"
install -d -o root -g root -m 0700 "${secret_root}"

create_secret() {
  local path=$1
  if [[ ! -e ${path} ]]; then
    umask 077
    openssl rand -hex 32 >"${path}"
  fi
  chown root:root "${path}"
  chmod 0600 "${path}"
}

napcat_webui_secret=${secret_root}/napcat-webui-token-v1
onebot_secret=${secret_root}/onebot-token-v1
create_secret "${napcat_webui_secret}"
create_secret "${onebot_secret}"

channel_signing_secret=${secret_root}/channel-signing-v1
[[ -f ${channel_signing_secret} ]] || {
  echo "channel signing secret is missing; run provision_gateway_secrets.sh first" >&2
  exit 1
}

install -d -o root -g "${gateway_user}" -m 0750 "$(dirname "${plugin_root}")" "${plugin_root}"
for plugin_file in main.py protocol.py metadata.yaml README.md; do
  install -o root -g root -m 0644 "${plugin_source}/${plugin_file}" "${plugin_root}/${plugin_file}"
done

install -d -o root -g "${gateway_user}" -m 0750 "${runtime_secret_root}"
install -o root -g "${gateway_user}" -m 0640 "${channel_signing_secret}" "${runtime_secret_path}"

install -d -o root -g root -m 0755 "$(dirname "${gateway_runtime_root}")" "${gateway_runtime_root}"
for core_file in __init__.py identity.py channel_gateway.py; do
  install -o root -g root -m 0644 \
    "/srv/myuna/repos/core/src/myuna_core/${core_file}" \
    "${gateway_runtime_root}/${core_file}"
done
install -d -o root -g root -m 0755 /usr/local/libexec/myuna-gateway
install -o root -g root -m 0755 "${gateway_runner_source}" \
  /usr/local/libexec/myuna-gateway/owner_challenge_gateway.py

napcat_webui_token=$(tr -d '\r\n' <"${napcat_webui_secret}")
onebot_token=$(tr -d '\r\n' <"${onebot_secret}")
[[ ${napcat_webui_token} =~ ^[0-9a-f]{64}$ && ${onebot_token} =~ ^[0-9a-f]{64}$ ]] || {
  echo "channel secret format check failed" >&2
  exit 1
}

umask 077
{
  printf 'CHANNEL_UID=%s\n' "${gateway_uid}"
  printf 'CHANNEL_GID=%s\n' "${gateway_gid}"
  printf 'CHANNEL_ROOT=%s\n' "${channel_root}"
  printf 'CHANNEL_PLUGIN_ROOT=%s\n' "${plugin_root}"
  printf 'CHANNEL_RUNTIME_ROOT=%s\n' /run/myuna-gateway
  printf 'CHANNEL_SIGNING_SECRET_PATH=%s\n' "${runtime_secret_path}"
  printf 'NAPCAT_WEBUI_TOKEN=%s\n' "${napcat_webui_token}"
} >"${env_file}"
chown root:root "${env_file}"
chmod 0600 "${env_file}"

onebot_config=${channel_root}/napcat-config/onebot11.json
umask 077
cat >"${onebot_config}" <<EOF
{
  "network": {
    "httpServers": [],
    "httpSseServers": [],
    "httpClients": [],
    "websocketServers": [],
    "websocketClients": [
      {
        "enable": true,
        "name": "myuna-astrbot-rws",
        "url": "ws://astrbot:6199/ws",
        "reportSelfMessage": false,
        "messagePostFormat": "array",
        "token": "${onebot_token}",
        "debug": false,
        "heartInterval": 30000,
        "reconnectInterval": 5000
      }
    ],
    "plugins": []
  },
  "musicSignUrl": "",
  "enableLocalFile2Url": false,
  "parseMultMsg": false
}
EOF
chown "${gateway_user}:${gateway_user}" "${onebot_config}"
chmod 0600 "${onebot_config}"

install -o root -g root -m 0644 "${unit_source}" "${unit_target}"
install -o root -g root -m 0644 "${gateway_unit_source}" \
  /etc/systemd/system/myuna-channel-gateway-dev.service
install -o root -g root -m 0644 "${gateway_socket_source}" \
  /etc/systemd/system/myuna-channel-gateway-dev.socket
install -o root -g root -m 0644 "${tmpfiles_source}" \
  /etc/tmpfiles.d/myuna-gateway.conf
systemd-tmpfiles --create /etc/tmpfiles.d/myuna-gateway.conf
systemctl daemon-reload
systemctl disable myuna-astrbot-qq-dev.service >/dev/null 2>&1 || true
systemctl disable myuna-channel-gateway-dev.socket >/dev/null 2>&1 || true
systemctl disable myuna-channel-gateway-dev.service >/dev/null 2>&1 || true

docker image inspect \
  soulter/astrbot@sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4 \
  mlikiowa/napcat-docker@sha256:32891e1f5aa654ef84fb4fcfb1724b4d844a26c2fcb11519945e64e22d13e766 \
  >/dev/null

docker compose --env-file "${env_file}" -f "${compose_file}" config --quiet

if systemctl is-active --quiet myuna-astrbot-qq-dev.service; then
  echo "refusing to alter an active channel stack" >&2
  exit 1
fi

echo "AstrBot/NapCat dev configuration and fail-closed QQ boundary installed."
echo "The service is disabled and inactive; no QQ login or Core connection was started."
