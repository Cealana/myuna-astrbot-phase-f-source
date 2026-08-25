#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root from the local server console" >&2
  exit 1
fi

case ${1:-} in
  astrbot-initial)
    secret=
    ;;
  napcat-webui)
    secret=/etc/myuna-gateway/secrets/napcat-webui-token-v1
    ;;
  onebot)
    secret=/etc/myuna-gateway/secrets/onebot-token-v1
    ;;
  owner-challenge)
    secret=/etc/myuna-gateway/secrets/owner-challenge-code-v1
    ;;
  *)
    echo "usage: $0 {astrbot-initial|napcat-webui|onebot|owner-challenge}" >&2
    exit 2
    ;;
esac

clip=/mnt/c/Windows/System32/clip.exe
[[ -x ${clip} ]] || {
  echo "Windows clipboard helper is unavailable" >&2
  exit 1
}
if [[ ${1} == astrbot-initial ]]; then
  password=$(
    docker logs myuna-astrbot-dev 2>&1 \
      | sed -E $'s/\x1B\[[0-9;]*[[:alpha:]]//g' \
      | sed -n 's/.*Initial password: //p' \
      | tail -n 1 \
      | tr -d '\r\n'
  )
  [[ -n ${password} ]] || {
    echo "AstrBot initial password was not found in the local container log" >&2
    exit 1
  }
  printf '%s' "${password}" | "${clip}"
  password=
else
  [[ -f ${secret} ]] || {
    echo "requested secret is not provisioned" >&2
    exit 1
  }
  tr -d '\r\n' <"${secret}" | "${clip}"
fi
echo "Secret copied to the local Windows clipboard without printing it."
echo "Paste it only into the intended local WebUI field, then overwrite the clipboard."
