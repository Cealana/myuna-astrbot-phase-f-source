#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

echo "SYSTEMD"
systemctl is-enabled myuna-astrbot-qq-dev.service 2>/dev/null || true
systemctl is-active myuna-astrbot-qq-dev.service 2>/dev/null || true

echo
echo "CONTAINERS"
docker ps --filter name=myuna-astrbot-dev --filter name=myuna-napcat-dev \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo
echo "LISTENERS"
ss -lntH '( sport = :6099 or sport = :6185 or sport = :6199 )' || true

echo
echo "MYUNA SERVICES"
for unit in myuna-core@dev.service myuna-retrieval-worker-dev.service myuna-channel-gateway-dev.service; do
  printf '%-43s ' "${unit}"
  systemctl is-active "${unit}" 2>/dev/null || true
done

