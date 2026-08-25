#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this helper as root from an interactive terminal." >&2
  exit 1
fi
if [[ ! -t 0 ]]; then
  echo "Refusing non-interactive credential input." >&2
  exit 1
fi

destination_dir=/etc/myuna/secrets
destination=${destination_dir}/deepseek-api-key
install -d -o root -g root -m 0700 "${destination_dir}"
temporary=$(mktemp "${destination_dir}/.deepseek-api-key.XXXXXX")
chmod 0600 "${temporary}"
trap 'unset api_key; rm -f "${temporary}"' EXIT

IFS= read -r -s -p "DeepSeek API key (input hidden): " api_key
printf '\n' >&2
if (( ${#api_key} < 8 || ${#api_key} > 4096 )); then
  echo "Credential length is outside the accepted range." >&2
  exit 1
fi
if [[ ${api_key} == *$'\n'* || ${api_key} == *$'\r'* ]]; then
  echo "Credential must be a single line." >&2
  exit 1
fi

printf '%s' "${api_key}" >"${temporary}"
unset api_key
install -o root -g root -m 0600 "${temporary}" "${destination}"
echo "DeepSeek credential installed with root-only permissions."
echo "No service was enabled, started, or given live-call permission."
