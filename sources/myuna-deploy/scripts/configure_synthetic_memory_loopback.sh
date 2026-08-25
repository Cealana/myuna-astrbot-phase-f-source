#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo=/srv/myuna/repos/deploy
core_repo=/srv/myuna/repos/core
environment_source="$repo/config/dev-loopback-v5-synthetic-memory.env"
environment_target=/etc/myuna/dev.env
fixture=/srv/myuna/repos/embedding-lab/fixtures/retrieval_zh_v1.jsonl
expected_fixture_sha256=d71454fcb48061876874f41cc1de3549029ea5c9876783a8a2e64bb57d1d0f8b

if systemctl is-active --quiet myuna-core@dev.service; then
  echo "stop myuna-core@dev before changing the memory capability gate" >&2
  exit 2
fi
if systemctl is-active --quiet myuna-retrieval-worker-dev.service; then
  echo "stop the retrieval worker before changing its Core contract" >&2
  exit 3
fi
if [[ "$(sha256sum "$fixture" | awk '{print $1}')" != "$expected_fixture_sha256" ]]; then
  echo "synthetic retrieval fixture checksum mismatch" >&2
  exit 4
fi
if [[ ! -S /run/postgresql/.s.PGSQL.5432 ]]; then
  echo "local PostgreSQL is unavailable" >&2
  exit 5
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g root -m 0700 /var/backups/myuna/config
install -o root -g root -m 0600 "$environment_target" \
  "/var/backups/myuna/config/dev.env.$timestamp"
install -o root -g myuna -m 0640 "$environment_source" "$environment_target"

runuser -u myuna -- env PYTHONPATH="$core_repo/src" python3 -c \
  'from pathlib import Path; from myuna_core.capabilities import load_capability_manifest; load_capability_manifest(Path("/srv/myuna/repos/deploy/config/capabilities/dev-v4.json"))'
systemctl daemon-reload
systemctl disable myuna-core@dev.service myuna-retrieval-worker-dev.service \
  >/dev/null 2>&1 || true
systemctl reset-failed myuna-core@dev.service myuna-retrieval-worker-dev.service \
  >/dev/null 2>&1 || true

echo "configured checksum-bound synthetic memory gate; both units remain stopped and disabled"
