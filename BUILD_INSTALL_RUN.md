# Build, Install, Run, and Modify

## Inputs

- Linux amd64.
- Python executable `/usr/bin/python3.12` with the exact identity enforced by the reviewed builder.
- Docker executable `/usr/bin/docker` with the exact identity enforced by the reviewed builder.
- The pinned official base image and all of its layers already present locally at `sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4`.
- No network access is used by the deterministic builder.

The reviewed builder verifies the complete official-base config, all base layer DiffIDs, tool identities, source commit, source epoch, Dockerfile, overlay bytes, canonical archive metadata, OCI config, manifest, and index.

## Deterministic build

From the repository root, use two absent output directories on the same local filesystem:

```sh
python3.12 sources/myuna-deploy/scripts/build_telegram_gateway_release_v1.py \
  sources/astrbot output-a
python3.12 sources/myuna-deploy/scripts/build_telegram_gateway_release_v1.py \
  sources/astrbot output-b
```

The two independently generated archives and receipts must be byte-identical. Public verification is performed by the same reviewed builder module before any image load. Do not substitute a different base, interpreter, Docker executable, source epoch, source commit, or output-publication route.

Expected selected image identities:

- OCI/Docker manifest and Docker 29 image identity: `sha256:ef2d2f966745b6d2e05b3286698bf6601a9a2c478f762b6b0df9703eee48d214`
- Config digest: `sha256:b55e699d4db6b94398cddb0c6c116fbc324bbcdbe27f9fdc63a93d5224edff45`
- Canonical OCI archive SHA-256: `6b0e6db3717a654628db0e831c7cc969ab3609d753d4b2f69ac92f249eb86259`

## Install and run

Load only a verified archive through the builder's verified load seam. Then use `sources/myuna-deploy/channels/astrbot-telegram/compose.dev.yml`, which pins the manifest digest above. Supply the referenced UID/GID, runtime directories, mounts, and secret references through the deployment environment. This publication intentionally includes no secret or private configuration value.

The compose route runs a single AstrBot Telegram service on its declared bridge network and uses existing read-only gateway/signing/media-auth mounts. Operators must preserve their own private runtime data and secret references outside this source tree.

The mounted Telegram gateway source must be the exact reviewed Deploy file under `sources/myuna-deploy/channels/astrbot-telegram/plugin/myuna_telegram_gateway/main.py`. Its customary plain-response constructor preserves each reply prefix and appends the fixed public corresponding-source URL once. Verify that mounted file against `FILES.sha256` before activation.

## Modify

Modify the source under `sources/astrbot/`, update the reviewed overlay and tests, then create a new independently reviewed source commit and deterministic receipt. Any change alters the expected source, layer, config, manifest, archive, and image identities; do not reuse the identities documented here for modified bytes.

The relevant generated-synthetic tests are included under `sources/astrbot/tests/`, `sources/myuna-core/tests/`, and `sources/myuna-deploy/tests/`.
