# Build, Install, Run, and Modify

## Frozen inputs

- Core commit `0da52b29f5ec18578a58f9467e0a5ef2becdcc72` / tree `8f9432d3821590c737cc04975ab151eb2b1927ce`.
- Deploy commit `053f8d74a44ee447d4f4adfdb2131cafdb03074c` / tree `be21865250649d06e09e865d66ebdadb91c592ab`.
- AstrBot commit `2d617544d883ea6c31ec40fcce59d4cfaa904dd1` / tree `bca89db05ec7a2a56afcb66741ff12dd5ba29f67`.
- Runtime base `6b10fc936994eaeb97fae4d4f96375c93ddcf9a505140cbaac6d9ef304b4b7af` under `sources/runtime-base/`.
- Linux amd64, `/usr/bin/python3`, and no network access for the runtime import smoke.

## Deterministic owner runtime build

Run the reviewed builder twice from this repository root with absent output directories:

```sh
PYTHONPATH=sources/myuna-core/src:sources/myuna-deploy/scripts PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  sources/myuna-deploy/scripts/build_p07_hybrid_live_releases_v1.py \
  --core-source sources/myuna-core --core-commit 0da52b29f5ec18578a58f9467e0a5ef2becdcc72 --core-output output-a/core \
  --deploy-source sources/myuna-deploy --deploy-commit 053f8d74a44ee447d4f4adfdb2131cafdb03074c \
  --runtime-base sources/runtime-base/6b10fc936994eaeb97fae4d4f96375c93ddcf9a505140cbaac6d9ef304b4b7af --runtime-output output-a/runtime \
  --runtime-profile p07-owner-private-memory-v1
```

The expected runtime release is `21cc54f20eaddfa8701e1a6d81620f8b40fafd5b551e6f681d36b779176c1f3c`. Reopen it with the reviewed validator and run the exact service-identity, runtime-only `PYTHONPATH`, `-B`, no-bytecode, network-denied import smoke before installation. Installation is content-addressed and must never overwrite an existing release.

## AstrBot image

The accepted AstrBot OCI image/config/archive binding is unchanged and is recorded in `SOURCE_MANIFEST.json`. Use the reviewed `sources/myuna-deploy/scripts/build_telegram_gateway_release_v1.py` route and compare independently generated receipts before load.

## Modify

Changes to Core, Deploy, AstrBot, the runtime base, selected overlays, or the import closure produce new source and release identities. Do not reuse the identities above for modified bytes. Runtime selection remains a separate supervised live operation.
