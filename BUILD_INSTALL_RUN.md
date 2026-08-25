# Build, Install, Run, and Modify

## Frozen inputs

- Core commit `4c13c0b20552b5d8a8720f180d0569405fed00b0` / tree `e43ae07babf5a448525d1035d400a37fde374a2b`.
- Deploy commit `c1aac3b2a41edfe8596cdf895bd0c8e9bbb6dcb1` / tree `11f7f6dad1078cc550b688466962b2f8cfc478ec`.
- AstrBot commit `2d617544d883ea6c31ec40fcce59d4cfaa904dd1` / tree `bca89db05ec7a2a56afcb66741ff12dd5ba29f67`.
- Runtime base `6b10fc936994eaeb97fae4d4f96375c93ddcf9a505140cbaac6d9ef304b4b7af` under `sources/runtime-base/`.
- Linux amd64, `/usr/bin/python3`, and no network access for the runtime import smoke.

## Deterministic owner runtime build

Run the reviewed builder twice from this repository root with absent output directories:

```sh
PYTHONPATH=sources/myuna-core/src:sources/myuna-deploy/scripts PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  sources/myuna-deploy/scripts/build_p07_hybrid_live_releases_v1.py \
  --core-source sources/myuna-core --core-commit 4c13c0b20552b5d8a8720f180d0569405fed00b0 --core-output output-a/core \
  --deploy-source sources/myuna-deploy --deploy-commit c1aac3b2a41edfe8596cdf895bd0c8e9bbb6dcb1 \
  --runtime-base sources/runtime-base/6b10fc936994eaeb97fae4d4f96375c93ddcf9a505140cbaac6d9ef304b4b7af --runtime-output output-a/runtime \
  --runtime-profile p07-owner-private-memory-v1
```

The expected Core release is `b94885c0e052942abffd36e228d6265f3c4ab666ea623e8d2b9fc2c27a869e4b`; the expected owner-runtime release is `c8750179574a6e61dca8a593c2227ad8e14ac2171809dff87f564b79864207b5`. Reopen them with the reviewed validators and run the exact service-identity, runtime-only `PYTHONPATH`, `-B`, no-bytecode, network-denied import smoke before installation. Installation is content-addressed and must never overwrite an existing release.

## AstrBot image

The accepted AstrBot OCI image/config/archive binding is unchanged and is recorded in `SOURCE_MANIFEST.json`. Use the reviewed `sources/myuna-deploy/scripts/build_telegram_gateway_release_v1.py` route and compare independently generated receipts before load.

## Modify

Changes to Core, Deploy, AstrBot, the runtime base, selected overlays, or the import closure produce new source and release identities. Do not reuse the identities above for modified bytes. Runtime selection remains a separate supervised live operation.
