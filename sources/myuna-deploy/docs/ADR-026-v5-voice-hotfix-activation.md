# ADR-026: v5 QQ voice hotfix activation

Status: prepared; activation requires the exact preview digest and explicit owner approval.

## Decision

The v5 voice hotfix is deployed as a new immutable Definition release and a new
immutable Core release. The original v5 release remains intact and becomes the
rollback target. The live Core Git checkout is not replaced or reset.

The change is limited to ordinary Myuna chat punctuation:

- omit one terminal Chinese `。` or English `.` from the whole reply;
- preserve sentence-internal full stops and expressive punctuation;
- leave Workbench, Checklist, quotations, and code behavior unchanged.

Only `myuna-core@qq.service` is restarted. NapCat, AstrBot, Minecraft, databases,
identity bindings, network listeners, model routing, daily budget, memory, tools,
vision, group handling, and Discord remain unchanged.

## Evidence and caveat

The combined 16-case Golden contract is hash-bound and release-gate ready. Core and
Definition regressions pass. Four bounded DeepSeek voice cases pass the automatic
punctuation and capability checks with no memory, tools, or QQ delivery.

One English synthetic prompt received a natural Chinese response. The punctuation
contract still passed, and this hotfix intentionally does not change language
selection. The activation preview records this as a non-blocking observation rather
than claiming a complete English-language semantic pass.

## Activation and rollback

Preview mode is read-only. Apply mode requires the exact user-approved digest. It
creates verified WSL and C-drive configuration backups, builds immutable Core and
Definition releases, records the approval, atomically moves the Definition pointer,
installs matching environment and capability metadata, and restarts only the QQ Core.

Any failure before completion restores the original Definition pointer, registry,
environment, capability manifest, and systemd drop-in, then restarts the original
Core. The prepared source commits and inactive artifacts may remain for audit, but
they cannot affect the running service without the runtime pointers and configuration.
