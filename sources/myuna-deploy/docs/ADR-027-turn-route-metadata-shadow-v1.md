# ADR-027: Turn/Route metadata-only Shadow v1 source candidate

Status: repository-only candidate; inactive
Date: 2026-07-20

## Decision

Build a source-only candidate that can, after a successful QQ reply has already
been returned, classify the same transient owner text for two advisory outputs:

- Turn: `A` natural close, `B` reply, `C` wait;
- Route: `A` local low-risk, `B` default cloud, `C` stronger cloud, `D`
  independent review.

The candidate writes only allowlisted metadata. It has no reply, routing,
memory, prompt, tool, identity, login, or approval authority.

R1 does not install or activate this candidate. In particular, the repository
files are not copied to `/opt`, `/usr/local/libexec`, `/etc`, `/run`, or `/var`;
no service, socket, model, port, task, timer, account, group, or marker is
created.

## Existing seam reused

The QQ runtime already closes the reply connection before a best-effort Memory
Shadow enqueue. The candidate changes only the repository version of that seam
to perform two independent sends:

```text
reply accepted -> connection closed
               -> Memory Shadow try/drop
               -> Turn/Route Shadow try/drop
```

Each marker check and send is isolated. A missing socket, full queue, exception,
or disabled marker is a silent drop and cannot escape to the reply path.

## Transient event

The proposed local datagram contains a fresh observation UUID, owner text,
character count, fixed event count `1`, bounded actual-route enum, and monotonic
enqueue time. Text is required for classification but may exist only in process
memory and the local Unix datagram. It is forbidden from traces and logs.

No channel, QQ, account, principal, namespace, conversation, event, message,
memory, prompt, reply, credential, token, cookie, QR, provider name, model name,
or route-reason value is sent.

## Frozen classifier

`scripts/turn_route_shadow/hybrid_classifier.py` is the exact candidate that
passed the isolated Hybrid v1 gate:

```text
SHA-256: 3a961875e11e0deb1aa48c5068a84e1fbdacd8b467e1a07e171078d47d8abc2b
```

Rules have precedence. Ambiguous cases may consult a fixed loopback-only model
client in a future approved stage. Model disabled, unavailable, timed out, or
invalid output falls back to Turn `B` and Route `D`.

The committed configuration keeps `model_enabled=false`.

## Actual route enum

The repository candidate maps Core metadata inside the QQ Gateway and carries
only one of these values:

```text
local_low_risk
deepseek_default
deepseek_pro
openai_or_independent_review
fallback
unknown
```

Current fixed mappings are `deepseek-v4-flash -> deepseek_default` and
`deepseek-v4-pro -> deepseek_pro`; everything else becomes `unknown`.

## Persistent trace

Trace fields are allowlisted and bucketed. Raw text and input hashes are both
forbidden. Every row states `shadow_only=true` and `production_effect=none`.
The proposed retention is seven days; retention automation is intentionally not
built or activated in R1.

## Security boundary

The systemd templates define a dedicated unprivileged user, no credentials,
strict filesystem protection, no home access, no capabilities, and only
AF_UNIX plus IPv4 loopback. The service may write only its systemd-created log
directory. It cannot start or stop the Windows model service.

The Marker, service account, installed files, retention job, and any processing
of real QQ text all require later immutable plans and explicit Owner approval.

## Rollback

R1 rollback is a normal Git revert because nothing is installed. A future live
rollback begins by removing the Turn/Route marker, then stopping its independent
socket and worker. It does not change Definition, Core, DeepSeek routing, QQ
identity, Memory Shadow, or NapCat.
