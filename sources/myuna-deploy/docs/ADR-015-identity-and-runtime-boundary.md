# ADR-015: Authenticated identity and fail-closed memory runtime boundary

Status: accepted for synthetic dev rehearsal; real identity activation remains blocked.

## Decision

Myuna treats gateway authentication metadata as the only identity input. A message body,
display name, nickname, prompt, or claim such as “I am Cealana” cannot change a principal,
namespace, or authority level.

An account binding stores a domain-separated HMAC-SHA256 fingerprint of the stable gateway
account identifier. The raw account identifier is not written to PostgreSQL, logs, fixtures,
or source control. The HMAC pepper must contain at least 32 bytes, live outside the repository,
and be supplied as a service credential. Rotating the pepper requires an explicit re-binding
procedure; silently accepting both old and new fingerprints is forbidden.

Each verified binding points to both a principal and that principal's namespace. The database
foreign key prevents a binding from selecting a namespace owned by another principal.

## Synthetic dev role

`myuna_dev_app` is a synthetic-only, read-only role. It has no access to base memory tables,
identity tables, administration tables, broad current-memory views, or request-controlled
namespace views. It may select only these hard-coded synthetic views:

- `memory.synthetic_dev_current_assertion`
- `memory.synthetic_dev_proactive_candidate`

Changing `myuna.namespace_id` cannot broaden either view. The role has no memory write path.
Future real-memory runtime access must use a distinct role and a separately reviewed policy;
`myuna_dev_app` must never be repurposed for real owner or friend data.

## AstrBot boundary

AstrBot is an interface adapter, not an identity authority by itself. Its adapter must pass a
stable authenticated platform account identifier through a trusted envelope. Myuna Core
fingerprints that identifier, resolves the verified binding, then freezes the resulting context
before any prompt or model sees the message body.

Unknown, disabled, revoked, mismatched-channel, or wrong-pepper identities fail closed with a
generic authorization error. The response must not reveal whether an account or principal exists.

## Host encryption gate

Real identity activation and real memory writes remain blocked until host static-encryption
prerequisites are complete: Secure Boot verified, BitLocker recovery material stored off the
single physical NVMe, C/D encryption verified, and a recovery test plan documented. TPM clearing
is not part of this procedure.

## Evidence required before activation

1. Full Core unit suite passes, including owner/friend prompt-injection tests.
2. Migration verification proves the dev role has only the two approved view grants.
3. A transaction-only fictional identity and lifecycle rehearsal rolls back to zero real rows.
4. Core and retrieval services remain disabled during the rehearsal.
5. C and D evidence bundles have matching checksums.
