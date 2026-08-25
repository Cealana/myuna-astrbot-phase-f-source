# Persistent Session Context v1 candidate

## Scope

This candidate persists only the already-authorized rolling short-term context
for verified Owner-private text conversations. QQ and Telegram remain isolated
and use different service accounts, directories, databases, and namespaces.
There is no group-chat, other-user, cross-channel, memory-write, or append-only
transcript scope.

## Storage contract

- Backend: Python standard-library SQLite in WAL mode with `synchronous=FULL`.
- Commit point: one transaction after a successful Core reply. Failed Core
  requests are not committed.
- Retention: exactly the current bounded snapshot, at most 128 messages and
  131072 characters under the live context policy. Older complete turns are
  replaced rather than archived.
- QQ path: `/var/lib/myuna-gateway/session-context/context.db`.
- Telegram path:
  `/var/lib/myuna-telegram-gateway/session-context/context.db`.
- Directory mode: `0700`; database, WAL, and shared-memory modes: `0600`.
- Stored identity: a one-way, channel-namespaced conversation fingerprint; no
  raw platform account ID is stored by this component.
- Integrity: schema, namespace, roles, order, counts, timestamp, and canonical
  content digest are validated before content is returned.
- Conversation mismatch starts empty and never returns the previous snapshot.

The default runtime mode remains `memory`. The candidate is activated only by
setting `MYUNA_SESSION_CONTEXT_STORE=sqlite-v1` for each target Gateway.

The repaired candidate also aligns the bounded provider chain for Owner-private
E2E: DeepSeek remains at a 60-second transport timeout, the selected Core
source release enforces one effective provider attempt, each Gateway waits 70
seconds, and the existing AstrBot adapter waits 75 seconds. A process-local,
content-free fingerprint guard suppresses identical redelivery for five
minutes without retaining message text. Activation leaves
`/etc/myuna/qq.env` unchanged and uses the content-addressed Core Release
Selector to bind `WorkingDirectory` and `PYTHONPATH` to the reviewed Core
release. Rollback restores the prior selector binding and Gateway release while
preserving SQLite. It changes no model, credential, daily budget, channel, or
identity.

## Failure behavior

- A corrupt or structurally invalid snapshot is rejected before a model call.
- An atomic write failure preserves the last good database snapshot. The
  already-produced reply remains deliverable and only the fixed,
  content-free `context_persistence_degraded` stage is emitted.
- A changed conversation fingerprint is never mixed with the saved snapshot.
- No message content is written to service logs, activation receipts, or
  default inspector output.

## Local administration

Metadata-only inspection:

```sh
python3 session_context_admin.py inspect --channel qq
python3 session_context_admin.py inspect --channel telegram
```

Printing message content requires both root and the explicit
`--show-content` flag. This output contains private chat content and must not be
redirected to an uncontrolled location.

Clearing is root-only and requires an exact confirmation:

```sh
python3 session_context_admin.py clear --channel qq --confirm CLEAR-QQ
python3 session_context_admin.py clear --channel telegram --confirm CLEAR-TELEGRAM
python3 session_context_admin.py clear --channel all --confirm CLEAR-ALL
```

Clear uses SQLite secure deletion, truncates the WAL, and vacuums the database.
It is intentionally separate from disabling persistence: rollback keeps the
database unless the Owner separately confirms deletion.

## Live gate

This repository candidate does not authorize installation, service restart,
real private-chat reads, content inspection, or live E2E. Before activation,
preserve the current release and unit drop-ins, install a content-addressed
candidate, enable one explicit environment switch per Gateway, and predeclare
the Telegram and QQ Owner-private restart/E2E/rollback scope.
