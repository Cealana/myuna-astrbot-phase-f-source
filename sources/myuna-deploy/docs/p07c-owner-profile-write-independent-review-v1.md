# P07-C Official independent source review v1

Status: Source and live pre-E2E review passed; Owner write E2E pending

## Scope reviewed

- Core candidate analysis, strict schema, intent parsing, private store, immutable
  publication, dynamic selector, Unix socket protocol and conversation routing.
- Deploy capability/environment contracts, Telegram explicit-consent projection,
  ownership transition, systemd sandbox and rollback-capable activation transaction.
- Audit and receipt projections for raw input, Profile text, query, identity,
  confirmation code, provider payload and digest leakage.

## Findings resolved during review

1. A partial initial ownership transfer did not always attempt root rollback. The flag is
   now set before chown and the failure path is covered by a synthetic test.
2. Re-activation incorrectly assumed revision 2 remained active. Root-owned state now
   bootstraps only once; service-owned state validates its current active revision.
3. Core read policy and Telegram write policy were mixed. Core retains the QQ/Telegram
   read profile while only the writer loads the Telegram-only write profile.
4. Writer code originally referenced a mutable repository checkout. It now pins a
   content-addressed Core release.
5. Activation originally overwrote a last-receipt file. Receipts are now unique,
   non-overwriting files; releases, ledgers, backups and receipts are never deleted.
6. Local-provider liveness alone was insufficient. T2 preflight now requires loopback
   bind, fixed local alias, offline mode and disabled provider logging.
7. Documentation incorrectly described separate Unix identities. It now records the
   actual design: separate units and sandboxes under one dedicated Profile identity.
8. Live bootstrap exposed that the dedicated Profile identity cannot traverse the
   `root:myuna 0550` Core release without a broad supplementary group. The writer now
   uses its own content-addressed `root:myuna_owner_profile 0550/0440` code release;
   the account receives no `myuna` group membership and the unit cannot read repos,
   worktrees or other `/srv/myuna` state.
9. The first post-activation socket probe exposed the same traversal problem for the
   shared `/etc/myuna` capability tree. The writer now receives a byte-identical
   `root:myuna_owner_profile 0750/0440` policy copy under its private `/opt` boundary,
   and activation verifies readability as the service identity before enabling the
   socket. The shared tree remains denied and no supplementary group was added.
10. The first Owner `/Diary` attempt exposed an untested outer ingress mismatch: the
    AstrBot plugin rejected every slash-prefixed message, so the request never reached
    the gateway, Core or writer. The plugin now admits only the exact Diary grammar,
    projects candidate consent only for that grammar, and retains all other slash
    commands as fail-closed. Cross-layer timeouts are ordered 175s/165s/150s, and Diary
    control turns bypass the ordinary 128-message session context.
11. The first repaired ingress attempt exposed a second consent-layer mismatch: the
    plugin projected candidate consent into the signed channel envelope, which the
    gateway correctly rejects as an upstream capability grant. The envelope is now
    always capability-free; only the verified gateway derives candidate consent for
    the authenticated Core context. The rejection was immediate and created no
    candidate, model call, memory write or service restart.

## Verification

- Core complete suite: 609 tests passed.
- Core P07-C write suite: 69 tests passed; active selector: 5 tests passed.
- Deploy P07-C write/environment/activation/code-release and compatibility suites:
  41 tests passed after the live permission repair.
- Focused configuration, capability, conversation and Telegram consent suites passed.
- Telegram Diary ingress/context/activation plus recovery, replay, context-capacity and
  compatibility regression passed 86/86 under the ordinary source identity. The old
  immutable-base builder suite passed 4/4 under its required root build identity. The
  focused repaired boundary, including a signed-envelope-to-authenticated-context
  cross-layer consent test, passed 36/36.
- Python AST parse and `git diff --check` passed for both worktrees.
- All tests use synthetic Profile content; no real Owner Profile, private message,
  credential, provider call, channel call or health endpoint was read or invoked.
- The selected Core release, isolated writer code release, service identity, socket,
  policy metadata, rollback journal absence and unique receipts were verified live.
  A malformed-request probe returned the exact fail-closed error with no model call,
  candidate or memory write; the writer remained active with zero restarts.

The Deploy repository's global discovery imports selected-upgrade tests from the formal
main checkout by fixed path, so it is not a valid pre-merge oracle for this worktree.
The P07-C affected Deploy tests were run directly from the dedicated worktree.

## Remaining gate

Source/mainline provenance, immutable releases, T2 activation and content-free local
poststate verification are complete. The first bootstrap failure rolled back cleanly;
the first post-activation probe then exposed the capability traversal defect, after
which the writer was stopped, repaired and re-activated before any memory operation.
Revision 2 remains active. Only authenticated Owner Telegram proposal, exact candidate
review, confirmation, revision 3 recall and final content-free audit remain pending.
