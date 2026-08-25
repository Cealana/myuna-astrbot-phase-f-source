# ADR-057: Owner Profile intelligent candidate write v1

Status: Accepted protocol; command boundary superseded by ADR-068

## Decision

P07-C completes the missing part of P07: Myuna may receive an explicit Owner-private
memory request, use only the approved local provider to analyse it, classify stable
facts, preferences, goals and ongoing projects, and prepare an exact next Profile
revision. The model never receives filesystem or lifecycle authority.

The v1 flow is proposal-first:

1. An authenticated Owner-private Telegram message explicitly invokes `/Benchmark <text>`.
2. Core authorizes `long_term_memory_write`, retrieves only bounded relevant Profile
   sections, and sends the supplied text plus those sections to the local provider with
   strict JSON output.
3. A deterministic validator rejects invented, temporal, ambiguous, malformed,
   oversized, duplicate or conflicting output. Accepted output becomes a private exact
   candidate derived from the active immutable revision.
4. Myuna renders the complete bounded change summary and a short confirmation code.
5. Only `/Benchmark confirm <code>` from the same authenticated scope may advance the exact
   candidate through `candidate_prepared`, `owner_confirmed` and `published`.
6. Publication creates a new immutable revision. The previous revision remains available
   for logical rollback; physical purge is not part of v1.

The candidate may remain pending for at most seven days. Pending storage contains the
exact candidate and scope binding, but not the raw source message. A new proposal may
not silently replace another pending candidate.

## Telegram ingress and session-context isolation

The outer AstrBot Telegram gate continues to reject arbitrary slash commands, but it
admits the exact bounded `/Benchmark` proposal/confirm/cancel grammar. The signed channel
envelope remains capability-free: `memory_candidate`, tools and media processing are
all false. Only after the gateway verifies the signature, private Owner binding and
Benchmark grammar does it derive `memory_candidate=true` in the authenticated Core context.
Malformed Benchmark commands and every other slash command stay fail-closed before the
Owner gateway.

Benchmark control turns are sent to Core as a single-turn request and are not loaded from or
committed to the ordinary 128-message session context. This prevents a candidate,
confirmation code or control reply from becoming ordinary conversational history. The
plugin, gateway and writer timeout budgets are ordered 175s > 165s > 150s, so an outer
layer cannot abandon a valid in-flight writer request before its bounded inner timeout.

## Stable and excluded data

Allowed categories remain `self_introduction`, `long_term_preference`,
`long_term_goal` and `ongoing_project`. Current status, dates that change the meaning,
deadlines, next actions, travel/location plans and other days-scale facts are rejected
as temporal and left for P08. Third-party private facts, credentials, financial,
government-ID, health and raw-message content are rejected.

The analyzer may add or update a section, or report no change / conflict / temporal-only.
It may not remove a section in v1. Inference without an explicit Owner statement is not
committable.

## Authority and privacy boundary

- Analysis is local-provider-only. DeepSeek, OpenAI and other external providers are
  denied for real Profile input, candidate content and existing Profile sections.
- Telegram Owner-private is the only v1 channel. QQ, groups and unauthenticated loopback
  calls are denied.
- The read service stays read-only through its systemd sandbox. A separate writer unit
  under the same dedicated Profile identity owns candidate/publication state; model
  output is untrusted input to that boundary.
- Candidate/profile/raw input/reply/identity and confirmation code are excluded from
  ordinary audit. Audit records only content-free operation, outcome, category/count
  buckets, revision numbers and fixed error categories.
- Unknown schema, stale base revision, digest mismatch, replay, timeout, unavailable
  provider/service, permission/type drift, crash residue and concurrent confirmation
  fail closed.

## Rollback

Before any activation, preserve exact Core/Deploy source refs, active Profile selector,
writer/read service state and previous immutable revision. A failed publication leaves
the old selector active. A successful publication can be rolled back by a new logical
restore event and selector update; no release, ledger, receipt or evidence is deleted.

The T2 activation transaction is separately gated. It pins an immutable Core release,
requires the local provider to remain loopback/offline/log-disabled, snapshots every
replaced config, leaves the writer socket inactive until the transaction is ready, and
stores each activation receipt under a unique non-overwriting name. Activation itself
does not send an Owner message or perform a memory write.

Writer execution code is installed as a separate content-addressed release under
`/opt/myuna/owner-profile-write-v1/releases/<sha256>/`, owned `root:myuna_owner_profile`
with `0550/0440` metadata. The writer identity is not added to the `myuna` group and
does not load code from Core releases, repositories, worktrees or mutable checkouts.
The byte-identical write capability policy is installed separately under the same
writer-only `/opt` boundary with `0750/0440` metadata. Before enabling the socket,
activation verifies policy readability as the actual writer identity; the shared
`/etc/myuna` capability tree remains inaccessible to that identity.

T2 activation and a content-free malformed-request socket probe now pass with zero
worker restarts. Those checks perform no model call, candidate creation or Profile
write. Authenticated Telegram proposal, exact confirmation, revision publication and
recall remain an explicit Owner E2E gate.

## Deferred

P07-C2 will cover passive candidate generation from ordinary Owner chat, but only after
P08 defines the stable-versus-temporal routing boundary. It must use bounded episode
selection, deterministic privacy/temporal prefilters, relevance-limited context,
deduplication/conflict checks and proposal-first review. Sending every complete raw
conversation to an external DeepSeek API is not the default design and would require a
separate explicit disclosure/retention authorization.

`/Diary` is a separate diary control/archive turn and never grants Profile candidate
consent. Automatic publication without Owner confirmation, cross-chat bulk analysis, P08/P10
double-write, deletion/purge, external model analysis and P15 cross-source proactive
retrieval are explicitly deferred.
