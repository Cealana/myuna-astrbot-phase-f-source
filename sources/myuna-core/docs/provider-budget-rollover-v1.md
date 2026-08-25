# Provider budget automatic UTC rollover v1

Status: Official semantic decision for P05 implementation and verification.

## Invariants

- The configured daily cap and pricing/accounting rules are unchanged.
- Provider execution still starts only after a successful reservation.
- A valid previous-day ledger never blocks a new UTC day merely because it
  contains `active` or `uncertain` reservations.
- Previous-day bytes are never deleted, rewritten, or described as settled.
- Unknown, corrupt, partial, future-dated, or cap-mismatched state fails closed.

## Authoritative time and locking

`DailyBudgetLedger` takes one timezone-aware clock reading after acquiring the
existing stable `<ledger>.lock` exclusive `flock`. The reading is normalized to
UTC and is authoritative for that transaction's date, timestamps, and rollover.
A naive clock value is rejected. A ledger date later than the authoritative UTC
date is clock regression and fails closed without archive or ledger mutation.

The same process-local lock and cross-process `flock` cover validation, archive
creation, ledger replacement, receipt recovery, and the requested accounting
operation. Concurrent contenders therefore observe either the old complete
ledger or the new complete ledger, never an unlocked intermediate state.

## Accepted ledger schema

The base ledger remains `schema_version: 1` for rollback compatibility. Its
required fields remain:

- `schema_version`
- `date_utc`
- `daily_limit_usd`
- `spent_usd`
- `reservations`

A current ledger may additionally contain exactly one optional `rollover`
object with schema `myuna.provider-budget-auto-rollover.v1`. Unknown top-level
or rollover fields are rejected. Amounts must be finite and non-negative;
reservations must be structurally valid; committed plus reserved value must not
exceed the unchanged configured cap.

The rollover object contains only:

- previous UTC date and current UTC date;
- exact archive filename and SHA-256;
- counts of previous `active` and `uncertain` reservations;
- UTC rollover timestamp;
- deterministic sanitized receipt filename.

It contains no reservation identifier or amount.

## Rollover transaction

For a strictly valid ledger whose date is earlier than the authoritative UTC
date:

1. Read and retain the exact original ledger bytes while holding the lock.
2. Write those exact bytes to private `archive/` storage using the existing
   `deepseek-<date>-<sha256>.json` content-addressed convention. If that name
   already exists, its metadata and exact bytes must match or rollover fails.
3. Atomically replace the live ledger with a current-day ledger having the
   identical `daily_limit_usd`, `spent_usd: "0"`, no reservations, and the
   content-free rollover object.
4. Durably create or verify the deterministic content-free receipt under
   `rollover-receipts/`.
5. Continue the originally requested reserve/snapshot/accounting operation.

The previous ledger's completed spend, active reservations, uncertain
reservations, reasons, identifiers, amounts, and timestamps remain only in the
immutable exact-byte archive. They are not carried into the new day's spend or
reservation total because they belong to the archived UTC day. This is neither
cancellation nor settlement.

A late settle, cancel, or uncertainty update for a reservation archived by
rollover must not mutate the immutable archive. It fails with
`BudgetAccountingError`; the archived reservation remains explicitly
unresolved and auditable.

## Atomicity, crash recovery, and idempotency

All file replacements use a same-directory temporary file, file `fsync`,
atomic rename, and parent-directory `fsync`. Archive creation is create-once;
existing content is verified rather than overwritten.

- Crash before archive publication: the live ledger remains authoritative.
- Crash after archive publication but before live-ledger rename: retry reuses
  the byte-identical archive and completes the rollover.
- Crash after live-ledger rename but before receipt publication: the new
  ledger's rollover object is authoritative; the next locked load verifies the
  archive and reconstructs the exact deterministic receipt.
- Crash after receipt publication: the next load verifies all three artifacts
  and proceeds without creating duplicates.

Synthetic failpoints exist only as injected test hooks. Production has no
environment-controlled failpoint.

## Corrupt and unknown recovery boundary

Automatic rollover handles only a strictly valid supported v1 ledger. It does
not guess at unknown schema, repair malformed JSON, lower a cap, synthesize
settlement, or overwrite drifted archives/receipts. These cases raise
`BudgetAccountingError` before provider execution.

The existing Deploy `reconcile_stale_provider_budget_v1.py` remains a bounded
operator recovery and rollback helper. It is not called by Core and is not the
normal rollover path. Its lock and existing archive convention remain
compatible with automatic rollover. Operator use still requires independent
prestate validation; no automatic code consumes or deletes its receipts.

Unloading or rolling back the Core release never deletes ledger, archive, or
receipt data. The pre-change Core accepts the optional rollover field while the
ledger is current because its v1 loader ignores extra fields. At a later UTC
boundary it may again require the retained manual helper if reservations exist.

## Typed degradation

Every `BudgetAccountingError` reaching HTTP maps to:

- HTTP status `503`;
- compatibility error `provider_budget_accounting_unavailable`;
- internal Core failure code `provider_budget_accounting_failed`;
- safe detail code `provider-budget-accounting-failed`;
- category `core_or_gateway_failure`;
- `retryable: false`;
- `owner_action_required: true`;
- the existing fixed canonical `core_or_gateway_failure` reply.

The exception message is never attached. The channel renderer may emit only the
fixed `reply`; it must not emit an amount, reservation identifier, ledger or
archive path, request fingerprint, upstream payload, or internal error text.
Internal audit may record only the fixed accounting classification and operation
stage in addition to already-approved request correlation metadata.

`BudgetExceededError` remains the distinct HTTP 429 daily-cap result. Automatic
rollover must not turn accounting uncertainty into cap exhaustion or vice versa.

## Verification matrix

Tests must cover missing/current ledgers, exact UTC boundary, multi-day rollover,
completed spend, active and uncertain reservations, late settlement, corrupt
JSON, unknown/partial schema, cap mismatch, future date/clock regression,
concurrent first requests, archive/receipt drift, crash before and after ledger
rename, receipt recovery, idempotent reload, safe HTTP projection, forbidden
channel strings, and unchanged budget-exceeded behavior.
