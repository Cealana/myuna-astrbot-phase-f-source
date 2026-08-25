# Selected Core release upgrade fixed CLI v1 — R4B-B

R4B-B defines the fixed entrypoint and content-addressed Executor release
contract. It remains repository/work-only and is not installed or executed.

The CLI cannot operate from the Deploy repository. It requires:

- execution from the exact content-addressed `/opt` Executor directory;
- an exact nine-artifact Executor manifest and immutable file metadata;
- an exact inactive Executor installation receipt;
- the exact installed selected-upgrade transaction and its inactive receipt;
- the activation, transaction, inactive-install, Executor-release, and
  Executor-install digests supplied explicitly and cross-validated;
- a separate fixed live confirmation for `activate-live` and `recover-live`.

`preflight` uses the pure controller and fixed backend but creates no Journal.
`activate-live` can create only the digest-bound Journal. `recover-live` can
open only that existing Journal. No command, unit, path, shell, model, channel,
memory, Secret, or network target is caller-selectable.

Later stages must still build a deterministic Executor release, add and test an
inactive installer, install it in parallel, run read-only live preflight, and
obtain separate approval for final activation.
