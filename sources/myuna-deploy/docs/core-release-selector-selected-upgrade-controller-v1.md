# Selected Core release upgrade controller v1 — R4B-A

R4B-A adds a pure composition controller. It deliberately keeps three actions
separate:

- `preflight()` verifies the exact live prestate but creates no Journal and
  reports `runtime_changed=false`;
- `activate()` is allowed only when no Journal exists, creates exactly one new
  Journal, and invokes the existing journaled upgrade state machine;
- `recover()` is allowed only when a Journal already exists and invokes the
  separately tested crash-recovery contract.

The controller receives its bundle, backend, and Journal factory as explicit
dependencies. It contains no fixed live path, CLI, installer, systemd command,
network access, Secret access, channel access, model call, or memory access.

Later stages must still provide and separately approve the fixed-path CLI,
content-addressed Executor release, inactive installation, read-only live
preflight, and final activation.
