# Selected Core upgrade inactive Executor installation v1

This contract installs one manifest-bound, content-addressed selected-upgrade
Executor release under `/opt/myuna/core-release-selector/selected-upgrade-executors`.
It also writes the exact non-sensitive receipt expected by the fixed CLI and
creates an empty root-only selected-upgrade activation state root.

The installer has no systemd, process, network, channel, model, memory, or
arbitrary command interface. It does not invoke the Executor and cannot select
or activate a Core release. Existing releases and conflicting receipts are
preserved and rejected; a failed new installation removes only paths created by
that attempt. A successful repeat is idempotent.

Installation and execution remain separate approval gates. Read-only live
preflight is not authorized by installation.
