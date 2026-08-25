# Selected Core upgrade state-preserving inactive installation v1

Replacement Executor releases may be installed after an earlier activation
failed and left an append-only journal. The installer accepts unrelated prior
activation directories, snapshots their metadata and content hashes, and
requires the snapshot to remain identical after installation.

The directory for the new activation plan digest must not already exist. The
installer never opens, modifies, deletes, or reuses a prior journal and still
does not invoke the Executor, systemd, channels, models, or memory.
