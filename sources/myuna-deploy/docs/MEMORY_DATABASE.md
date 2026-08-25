# Myuna memory database

Status: Stage 1 development database  
Data class: synthetic only  
PostgreSQL major: 18

## Trust boundaries

`myuna_dev` is a development fact store, not an active personal-memory system.
It accepts only the committed synthetic fixture until a later user-approved
stage. Operational/server records are rejected by a database constraint and
belong to a separate future store.

Roles:

| Role | Login | Purpose |
|---|---|---|
| `postgres` | local admin | package/cluster administration, extensions, backup and restore |
| `myuna_dev_owner` | no | owns schemas and tables; used only through controlled migrations |
| `myuna_dev_app` | local peer only | select/insert runtime surface; cannot update or delete |

The Linux user `myuna` can request database role `myuna_dev_app` only for
database `myuna_dev` through the Unix socket. No database password is created.

## Physical model

- `memory_source`: allowed provenance; excludes operational records.
- `memory_event`: detailed source text and time representation.
- `memory_assertion`: searchable facts, preferences, anchors and current state.
- `memory_anchor`: firsts, exact quotes and important moments.
- `memory_relation`: extensible assertion-to-entity relationships.
- `memory_revision`: append-only correction/status chain.
- `memory_embedding`: replaceable vectors keyed by provider/model revision.
- `memory_consolidation_run`: derived compression and review runs.
- `memory_policy_action`: reversible suppression/exclusion and future purge receipts.
- `memory_access_audit`: purpose-bound access receipts without raw query text.
- `myuna_admin.schema_migration`: immutable migration checksums.
- `myuna_admin.dataset_load`: synthetic dataset provenance.

The application role has select/insert only. Corrections append a successor and
revision; they do not overwrite the old assertion. Physical purge remains an
administrative, separately approved operation.

## Retrieval baseline

Stage 1 validates hard filters, B-tree time/status access, GIN arrays/JSONB,
`pg_trgm`, and exact pgvector scans. It deliberately creates no HNSW or IVFFlat
index. The seeded four-dimensional vectors are synthetic plumbing checks, not
semantic embeddings and may never be used for real answers.

## Backup and recovery

- Use PostgreSQL custom-format logical backups with SHA-256 sidecars.
- Keep live files on ext4; copy only completed backups to Windows storage.
- A backup is accepted only after `pg_restore` into an isolated drill database,
  row-count checks, extension checks, and automatic deletion of the drill DB.
- Synthetic backups may be copied to ordinary C/D engineering folders. Later
  real-memory backups require encryption and a separate secret-recovery plan.
- PITR/WAL archiving is intentionally deferred until real persistent data is
  approved; logical backup is sufficient for this synthetic-only stage.
