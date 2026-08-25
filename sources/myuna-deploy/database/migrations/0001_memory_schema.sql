\set ON_ERROR_STOP on

CREATE SCHEMA IF NOT EXISTS extensions AUTHORIZATION myuna_dev_owner;
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;

SET ROLE myuna_dev_owner;

CREATE SCHEMA IF NOT EXISTS myuna_admin AUTHORIZATION myuna_dev_owner;
CREATE SCHEMA IF NOT EXISTS memory AUTHORIZATION myuna_dev_owner;

CREATE TABLE myuna_admin.schema_migration (
    migration_version text PRIMARY KEY,
    migration_sha256 text NOT NULL CHECK (migration_sha256 ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_by text NOT NULL DEFAULT current_user,
    notes jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(notes) = 'object')
);

CREATE TABLE myuna_admin.dataset_load (
    dataset_id text PRIMARY KEY,
    dataset_sha256 text NOT NULL CHECK (dataset_sha256 ~ '^[0-9a-f]{64}$'),
    synthetic_only boolean NOT NULL CHECK (synthetic_only),
    assertion_count integer NOT NULL CHECK (assertion_count >= 0),
    loaded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    loaded_by text NOT NULL DEFAULT current_user,
    notes jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(notes) = 'object')
);

CREATE TABLE memory.memory_source (
    source_id text PRIMARY KEY,
    source_kind text NOT NULL CHECK (
        source_kind IN ('conversation', 'manual_import', 'document', 'model_inference')
    ),
    source_reference text NOT NULL,
    captured_at timestamptz NOT NULL,
    content_sha256 text CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$'),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE memory.memory_event (
    event_id text PRIMARY KEY,
    source_id text NOT NULL REFERENCES memory.memory_source(source_id),
    event_text text NOT NULL CHECK (length(btrim(event_text)) > 0),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    timezone_name text NOT NULL CHECK (length(btrim(timezone_name)) > 0),
    time_precision text NOT NULL CHECK (
        time_precision IN ('unknown', 'date', 'part_of_day', 'minute', 'exact')
    ),
    time_phrase text,
    exact_quote text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE memory.memory_assertion (
    assertion_id text PRIMARY KEY,
    source_id text NOT NULL REFERENCES memory.memory_source(source_id),
    event_id text NOT NULL REFERENCES memory.memory_event(event_id),
    memory_kind text NOT NULL CHECK (
        memory_kind IN ('episodic', 'semantic', 'preference', 'anchor', 'current_state')
    ),
    memory_status text NOT NULL CHECK (
        memory_status IN ('provisional', 'confirmed', 'suppressed', 'tombstoned')
    ),
    confirmation_level text NOT NULL CHECK (
        confirmation_level IN ('model_inferred', 'observed', 'user_confirmed')
    ),
    assertion_text text NOT NULL CHECK (length(btrim(assertion_text)) > 0),
    scope text[] NOT NULL DEFAULT ARRAY['global']::text[] CHECK (cardinality(scope) > 0),
    importance numeric(4, 3) NOT NULL DEFAULT 0.5 CHECK (importance BETWEEN 0 AND 1),
    sensitivity text NOT NULL DEFAULT 'normal' CHECK (
        sensitivity IN ('public', 'normal', 'sensitive', 'restricted')
    ),
    tags text[] NOT NULL DEFAULT ARRAY[]::text[],
    do_not_surface_proactively boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    supersedes_id text REFERENCES memory.memory_assertion(assertion_id)
        DEFERRABLE INITIALLY DEFERRED,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    policy_version text NOT NULL,
    policy_reasons text[] NOT NULL DEFAULT ARRAY[]::text[],
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (supersedes_id IS NULL OR supersedes_id <> assertion_id),
    CHECK (memory_kind <> 'current_state' OR expires_at IS NOT NULL),
    CHECK (memory_status <> 'suppressed' OR do_not_surface_proactively)
);

CREATE TABLE memory.memory_anchor (
    anchor_id text PRIMARY KEY,
    assertion_id text NOT NULL UNIQUE REFERENCES memory.memory_assertion(assertion_id),
    anchor_kind text NOT NULL CHECK (
        anchor_kind IN ('first', 'exact_quote', 'important_moment', 'manual')
    ),
    title text NOT NULL CHECK (length(btrim(title)) > 0),
    preservation_note text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE memory.memory_relation (
    relation_id text PRIMARY KEY,
    from_assertion_id text NOT NULL REFERENCES memory.memory_assertion(assertion_id),
    target_type text NOT NULL,
    target_id text NOT NULL,
    relation_kind text NOT NULL,
    weight numeric(4, 3) NOT NULL DEFAULT 0.5 CHECK (weight BETWEEN 0 AND 1),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (from_assertion_id, target_type, target_id, relation_kind)
);

CREATE TABLE memory.memory_revision (
    revision_id text PRIMARY KEY,
    previous_assertion_id text REFERENCES memory.memory_assertion(assertion_id),
    new_assertion_id text NOT NULL REFERENCES memory.memory_assertion(assertion_id),
    revision_kind text NOT NULL CHECK (
        revision_kind IN ('correction', 'confirmation', 'suppression', 'restoration', 'tombstone')
    ),
    reason text NOT NULL CHECK (length(btrim(reason)) > 0),
    actor text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (previous_assertion_id IS NULL OR previous_assertion_id <> new_assertion_id)
);

CREATE TABLE memory.memory_embedding (
    assertion_id text NOT NULL REFERENCES memory.memory_assertion(assertion_id),
    provider_id text NOT NULL,
    model_id text NOT NULL,
    model_revision text NOT NULL,
    dimensions integer NOT NULL CHECK (dimensions > 0),
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    embedding extensions.vector NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (assertion_id, provider_id, model_id, model_revision),
    CHECK (extensions.vector_dims(embedding) = dimensions)
);

CREATE TABLE memory.memory_consolidation_run (
    run_id text PRIMARY KEY,
    run_kind text NOT NULL CHECK (run_kind IN ('daily_review', 'weekly_review', 'manual')),
    policy_version text NOT NULL,
    input_assertion_ids text[] NOT NULL DEFAULT ARRAY[]::text[],
    output_assertion_id text REFERENCES memory.memory_assertion(assertion_id),
    run_status text NOT NULL CHECK (run_status IN ('planned', 'completed', 'failed', 'cancelled')),
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(details) = 'object')
);

CREATE TABLE memory.memory_policy_action (
    action_id text PRIMARY KEY,
    assertion_id text REFERENCES memory.memory_assertion(assertion_id),
    action_kind text NOT NULL CHECK (
        action_kind IN (
            'exclude', 'suppress', 'restore', 'tombstone', 'purge_request', 'purge_complete'
        )
    ),
    reversible boolean NOT NULL,
    reason text NOT NULL,
    actor text NOT NULL,
    effective_at timestamptz NOT NULL,
    reverses_action_id text REFERENCES memory.memory_policy_action(action_id),
    receipt jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(receipt) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE memory.memory_access_audit (
    audit_id text PRIMARY KEY,
    actor text NOT NULL,
    purpose text NOT NULL CHECK (length(btrim(purpose)) > 0),
    query_fingerprint text NOT NULL CHECK (query_fingerprint ~ '^[0-9a-f]{64}$'),
    result_assertion_ids text[] NOT NULL DEFAULT ARRAY[]::text[],
    access_scope text[] NOT NULL DEFAULT ARRAY[]::text[],
    occurred_at timestamptz NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE UNIQUE INDEX memory_assertion_one_successor_idx
    ON memory.memory_assertion (supersedes_id)
    WHERE supersedes_id IS NOT NULL;
CREATE INDEX memory_assertion_time_idx
    ON memory.memory_assertion (memory_status, memory_kind, created_at DESC);
CREATE INDEX memory_event_occurred_idx
    ON memory.memory_event (occurred_at DESC, recorded_at DESC);
CREATE INDEX memory_assertion_scope_idx
    ON memory.memory_assertion USING gin (scope);
CREATE INDEX memory_assertion_tags_idx
    ON memory.memory_assertion USING gin (tags);
CREATE INDEX memory_assertion_metadata_idx
    ON memory.memory_assertion USING gin (metadata jsonb_path_ops);
CREATE INDEX memory_source_metadata_idx
    ON memory.memory_source USING gin (metadata jsonb_path_ops);
CREATE INDEX memory_assertion_text_trgm_idx
    ON memory.memory_assertion USING gin (assertion_text extensions.gin_trgm_ops);
CREATE INDEX memory_embedding_model_idx
    ON memory.memory_embedding (provider_id, model_id, model_revision, dimensions);

CREATE VIEW memory.current_assertion
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.memory_assertion AS assertion
WHERE assertion.memory_status IN ('confirmed', 'provisional', 'suppressed')
  AND (assertion.expires_at IS NULL OR assertion.expires_at > clock_timestamp())
  AND NOT EXISTS (
      SELECT 1
      FROM memory.memory_assertion AS successor
      WHERE successor.supersedes_id = assertion.assertion_id
  );

CREATE VIEW memory.proactive_candidate
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.current_assertion AS assertion
WHERE NOT assertion.do_not_surface_proactively;

INSERT INTO myuna_admin.schema_migration (
    migration_version,
    migration_sha256,
    notes
)
VALUES (
    :'migration_version',
    :'migration_sha256',
    jsonb_build_object('stage', 'memory-stage-1', 'synthetic_only', true)
);

RESET ROLE;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA myuna_admin FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON SCHEMA memory FROM PUBLIC;
GRANT USAGE ON SCHEMA memory, extensions TO myuna_dev_app;
GRANT SELECT ON ALL TABLES IN SCHEMA memory TO myuna_dev_app;
GRANT INSERT ON TABLE
    memory.memory_source,
    memory.memory_event,
    memory.memory_assertion,
    memory.memory_anchor,
    memory.memory_relation,
    memory.memory_revision,
    memory.memory_embedding,
    memory.memory_consolidation_run,
    memory.memory_policy_action,
    memory.memory_access_audit
TO myuna_dev_app;

ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA memory
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA memory
    GRANT SELECT ON TABLES TO myuna_dev_app;
