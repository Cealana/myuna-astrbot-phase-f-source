\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'real-memory v1 dev migration may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'migration requires the synthetic-only dev database';
    END IF;
END
$guard$;

SET ROLE myuna_dev_owner;

CREATE SCHEMA IF NOT EXISTS myuna_identity AUTHORIZATION myuna_dev_owner;

CREATE TABLE myuna_identity.principal (
    principal_id text PRIMARY KEY CHECK (principal_id ~ '^principal-[a-z0-9][a-z0-9._-]{2,127}$'),
    principal_kind text NOT NULL CHECK (
        principal_kind IN ('owner', 'friend', 'service', 'test')
    ),
    authority_level text NOT NULL CHECK (
        authority_level IN ('owner', 'member', 'service', 'test')
    ),
    display_name text,
    principal_status text NOT NULL DEFAULT 'active' CHECK (
        principal_status IN ('pending', 'active', 'disabled', 'revoked')
    ),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX myuna_identity_one_active_owner_idx
    ON myuna_identity.principal ((principal_kind))
    WHERE principal_kind = 'owner' AND principal_status = 'active';

CREATE TABLE myuna_identity.account_binding (
    binding_id text PRIMARY KEY CHECK (length(btrim(binding_id)) > 0),
    principal_id text NOT NULL REFERENCES myuna_identity.principal(principal_id),
    channel_kind text NOT NULL CHECK (channel_kind IN ('local', 'astrbot_qq', 'web', 'api')),
    account_fingerprint text NOT NULL CHECK (account_fingerprint ~ '^[0-9a-f]{64}$'),
    binding_status text NOT NULL DEFAULT 'pending' CHECK (
        binding_status IN ('pending', 'verified', 'disabled', 'revoked')
    ),
    verified_at timestamptz,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (channel_kind, account_fingerprint),
    CHECK ((binding_status = 'verified') = (verified_at IS NOT NULL))
);

CREATE TABLE memory.memory_namespace (
    namespace_id text PRIMARY KEY CHECK (namespace_id ~ '^ns-[a-z0-9][a-z0-9._-]{2,127}$'),
    owner_principal_id text NOT NULL REFERENCES myuna_identity.principal(principal_id),
    namespace_kind text NOT NULL CHECK (namespace_kind IN ('personal', 'shared', 'test')),
    namespace_status text NOT NULL DEFAULT 'active' CHECK (
        namespace_status IN ('pending', 'active', 'frozen', 'disabled')
    ),
    policy_version text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO myuna_identity.principal (
    principal_id, principal_kind, authority_level, display_name, metadata
)
VALUES (
    'principal-synthetic', 'test', 'test', 'Synthetic Test Principal',
    '{"synthetic": true}'::jsonb
)
ON CONFLICT (principal_id) DO NOTHING;

INSERT INTO memory.memory_namespace (
    namespace_id, owner_principal_id, namespace_kind, policy_version, metadata
)
VALUES (
    'ns-synthetic-dev', 'principal-synthetic', 'test', 'memory-policy-v1.0',
    '{"synthetic": true}'::jsonb
)
ON CONFLICT (namespace_id) DO NOTHING;

ALTER TABLE memory.memory_source
    ADD COLUMN principal_id text NOT NULL DEFAULT 'principal-synthetic',
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev',
    ADD COLUMN channel_binding_id text;

ALTER TABLE memory.memory_source
    ADD CONSTRAINT memory_source_principal_fk
        FOREIGN KEY (principal_id) REFERENCES myuna_identity.principal(principal_id),
    ADD CONSTRAINT memory_source_namespace_fk
        FOREIGN KEY (namespace_id) REFERENCES memory.memory_namespace(namespace_id),
    ADD CONSTRAINT memory_source_binding_fk
        FOREIGN KEY (channel_binding_id) REFERENCES myuna_identity.account_binding(binding_id),
    ADD CONSTRAINT memory_source_id_namespace_unique UNIQUE (source_id, namespace_id);

ALTER TABLE memory.memory_event
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev';

ALTER TABLE memory.memory_event
    ADD CONSTRAINT memory_event_namespace_fk
        FOREIGN KEY (namespace_id) REFERENCES memory.memory_namespace(namespace_id),
    ADD CONSTRAINT memory_event_source_namespace_fk
        FOREIGN KEY (source_id, namespace_id)
        REFERENCES memory.memory_source(source_id, namespace_id),
    ADD CONSTRAINT memory_event_id_namespace_unique UNIQUE (event_id, namespace_id);

ALTER TABLE memory.memory_assertion
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev',
    ADD COLUMN review_after timestamptz,
    ADD COLUMN consolidate_after timestamptz,
    ADD COLUMN low_activity_after timestamptz;

UPDATE memory.memory_assertion AS assertion
SET
    review_after = event.recorded_at + interval '3 days',
    consolidate_after = event.recorded_at + interval '7 days',
    low_activity_after = event.recorded_at + interval '30 days'
FROM memory.memory_event AS event
WHERE event.event_id = assertion.event_id
  AND assertion.memory_status = 'provisional';

ALTER TABLE memory.memory_assertion
    ADD CONSTRAINT memory_assertion_namespace_fk
        FOREIGN KEY (namespace_id) REFERENCES memory.memory_namespace(namespace_id),
    ADD CONSTRAINT memory_assertion_source_namespace_fk
        FOREIGN KEY (source_id, namespace_id)
        REFERENCES memory.memory_source(source_id, namespace_id),
    ADD CONSTRAINT memory_assertion_event_namespace_fk
        FOREIGN KEY (event_id, namespace_id)
        REFERENCES memory.memory_event(event_id, namespace_id),
    ADD CONSTRAINT memory_assertion_id_namespace_unique UNIQUE (assertion_id, namespace_id),
    ADD CONSTRAINT memory_assertion_lifecycle_order_check CHECK (
        (
            review_after IS NULL
            AND consolidate_after IS NULL
            AND low_activity_after IS NULL
        ) OR (
            review_after IS NOT NULL
            AND consolidate_after IS NOT NULL
            AND low_activity_after IS NOT NULL
            AND review_after <= consolidate_after
            AND consolidate_after <= low_activity_after
        )
    ),
    ADD CONSTRAINT memory_assertion_model_inference_not_confirmed_check CHECK (
        NOT (confirmation_level = 'model_inferred' AND memory_status = 'confirmed')
    );

ALTER TABLE memory.memory_assertion
    DROP CONSTRAINT memory_assertion_memory_kind_check;
ALTER TABLE memory.memory_assertion
    ADD CONSTRAINT memory_assertion_memory_kind_check CHECK (
        memory_kind IN (
            'episodic', 'semantic', 'preference', 'anchor', 'current_state',
            'exact_quote', 'fact', 'relationship', 'project'
        )
    );

ALTER TABLE memory.memory_revision
    DROP CONSTRAINT memory_revision_revision_kind_check;
ALTER TABLE memory.memory_revision
    ADD CONSTRAINT memory_revision_revision_kind_check CHECK (
        revision_kind IN (
            'correction', 'state_change', 'confirmation', 'suppression',
            'restoration', 'tombstone', 'rationale_added', 'classification'
        )
    );

ALTER TABLE memory.memory_consolidation_run
    DROP CONSTRAINT memory_consolidation_run_run_kind_check;
ALTER TABLE memory.memory_consolidation_run
    ADD CONSTRAINT memory_consolidation_run_run_kind_check CHECK (
        run_kind IN (
            'daily_review', 'weekly_review', 'manual', 'idle_organizer',
            'three_day_review', 'seven_day_consolidation', 'thirty_day_archive'
        )
    ),
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev'
        REFERENCES memory.memory_namespace(namespace_id),
    ADD COLUMN proposal_only boolean NOT NULL DEFAULT true,
    ADD COLUMN organizer_kind text CHECK (
        organizer_kind IS NULL OR organizer_kind IN ('deterministic', 'local_model', 'manual')
    ),
    ADD COLUMN network_allowed boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT memory_consolidation_proposal_guard CHECK (
        organizer_kind <> 'local_model' OR (proposal_only AND NOT network_allowed)
    );

ALTER TABLE memory.memory_policy_action
    DROP CONSTRAINT memory_policy_action_action_kind_check;
ALTER TABLE memory.memory_policy_action
    ADD CONSTRAINT memory_policy_action_action_kind_check CHECK (
        action_kind IN (
            'exclude', 'sealed_archive', 'discard', 'suppress', 'restore',
            'low_activity', 'tombstone', 'purge_request', 'purge_complete'
        )
    ),
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev'
        REFERENCES memory.memory_namespace(namespace_id),
    ADD COLUMN recoverable_until timestamptz,
    ADD CONSTRAINT memory_policy_action_recovery_check CHECK (
        action_kind <> 'tombstone' OR (reversible AND recoverable_until IS NOT NULL)
    );

ALTER TABLE memory.memory_access_audit
    ADD COLUMN namespace_id text NOT NULL DEFAULT 'ns-synthetic-dev'
        REFERENCES memory.memory_namespace(namespace_id),
    ADD COLUMN principal_id text NOT NULL DEFAULT 'principal-synthetic'
        REFERENCES myuna_identity.principal(principal_id);

CREATE TABLE memory.memory_rationale (
    rationale_id text PRIMARY KEY,
    namespace_id text NOT NULL REFERENCES memory.memory_namespace(namespace_id),
    assertion_id text NOT NULL,
    source_event_id text NOT NULL,
    rationale_kind text NOT NULL CHECK (
        rationale_kind IN ('user_stated', 'conversation_context', 'model_hypothesis')
    ),
    confirmation_level text NOT NULL CHECK (
        confirmation_level IN ('model_inferred', 'observed', 'user_confirmed')
    ),
    rationale_text text NOT NULL CHECK (length(btrim(rationale_text)) > 0),
    rationale_status text NOT NULL DEFAULT 'active' CHECK (
        rationale_status IN ('provisional', 'confirmed', 'superseded', 'tombstoned')
    ),
    supersedes_id text REFERENCES memory.memory_rationale(rationale_id)
        DEFERRABLE INITIALLY DEFERRED,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (assertion_id, namespace_id)
        REFERENCES memory.memory_assertion(assertion_id, namespace_id),
    FOREIGN KEY (source_event_id, namespace_id)
        REFERENCES memory.memory_event(event_id, namespace_id),
    CHECK (
        NOT (
            rationale_kind = 'model_hypothesis'
            AND rationale_status = 'confirmed'
        )
    )
);

CREATE TABLE memory.memory_review_item (
    review_id text PRIMARY KEY,
    namespace_id text NOT NULL REFERENCES memory.memory_namespace(namespace_id),
    assertion_id text NOT NULL,
    review_kind text NOT NULL CHECK (
        review_kind IN ('clarify_reason', 'correction_or_change', 'time', 'subject', 'classification')
    ),
    question_text text NOT NULL CHECK (length(btrim(question_text)) > 0),
    due_at timestamptz NOT NULL,
    review_status text NOT NULL DEFAULT 'pending' CHECK (
        review_status IN ('pending', 'asked', 'answered', 'dismissed', 'expired')
    ),
    asked_at timestamptz,
    answered_at timestamptz,
    answer_event_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (assertion_id, namespace_id)
        REFERENCES memory.memory_assertion(assertion_id, namespace_id),
    FOREIGN KEY (answer_event_id, namespace_id)
        REFERENCES memory.memory_event(event_id, namespace_id),
    CHECK (answered_at IS NULL OR asked_at IS NOT NULL),
    CHECK (answer_event_id IS NULL OR review_status = 'answered')
);

CREATE TABLE memory.memory_deletion_case (
    deletion_case_id text PRIMARY KEY,
    namespace_id text NOT NULL REFERENCES memory.memory_namespace(namespace_id),
    requested_by_principal_id text NOT NULL REFERENCES myuna_identity.principal(principal_id),
    deletion_kind text NOT NULL CHECK (deletion_kind IN ('recoverable', 'permanent')),
    target_assertion_ids text[] NOT NULL DEFAULT ARRAY[]::text[],
    requested_at timestamptz NOT NULL,
    recoverable_until timestamptz,
    deletion_status text NOT NULL CHECK (
        deletion_status IN ('requested', 'quarantined', 'restored', 'purging', 'completed', 'failed')
    ),
    reason text,
    receipt jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(receipt) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (deletion_kind = 'recoverable' AND recoverable_until >= requested_at + interval '90 days')
        OR (deletion_kind = 'permanent' AND recoverable_until IS NULL)
    )
);

CREATE TABLE myuna_admin.sealed_archive_receipt (
    receipt_id text PRIMARY KEY,
    principal_id text NOT NULL REFERENCES myuna_identity.principal(principal_id),
    namespace_id text NOT NULL REFERENCES memory.memory_namespace(namespace_id),
    archive_object_fingerprint text NOT NULL CHECK (
        archive_object_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    captured_at timestamptz NOT NULL,
    receipt_status text NOT NULL CHECK (
        receipt_status IN ('stored', 'restored_by_owner', 'purge_requested', 'purged')
    ),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX memory_assertion_namespace_time_idx
    ON memory.memory_assertion (namespace_id, memory_status, created_at DESC);
CREATE INDEX memory_event_namespace_occurred_idx
    ON memory.memory_event (namespace_id, occurred_at DESC, recorded_at DESC);
CREATE INDEX memory_review_due_idx
    ON memory.memory_review_item (namespace_id, review_status, due_at);
CREATE INDEX memory_rationale_assertion_idx
    ON memory.memory_rationale (namespace_id, assertion_id, created_at DESC);
CREATE INDEX memory_deletion_status_idx
    ON memory.memory_deletion_case (namespace_id, deletion_status, requested_at DESC);

DROP VIEW memory.proactive_candidate;
DROP VIEW memory.current_assertion;

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
WHERE NOT assertion.do_not_surface_proactively
  AND (
      assertion.low_activity_after IS NULL
      OR assertion.low_activity_after > clock_timestamp()
  );

CREATE VIEW memory.request_scoped_current_assertion
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.current_assertion AS assertion
WHERE assertion.namespace_id = current_setting('myuna.namespace_id', true);

REVOKE ALL ON SCHEMA myuna_identity FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA myuna_identity FROM PUBLIC, myuna_dev_app;
GRANT USAGE ON SCHEMA myuna_identity TO myuna_dev_app;
GRANT SELECT ON TABLE myuna_identity.principal TO myuna_dev_app;
GRANT SELECT ON TABLE memory.memory_namespace TO myuna_dev_app;
GRANT SELECT, INSERT ON TABLE
    memory.memory_rationale,
    memory.memory_review_item,
    memory.memory_deletion_case
TO myuna_dev_app;
GRANT SELECT ON TABLE
    memory.current_assertion,
    memory.proactive_candidate,
    memory.request_scoped_current_assertion
TO myuna_dev_app;
REVOKE ALL ON TABLE myuna_identity.account_binding FROM myuna_dev_app;
REVOKE ALL ON TABLE myuna_admin.sealed_archive_receipt FROM PUBLIC, myuna_dev_app;

INSERT INTO myuna_admin.schema_migration (
    migration_version,
    migration_sha256,
    notes
)
VALUES (
    :'migration_version',
    :'migration_sha256',
    jsonb_build_object(
        'stage', 'real-memory-contract-v1-dev',
        'synthetic_only', true,
        'real_data_inserted', false,
        'lifecycle_days', jsonb_build_array(3, 7, 30),
        'deletion_recovery_days', 90
    )
);

RESET ROLE;

