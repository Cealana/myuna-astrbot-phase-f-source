\set ON_ERROR_STOP on

DO $preflight$
BEGIN
    IF current_database() <> 'myuna_dev'
       OR current_setting('myuna.environment', true) IS DISTINCT FROM 'dev'
       OR current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'fictional rehearsal is limited to the synthetic dev database';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0003_dev_runtime_fail_closed'
          AND notes @> '{"real_data_inserted": false}'::jsonb
    ) THEN
        RAISE EXCEPTION 'runtime hardening must be present before identity rehearsal';
    END IF;
    IF EXISTS (
        SELECT 1 FROM myuna_identity.principal
        WHERE principal_id LIKE 'principal-rehearsal-%'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_namespace
        WHERE namespace_id LIKE 'ns-rehearsal-%'
    ) THEN
        RAISE EXCEPTION 'stale fictional rehearsal rows exist';
    END IF;
END
$preflight$;

CREATE ROLE myuna_rehearsal_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE myuna_rehearsal_friend NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS;

SET ROLE myuna_dev_owner;

INSERT INTO myuna_identity.principal (
    principal_id, principal_kind, authority_level, display_name, metadata
)
VALUES
    (
        'principal-rehearsal-owner', 'owner', 'owner', 'Fictional Owner',
        '{"synthetic": true, "transaction_only": true}'::jsonb
    ),
    (
        'principal-rehearsal-friend', 'friend', 'member', 'Fictional Friend',
        '{"synthetic": true, "transaction_only": true}'::jsonb
    );

INSERT INTO memory.memory_namespace (
    namespace_id, owner_principal_id, namespace_kind, policy_version, metadata
)
VALUES
    (
        'ns-rehearsal-owner-private', 'principal-rehearsal-owner', 'personal',
        'memory-policy-v1.0', '{"synthetic": true, "transaction_only": true}'::jsonb
    ),
    (
        'ns-rehearsal-friend-private', 'principal-rehearsal-friend', 'personal',
        'memory-policy-v1.0', '{"synthetic": true, "transaction_only": true}'::jsonb
    );

INSERT INTO myuna_identity.account_binding (
    binding_id, principal_id, namespace_id, channel_kind, account_fingerprint,
    binding_status, verified_at, metadata
)
VALUES
    (
        'binding-rehearsal-owner', 'principal-rehearsal-owner',
        'ns-rehearsal-owner-private', 'astrbot_qq', repeat('a', 64),
        'verified', clock_timestamp(),
        '{"synthetic": true, "raw_account_stored": false}'::jsonb
    ),
    (
        'binding-rehearsal-friend', 'principal-rehearsal-friend',
        'ns-rehearsal-friend-private', 'astrbot_qq', repeat('b', 64),
        'verified', clock_timestamp(),
        '{"synthetic": true, "raw_account_stored": false}'::jsonb
    );

INSERT INTO memory.memory_source (
    source_id, source_kind, source_reference, captured_at, content_sha256, metadata,
    principal_id, namespace_id, channel_binding_id
)
VALUES
    (
        'source-rehearsal-owner-baseline', 'conversation', 'fictional:owner:baseline',
        clock_timestamp(), repeat('1', 64), '{"synthetic": true}'::jsonb,
        'principal-rehearsal-owner', 'ns-rehearsal-owner-private',
        'binding-rehearsal-owner'
    ),
    (
        'source-rehearsal-owner-recoverable', 'conversation', 'fictional:owner:recoverable',
        clock_timestamp(), repeat('2', 64), '{"synthetic": true}'::jsonb,
        'principal-rehearsal-owner', 'ns-rehearsal-owner-private',
        'binding-rehearsal-owner'
    ),
    (
        'source-rehearsal-owner-permanent', 'conversation', 'fictional:owner:permanent',
        clock_timestamp(), repeat('3', 64), '{"synthetic": true}'::jsonb,
        'principal-rehearsal-owner', 'ns-rehearsal-owner-private',
        'binding-rehearsal-owner'
    ),
    (
        'source-rehearsal-owner-provisional', 'conversation', 'fictional:owner:provisional',
        clock_timestamp(), repeat('4', 64), '{"synthetic": true}'::jsonb,
        'principal-rehearsal-owner', 'ns-rehearsal-owner-private',
        'binding-rehearsal-owner'
    ),
    (
        'source-rehearsal-friend-baseline', 'conversation', 'fictional:friend:baseline',
        clock_timestamp(), repeat('5', 64), '{"synthetic": true}'::jsonb,
        'principal-rehearsal-friend', 'ns-rehearsal-friend-private',
        'binding-rehearsal-friend'
    );

INSERT INTO memory.memory_event (
    event_id, source_id, namespace_id, event_text, occurred_at, recorded_at,
    timezone_name, time_precision, time_phrase, exact_quote, metadata
)
SELECT
    replace(source_id, 'source-', 'event-'),
    source_id,
    namespace_id,
    CASE source_id
        WHEN 'source-rehearsal-owner-permanent'
            THEN 'FICTIONAL-PERMANENT-SECRET-7D21 event'
        ELSE 'Fictional identity-gate rehearsal event'
    END,
    clock_timestamp(),
    clock_timestamp(),
    'Asia/Shanghai',
    'minute',
    'fictional rehearsal minute',
    CASE source_id
        WHEN 'source-rehearsal-owner-baseline'
            THEN 'Fictional exact quote anchor'
        WHEN 'source-rehearsal-owner-permanent'
            THEN 'FICTIONAL-PERMANENT-SECRET-7D21 quote'
        ELSE NULL
    END,
    '{"synthetic": true}'::jsonb
FROM memory.memory_source
WHERE source_id LIKE 'source-rehearsal-%';

INSERT INTO memory.memory_assertion (
    assertion_id, source_id, event_id, namespace_id, memory_kind, memory_status,
    confirmation_level, assertion_text, scope, importance, sensitivity, tags,
    do_not_surface_proactively, expires_at, supersedes_id, schema_version,
    policy_version, policy_reasons, metadata, review_after, consolidate_after,
    low_activity_after
)
VALUES
    (
        'assertion-rehearsal-owner-baseline', 'source-rehearsal-owner-baseline',
        'event-rehearsal-owner-baseline', 'ns-rehearsal-owner-private',
        'exact_quote', 'confirmed', 'user_confirmed',
        'Fictional owner exact quote anchor', ARRAY['private'], 0.9, 'restricted',
        ARRAY['fictional', 'anchor'], false, NULL, NULL, 1, 'memory-policy-v1.0',
        ARRAY['fictional-rehearsal'], '{"synthetic": true}'::jsonb, NULL, NULL, NULL
    ),
    (
        'assertion-rehearsal-owner-recoverable', 'source-rehearsal-owner-recoverable',
        'event-rehearsal-owner-recoverable', 'ns-rehearsal-owner-private',
        'episodic', 'confirmed', 'user_confirmed',
        'Fictional recoverable memory', ARRAY['private'], 0.7, 'sensitive',
        ARRAY['fictional', 'recoverable'], false, NULL, NULL, 1, 'memory-policy-v1.0',
        ARRAY['fictional-rehearsal'], '{"synthetic": true}'::jsonb, NULL, NULL, NULL
    ),
    (
        'assertion-rehearsal-owner-permanent', 'source-rehearsal-owner-permanent',
        'event-rehearsal-owner-permanent', 'ns-rehearsal-owner-private',
        'fact', 'confirmed', 'user_confirmed',
        'FICTIONAL-PERMANENT-SECRET-7D21 assertion', ARRAY['private'], 0.8, 'restricted',
        ARRAY['fictional', 'permanent'], true, NULL, NULL, 1, 'memory-policy-v1.0',
        ARRAY['fictional-rehearsal'], '{"synthetic": true}'::jsonb, NULL, NULL, NULL
    ),
    (
        'assertion-rehearsal-owner-provisional', 'source-rehearsal-owner-provisional',
        'event-rehearsal-owner-provisional', 'ns-rehearsal-owner-private',
        'current_state', 'provisional', 'observed',
        'Fictional temporary preference', ARRAY['private'], 0.5, 'normal',
        ARRAY['fictional', 'provisional'], false, clock_timestamp() + interval '90 days',
        NULL, 1, 'memory-policy-v1.0', ARRAY['fictional-rehearsal'],
        '{"synthetic": true}'::jsonb, clock_timestamp() + interval '3 days',
        clock_timestamp() + interval '7 days', clock_timestamp() + interval '30 days'
    ),
    (
        'assertion-rehearsal-friend-baseline', 'source-rehearsal-friend-baseline',
        'event-rehearsal-friend-baseline', 'ns-rehearsal-friend-private',
        'preference', 'confirmed', 'user_confirmed',
        'Fictional friend preference', ARRAY['private'], 0.6, 'normal',
        ARRAY['fictional', 'friend'], false, NULL, NULL, 1, 'memory-policy-v1.0',
        ARRAY['fictional-rehearsal'], '{"synthetic": true}'::jsonb, NULL, NULL, NULL
    );

INSERT INTO memory.memory_anchor (
    anchor_id, assertion_id, anchor_kind, title, preservation_note
)
VALUES (
    'anchor-rehearsal-owner-baseline', 'assertion-rehearsal-owner-baseline',
    'exact_quote', 'Fictional exact quote', 'Transaction-only rehearsal'
);

INSERT INTO memory.memory_rationale (
    rationale_id, namespace_id, assertion_id, source_event_id, rationale_kind,
    confirmation_level, rationale_text, rationale_status, metadata
)
VALUES (
    'rationale-rehearsal-owner-provisional', 'ns-rehearsal-owner-private',
    'assertion-rehearsal-owner-provisional', 'event-rehearsal-owner-provisional',
    'conversation_context', 'observed', 'Fictional provisional rationale',
    'provisional', '{"synthetic": true}'::jsonb
);

INSERT INTO memory.memory_review_item (
    review_id, namespace_id, assertion_id, review_kind, question_text, due_at,
    review_status, metadata
)
VALUES (
    'review-rehearsal-owner-provisional', 'ns-rehearsal-owner-private',
    'assertion-rehearsal-owner-provisional', 'classification',
    'Fictional three-day clarification question?', clock_timestamp() + interval '3 days',
    'pending', '{"synthetic": true}'::jsonb
);

CREATE VIEW memory.rehearsal_owner_current_assertion
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.current_assertion AS assertion
WHERE assertion.namespace_id = 'ns-rehearsal-owner-private';

CREATE VIEW memory.rehearsal_friend_current_assertion
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.current_assertion AS assertion
WHERE assertion.namespace_id = 'ns-rehearsal-friend-private';

RESET ROLE;

GRANT USAGE ON SCHEMA memory TO myuna_rehearsal_owner, myuna_rehearsal_friend;
GRANT SELECT ON memory.rehearsal_owner_current_assertion TO myuna_rehearsal_owner;
GRANT SELECT ON memory.rehearsal_friend_current_assertion TO myuna_rehearsal_friend;

DO $access_verify$
BEGIN
    IF has_table_privilege(
        'myuna_rehearsal_owner', 'memory.rehearsal_friend_current_assertion', 'SELECT'
    ) OR has_table_privilege(
        'myuna_rehearsal_friend', 'memory.rehearsal_owner_current_assertion', 'SELECT'
    ) OR has_table_privilege(
        'myuna_rehearsal_owner', 'memory.memory_assertion', 'SELECT'
    ) OR has_table_privilege(
        'myuna_rehearsal_friend', 'memory.memory_assertion', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'fictional role can bypass namespace views';
    END IF;
END
$access_verify$;

SET ROLE myuna_rehearsal_owner;
SELECT count(*) AS fictional_owner_initial_visible
FROM memory.rehearsal_owner_current_assertion;
RESET ROLE;

SET ROLE myuna_rehearsal_friend;
SELECT count(*) AS fictional_friend_initial_visible
FROM memory.rehearsal_friend_current_assertion;
RESET ROLE;

SET ROLE myuna_dev_owner;

INSERT INTO memory.memory_assertion (
    assertion_id, source_id, event_id, namespace_id, memory_kind, memory_status,
    confirmation_level, assertion_text, scope, importance, sensitivity, tags,
    do_not_surface_proactively, expires_at, supersedes_id, schema_version,
    policy_version, policy_reasons, metadata
)
VALUES (
    'assertion-rehearsal-owner-recoverable-tombstone',
    'source-rehearsal-owner-recoverable', 'event-rehearsal-owner-recoverable',
    'ns-rehearsal-owner-private', 'episodic', 'tombstoned', 'observed',
    '[fictional recoverable quarantine marker]', ARRAY['private'], 0.7, 'sensitive',
    ARRAY['fictional', 'quarantine'], true, NULL,
    'assertion-rehearsal-owner-recoverable', 1, 'memory-policy-v1.0',
    ARRAY['owner-approved-fictional-rehearsal'], '{"synthetic": true}'::jsonb
);

INSERT INTO memory.memory_revision (
    revision_id, previous_assertion_id, new_assertion_id, revision_kind, reason, actor
)
VALUES (
    'revision-rehearsal-owner-quarantine', 'assertion-rehearsal-owner-recoverable',
    'assertion-rehearsal-owner-recoverable-tombstone', 'tombstone',
    'Fictional 90-day recoverable deletion rehearsal', 'principal-rehearsal-owner'
);

INSERT INTO memory.memory_policy_action (
    action_id, assertion_id, action_kind, reversible, reason, actor, effective_at,
    receipt, namespace_id, recoverable_until
)
VALUES (
    'action-rehearsal-owner-quarantine', 'assertion-rehearsal-owner-recoverable',
    'tombstone', true, 'Fictional owner recoverable deletion',
    'principal-rehearsal-owner', clock_timestamp(),
    '{"synthetic": true}'::jsonb, 'ns-rehearsal-owner-private',
    clock_timestamp() + interval '90 days'
);

INSERT INTO memory.memory_deletion_case (
    deletion_case_id, namespace_id, requested_by_principal_id, deletion_kind,
    target_assertion_ids, requested_at, recoverable_until, deletion_status, reason, receipt
)
VALUES (
    'deletion-rehearsal-owner-recoverable', 'ns-rehearsal-owner-private',
    'principal-rehearsal-owner', 'recoverable',
    ARRAY['assertion-rehearsal-owner-recoverable'], clock_timestamp(),
    clock_timestamp() + interval '90 days', 'quarantined',
    'Fictional recoverable deletion', '{"synthetic": true}'::jsonb
);

DO $quarantine_verify$
BEGIN
    IF EXISTS (
        SELECT 1 FROM memory.current_assertion
        WHERE assertion_id = 'assertion-rehearsal-owner-recoverable'
    ) OR EXISTS (
        SELECT 1 FROM memory.current_assertion
        WHERE assertion_id = 'assertion-rehearsal-owner-recoverable-tombstone'
    ) OR NOT EXISTS (
        SELECT 1 FROM memory.memory_deletion_case
        WHERE deletion_case_id = 'deletion-rehearsal-owner-recoverable'
          AND deletion_status = 'quarantined'
          AND recoverable_until >= requested_at + interval '90 days'
    ) THEN
        RAISE EXCEPTION '90-day recoverable quarantine did not hide the memory safely';
    END IF;
END
$quarantine_verify$;

INSERT INTO memory.memory_assertion (
    assertion_id, source_id, event_id, namespace_id, memory_kind, memory_status,
    confirmation_level, assertion_text, scope, importance, sensitivity, tags,
    do_not_surface_proactively, expires_at, supersedes_id, schema_version,
    policy_version, policy_reasons, metadata
)
VALUES (
    'assertion-rehearsal-owner-recoverable-restored',
    'source-rehearsal-owner-recoverable', 'event-rehearsal-owner-recoverable',
    'ns-rehearsal-owner-private', 'episodic', 'confirmed', 'user_confirmed',
    'Fictional recoverable memory', ARRAY['private'], 0.7, 'sensitive',
    ARRAY['fictional', 'restored'], false, NULL,
    'assertion-rehearsal-owner-recoverable-tombstone', 1, 'memory-policy-v1.0',
    ARRAY['owner-approved-fictional-restoration'], '{"synthetic": true}'::jsonb
);

INSERT INTO memory.memory_revision (
    revision_id, previous_assertion_id, new_assertion_id, revision_kind, reason, actor
)
VALUES (
    'revision-rehearsal-owner-restoration',
    'assertion-rehearsal-owner-recoverable-tombstone',
    'assertion-rehearsal-owner-recoverable-restored', 'restoration',
    'Fictional owner restoration rehearsal', 'principal-rehearsal-owner'
);

INSERT INTO memory.memory_policy_action (
    action_id, assertion_id, action_kind, reversible, reason, actor, effective_at,
    reverses_action_id, receipt, namespace_id
)
VALUES (
    'action-rehearsal-owner-restoration',
    'assertion-rehearsal-owner-recoverable-restored', 'restore', true,
    'Fictional owner restoration', 'principal-rehearsal-owner', clock_timestamp(),
    'action-rehearsal-owner-quarantine', '{"synthetic": true}'::jsonb,
    'ns-rehearsal-owner-private'
);

UPDATE memory.memory_deletion_case
SET deletion_status = 'restored',
    receipt = '{"synthetic": true, "restoration_verified": true}'::jsonb
WHERE deletion_case_id = 'deletion-rehearsal-owner-recoverable';

DO $restoration_verify$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM memory.current_assertion
        WHERE assertion_id = 'assertion-rehearsal-owner-recoverable-restored'
          AND namespace_id = 'ns-rehearsal-owner-private'
    ) OR EXISTS (
        SELECT 1 FROM memory.current_assertion
        WHERE assertion_id IN (
            'assertion-rehearsal-owner-recoverable',
            'assertion-rehearsal-owner-recoverable-tombstone'
        )
    ) THEN
        RAISE EXCEPTION 'recoverable memory restoration did not produce one current successor';
    END IF;
END
$restoration_verify$;

INSERT INTO memory.memory_deletion_case (
    deletion_case_id, namespace_id, requested_by_principal_id, deletion_kind,
    target_assertion_ids, requested_at, recoverable_until, deletion_status, reason, receipt
)
VALUES (
    'deletion-rehearsal-owner-permanent', 'ns-rehearsal-owner-private',
    'principal-rehearsal-owner', 'permanent',
    ARRAY['assertion-rehearsal-owner-permanent'], clock_timestamp(), NULL, 'purging',
    'Fictional permanent deletion', '{"synthetic": true}'::jsonb
);

DELETE FROM memory.memory_anchor
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_rationale
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_review_item
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_relation
WHERE from_assertion_id = 'assertion-rehearsal-owner-permanent'
   OR target_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_revision
WHERE previous_assertion_id = 'assertion-rehearsal-owner-permanent'
   OR new_assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_embedding
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_policy_action
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_assertion
WHERE assertion_id = 'assertion-rehearsal-owner-permanent';
DELETE FROM memory.memory_event
WHERE event_id = 'event-rehearsal-owner-permanent';
DELETE FROM memory.memory_source
WHERE source_id = 'source-rehearsal-owner-permanent';

UPDATE memory.memory_deletion_case
SET deletion_status = 'completed',
    receipt = jsonb_build_object(
        'synthetic', true,
        'content_purged', true,
        'receipt_sha256', repeat('6', 64)
    )
WHERE deletion_case_id = 'deletion-rehearsal-owner-permanent';

DO $purge_verify$
BEGIN
    IF EXISTS (
        SELECT 1 FROM memory.memory_source
        WHERE source_id = 'source-rehearsal-owner-permanent'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_event
        WHERE event_id = 'event-rehearsal-owner-permanent'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_assertion
        WHERE assertion_id = 'assertion-rehearsal-owner-permanent'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_source
        WHERE source_reference LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
           OR metadata::text LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_event
        WHERE event_text LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
           OR coalesce(exact_quote, '') LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
           OR metadata::text LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_assertion
        WHERE assertion_text LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
           OR metadata::text LIKE '%FICTIONAL-PERMANENT-SECRET-7D21%'
    ) OR NOT EXISTS (
        SELECT 1 FROM memory.memory_deletion_case
        WHERE deletion_case_id = 'deletion-rehearsal-owner-permanent'
          AND deletion_status = 'completed'
          AND receipt @> '{"content_purged": true}'::jsonb
    ) THEN
        RAISE EXCEPTION 'permanent online purge rehearsal failed';
    END IF;
END
$purge_verify$;

RESET ROLE;

COPY (
    SELECT jsonb_build_object(
        'schema', 'myuna-fictional-identity-lifecycle-rehearsal-v1',
        'synthetic_only', true,
        'transaction_rollback_required', true,
        'raw_account_ids_stored', false,
        'owner_visible_current', (
            SELECT count(*) FROM memory.rehearsal_owner_current_assertion
        ),
        'friend_visible_current', (
            SELECT count(*) FROM memory.rehearsal_friend_current_assertion
        ),
        'owner_view_cross_namespace_rows', (
            SELECT count(*) FROM memory.rehearsal_owner_current_assertion
            WHERE namespace_id <> 'ns-rehearsal-owner-private'
        ),
        'friend_view_cross_namespace_rows', (
            SELECT count(*) FROM memory.rehearsal_friend_current_assertion
            WHERE namespace_id <> 'ns-rehearsal-friend-private'
        ),
        'recoverable_case_status', (
            SELECT deletion_status FROM memory.memory_deletion_case
            WHERE deletion_case_id = 'deletion-rehearsal-owner-recoverable'
        ),
        'recoverable_days', (
            SELECT extract(day FROM recoverable_until - requested_at)::integer
            FROM memory.memory_deletion_case
            WHERE deletion_case_id = 'deletion-rehearsal-owner-recoverable'
        ),
        'restored_current_rows', (
            SELECT count(*) FROM memory.current_assertion
            WHERE assertion_id = 'assertion-rehearsal-owner-recoverable-restored'
        ),
        'permanent_case_status', (
            SELECT deletion_status FROM memory.memory_deletion_case
            WHERE deletion_case_id = 'deletion-rehearsal-owner-permanent'
        ),
        'permanent_content_rows_remaining', (
            SELECT count(*) FROM memory.memory_assertion
            WHERE assertion_id = 'assertion-rehearsal-owner-permanent'
        ),
        'runtime_role_base_table_select', has_table_privilege(
            'myuna_dev_app', 'memory.memory_assertion', 'SELECT'
        ),
        'runtime_role_base_table_insert', has_table_privilege(
            'myuna_dev_app', 'memory.memory_assertion', 'INSERT'
        )
    )
) TO '/tmp/myuna-fictional-identity-lifecycle-evidence.json';
