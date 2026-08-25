\set ON_ERROR_STOP on

DO $verify$
DECLARE
    source_total integer;
    event_total integer;
    assertion_total integer;
    identity_gate_v1_applied boolean;
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'verification may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'database environment marker is not dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'database is not synthetic-only';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0002_real_memory_contract_v1'
          AND notes @> '{"real_data_inserted": false}'::jsonb
    ) THEN
        RAISE EXCEPTION 'real-memory v1 migration record is missing or unsafe';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0003_dev_runtime_fail_closed'
          AND notes @> '{"runtime_access": "synthetic-read-only"}'::jsonb
    ) INTO identity_gate_v1_applied;

    SELECT count(*) INTO source_total FROM memory.memory_source;
    SELECT count(*) INTO event_total FROM memory.memory_event;
    SELECT count(*) INTO assertion_total FROM memory.memory_assertion;
    IF source_total <> event_total
       OR source_total <> assertion_total
       OR source_total < 10009 THEN
        RAISE EXCEPTION 'synthetic row counts changed unexpectedly: %, %, %',
            source_total, event_total, assertion_total;
    END IF;
    IF EXISTS (
        SELECT 1 FROM myuna_identity.principal
        WHERE principal_kind <> 'test' OR principal_id <> 'principal-synthetic'
    ) THEN
        RAISE EXCEPTION 'a real principal was created during synthetic migration';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_namespace
        WHERE namespace_kind <> 'test' OR namespace_id <> 'ns-synthetic-dev'
    ) THEN
        RAISE EXCEPTION 'a real namespace was created during synthetic migration';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_source
        WHERE principal_id <> 'principal-synthetic'
           OR namespace_id <> 'ns-synthetic-dev'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_event
        WHERE namespace_id <> 'ns-synthetic-dev'
    ) OR EXISTS (
        SELECT 1 FROM memory.memory_assertion
        WHERE namespace_id <> 'ns-synthetic-dev'
    ) THEN
        RAISE EXCEPTION 'synthetic rows escaped the synthetic principal/namespace';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM memory.memory_assertion AS assertion
        JOIN memory.memory_source AS source USING (source_id)
        JOIN memory.memory_event AS event USING (event_id)
        WHERE assertion.namespace_id <> source.namespace_id
           OR assertion.namespace_id <> event.namespace_id
    ) THEN
        RAISE EXCEPTION 'namespace lineage mismatch';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_assertion
        WHERE memory_status = 'provisional'
          AND (
              review_after IS NULL
              OR consolidate_after IS NULL
              OR low_activity_after IS NULL
              OR review_after > consolidate_after
              OR consolidate_after > low_activity_after
          )
    ) THEN
        RAISE EXCEPTION 'provisional memory lacks the ordered 3/7/30 lifecycle';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_assertion
        WHERE confirmation_level = 'model_inferred'
          AND memory_status = 'confirmed'
    ) THEN
        RAISE EXCEPTION 'model inference was promoted to confirmed';
    END IF;
    IF has_table_privilege(
        'myuna_dev_app', 'myuna_identity.account_binding', 'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
        RAISE EXCEPTION 'Core application role can access account bindings';
    END IF;
    IF has_table_privilege(
        'myuna_dev_app', 'myuna_admin.sealed_archive_receipt', 'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
        RAISE EXCEPTION 'Core application role can access sealed archive receipts';
    END IF;
    IF identity_gate_v1_applied THEN
        IF has_table_privilege(
            'myuna_dev_app', 'memory.request_scoped_current_assertion', 'SELECT'
        ) OR has_table_privilege(
            'myuna_dev_app', 'memory.memory_assertion', 'SELECT'
        ) OR has_table_privilege(
            'myuna_dev_app', 'memory.memory_assertion', 'INSERT'
        ) OR NOT has_table_privilege(
            'myuna_dev_app', 'memory.synthetic_dev_current_assertion', 'SELECT'
        ) THEN
            RAISE EXCEPTION 'identity-gate runtime privileges are not fail-closed';
        END IF;
    ELSIF NOT has_table_privilege(
        'myuna_dev_app', 'memory.request_scoped_current_assertion', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'pre-hardening Core role cannot use the scoped memory view';
    END IF;
    IF EXISTS (SELECT 1 FROM myuna_identity.account_binding) THEN
        RAISE EXCEPTION 'an account binding was created before owner approval';
    END IF;
    IF EXISTS (SELECT 1 FROM myuna_admin.sealed_archive_receipt) THEN
        RAISE EXCEPTION 'sealed archive content/receipt was created prematurely';
    END IF;
    IF EXISTS (SELECT 1 FROM memory.memory_rationale)
       OR EXISTS (SELECT 1 FROM memory.memory_review_item)
       OR EXISTS (SELECT 1 FROM memory.memory_deletion_case) THEN
        RAISE EXCEPTION 'real-memory lifecycle tables are not empty';
    END IF;
END
$verify$;

SELECT EXISTS (
    SELECT 1
    FROM myuna_admin.schema_migration
    WHERE migration_version = '0003_dev_runtime_fail_closed'
) AS identity_gate_v1_applied
\gset

\if :identity_gate_v1_applied
SELECT
    (SELECT count(*) FROM myuna_identity.principal) AS principals,
    (SELECT count(*) FROM memory.memory_namespace) AS namespaces,
    (SELECT count(*) FROM memory.memory_source) AS sources,
    (SELECT count(*) FROM memory.memory_event) AS events,
    (SELECT count(*) FROM memory.memory_assertion) AS assertions,
    (SELECT count(*) FROM memory.synthetic_dev_current_assertion) AS scoped_current,
    current_setting('myuna.synthetic_only') AS synthetic_only;
\else
SET myuna.namespace_id = 'ns-synthetic-dev';

SELECT
    (SELECT count(*) FROM myuna_identity.principal) AS principals,
    (SELECT count(*) FROM memory.memory_namespace) AS namespaces,
    (SELECT count(*) FROM memory.memory_source) AS sources,
    (SELECT count(*) FROM memory.memory_event) AS events,
    (SELECT count(*) FROM memory.memory_assertion) AS assertions,
    (SELECT count(*) FROM memory.request_scoped_current_assertion) AS scoped_current,
    current_setting('myuna.synthetic_only') AS synthetic_only;

RESET myuna.namespace_id;
\endif
