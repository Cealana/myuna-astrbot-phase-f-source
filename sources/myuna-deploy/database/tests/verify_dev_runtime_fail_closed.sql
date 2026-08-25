\set ON_ERROR_STOP on

DO $verify$
DECLARE
    relation record;
BEGIN
    IF current_database() <> 'myuna_dev'
       OR current_setting('myuna.environment', true) IS DISTINCT FROM 'dev'
       OR current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'verification is limited to the synthetic dev database';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0003_dev_runtime_fail_closed'
          AND notes @> '{"real_data_inserted": false, "runtime_access": "synthetic-read-only"}'::jsonb
    ) THEN
        RAISE EXCEPTION 'identity-gate migration record is missing or unsafe';
    END IF;

    IF has_schema_privilege('myuna_dev_app', 'myuna_admin', 'USAGE')
       OR has_schema_privilege('myuna_dev_app', 'myuna_identity', 'USAGE')
       OR has_schema_privilege('myuna_dev_app', 'memory', 'CREATE') THEN
        RAISE EXCEPTION 'runtime role has forbidden schema privileges';
    END IF;

    FOR relation IN
        SELECT namespace.nspname AS schema_name, class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname IN ('myuna_admin', 'myuna_identity', 'memory')
          AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND NOT (
              namespace.nspname = 'memory'
              AND class.relname IN (
                  'synthetic_dev_current_assertion',
                  'synthetic_dev_proactive_candidate'
              )
          )
    LOOP
        IF has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'SELECT'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'INSERT'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'UPDATE'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'DELETE'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'TRUNCATE'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'REFERENCES'
        ) OR has_table_privilege(
            'myuna_dev_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'TRIGGER'
        ) THEN
            RAISE EXCEPTION 'runtime role can access forbidden relation %.%',
                relation.schema_name, relation.relation_name;
        END IF;
    END LOOP;

    IF NOT has_table_privilege(
        'myuna_dev_app', 'memory.synthetic_dev_current_assertion', 'SELECT'
    ) OR NOT has_table_privilege(
        'myuna_dev_app', 'memory.synthetic_dev_proactive_candidate', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'runtime role lacks an approved synthetic read surface';
    END IF;

    IF has_table_privilege(
        'myuna_dev_app', 'memory.synthetic_dev_current_assertion', 'INSERT'
    ) OR has_table_privilege(
        'myuna_dev_app', 'memory.synthetic_dev_current_assertion', 'UPDATE'
    ) OR has_table_privilege(
        'myuna_dev_app', 'memory.synthetic_dev_current_assertion', 'DELETE'
    ) THEN
        RAISE EXCEPTION 'approved synthetic view is not read-only';
    END IF;

    IF EXISTS (SELECT 1 FROM myuna_identity.account_binding)
       OR EXISTS (
           SELECT 1 FROM myuna_identity.principal
           WHERE principal_kind <> 'test' OR principal_id <> 'principal-synthetic'
       ) OR EXISTS (
           SELECT 1 FROM memory.memory_namespace
           WHERE namespace_kind <> 'test' OR namespace_id <> 'ns-synthetic-dev'
       ) THEN
        RAISE EXCEPTION 'real identity data was written';
    END IF;
END
$verify$;

SET ROLE myuna_dev_app;

SELECT count(*) AS approved_current_count
FROM memory.synthetic_dev_current_assertion;

SET myuna.namespace_id = 'ns-attacker-controlled';

SELECT count(*) AS namespace_guc_cannot_expand_scope
FROM memory.synthetic_dev_current_assertion;

RESET myuna.namespace_id;
RESET ROLE;
