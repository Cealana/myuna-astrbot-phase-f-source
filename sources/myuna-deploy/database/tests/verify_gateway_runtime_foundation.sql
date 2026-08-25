\set ON_ERROR_STOP on

DO $verify$
DECLARE
    runtime_role record;
    relation record;
    approved_function_count integer;
BEGIN
    IF current_database() <> 'myuna_dev'
       OR current_setting('myuna.environment', true) IS DISTINCT FROM 'dev'
       OR current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'gateway verification is limited to the synthetic dev database';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0004_gateway_runtime_foundation'
          AND notes @> '{
              "real_data_inserted": false,
              "runtime_access": "security-definer-functions-only",
              "plaintext_operational_content": false,
              "astrbot_connected": false
          }'::jsonb
    ) THEN
        RAISE EXCEPTION 'gateway migration record is missing or unsafe';
    END IF;

    SELECT * INTO runtime_role
    FROM pg_roles
    WHERE rolname = 'myuna_gateway_app';

    IF runtime_role IS NULL
       OR NOT runtime_role.rolcanlogin
       OR runtime_role.rolinherit
       OR runtime_role.rolsuper
       OR runtime_role.rolcreatedb
       OR runtime_role.rolcreaterole
       OR runtime_role.rolreplication
       OR runtime_role.rolbypassrls
       OR runtime_role.rolconnlimit <> 5 THEN
        RAISE EXCEPTION 'gateway runtime role attributes are unsafe';
    END IF;

    IF NOT has_schema_privilege('myuna_gateway_app', 'gateway_runtime', 'USAGE')
       OR has_schema_privilege('myuna_gateway_app', 'gateway_runtime', 'CREATE')
       OR has_schema_privilege('myuna_gateway_app', 'myuna_admin', 'USAGE')
       OR has_schema_privilege('myuna_gateway_app', 'myuna_identity', 'USAGE')
       OR has_schema_privilege('myuna_gateway_app', 'memory', 'USAGE') THEN
        RAISE EXCEPTION 'gateway runtime schema privileges are unsafe';
    END IF;

    FOR relation IN
        SELECT namespace.nspname AS schema_name, class.relname AS relation_name
        FROM pg_class AS class
        JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname IN (
            'gateway_runtime', 'myuna_admin', 'myuna_identity', 'memory'
        )
          AND class.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        IF has_table_privilege(
            'myuna_gateway_app',
            format('%I.%I', relation.schema_name, relation.relation_name),
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        ) THEN
            RAISE EXCEPTION 'gateway role can directly access %.%',
                relation.schema_name, relation.relation_name;
        END IF;
    END LOOP;

    SELECT count(*) INTO approved_function_count
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'gateway_runtime'
      AND procedure.proname IN (
          'claim_inbound_event',
          'record_inbound_outcome',
          'enqueue_outbound',
          'claim_outbound',
          'mark_outbound_delivered',
          'mark_outbound_retry'
      )
      AND procedure.prosecdef
      AND has_function_privilege('myuna_gateway_app', procedure.oid, 'EXECUTE');

    IF approved_function_count <> 6 THEN
        RAISE EXCEPTION 'gateway role lacks the exact approved function surface';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'gateway_runtime'
          AND column_name IN (
              'actor_account_id',
              'raw_account_id',
              'message_text',
              'raw_payload',
              'signature',
              'nonce'
          )
    ) THEN
        RAISE EXCEPTION 'gateway operational schema contains a forbidden plaintext column';
    END IF;

    IF EXISTS (SELECT 1 FROM myuna_identity.account_binding)
       OR EXISTS (
           SELECT 1 FROM myuna_identity.principal
           WHERE principal_kind <> 'test' OR principal_id <> 'principal-synthetic'
       ) OR EXISTS (
           SELECT 1 FROM memory.memory_namespace
           WHERE namespace_kind <> 'test' OR namespace_id <> 'ns-synthetic-dev'
       ) THEN
        RAISE EXCEPTION 'real identity data was written by the gateway foundation';
    END IF;
END
$verify$;

