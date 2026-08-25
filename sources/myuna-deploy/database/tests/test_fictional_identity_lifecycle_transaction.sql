\set ON_ERROR_STOP on

BEGIN;
\ir ../migrations/0003_dev_runtime_fail_closed.sql
\ir verify_dev_runtime_fail_closed.sql
\ir rehearse_fictional_identity_lifecycle_body.sql
ROLLBACK;

DO $rollback_verify$
BEGIN
    IF EXISTS (
        SELECT 1 FROM myuna_admin.schema_migration
        WHERE migration_version = '0003_dev_runtime_fail_closed'
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'myuna_identity'
          AND table_name = 'account_binding'
          AND column_name = 'namespace_id'
    ) OR to_regclass('memory.synthetic_dev_current_assertion') IS NOT NULL
      OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'myuna_rehearsal_%')
      OR EXISTS (
          SELECT 1 FROM myuna_identity.principal
          WHERE principal_id LIKE 'principal-rehearsal-%'
      ) THEN
        RAISE EXCEPTION 'fictional migration rehearsal did not roll back cleanly';
    END IF;
END
$rollback_verify$;
