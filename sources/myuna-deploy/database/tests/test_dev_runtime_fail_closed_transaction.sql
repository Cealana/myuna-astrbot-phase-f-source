\set ON_ERROR_STOP on

BEGIN;
\ir ../migrations/0003_dev_runtime_fail_closed.sql
\ir verify_dev_runtime_fail_closed.sql
ROLLBACK;

DO $rollback_verify$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0003_dev_runtime_fail_closed'
    ) OR EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'myuna_identity'
          AND table_name = 'account_binding'
          AND column_name = 'namespace_id'
    ) OR to_regclass('memory.synthetic_dev_current_assertion') IS NOT NULL THEN
        RAISE EXCEPTION 'transactional rehearsal did not roll back cleanly';
    END IF;
END
$rollback_verify$;
