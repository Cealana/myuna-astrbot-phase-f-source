\set ON_ERROR_STOP on

BEGIN;
\ir ../migrations/0004_gateway_runtime_foundation.sql
\ir verify_gateway_runtime_foundation.sql
\ir rehearse_gateway_runtime_body.sql
ROLLBACK;

DO $rollback_verify$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'myuna_gateway_app'
    ) OR to_regnamespace('gateway_runtime') IS NOT NULL OR EXISTS (
        SELECT 1
        FROM myuna_admin.schema_migration
        WHERE migration_version = '0004_gateway_runtime_foundation'
    ) THEN
        RAISE EXCEPTION 'gateway migration rehearsal did not roll back cleanly';
    END IF;
END
$rollback_verify$;
