\set ON_ERROR_STOP on
\set migration_version '0005_qq_owner_runtime_resolution'
\set migration_sha256 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

BEGIN;
\ir ../migrations/0005_qq_owner_runtime_resolution.sql
\ir verify_qq_owner_runtime_resolution.sql
ROLLBACK;

SELECT 1 / CASE WHEN to_regprocedure(
    'gateway_runtime.resolve_verified_binding(text,text)'
) IS NULL THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN count(*) = 0 THEN 1 ELSE 0 END
FROM myuna_admin.schema_migration
WHERE migration_version = :'migration_version';
