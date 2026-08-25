\set ON_ERROR_STOP on

BEGIN;
\ir rehearse_fictional_identity_lifecycle_body.sql
ROLLBACK;

DO $rollback_verify$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'myuna_rehearsal_%')
       OR EXISTS (
           SELECT 1 FROM myuna_identity.principal
           WHERE principal_id LIKE 'principal-rehearsal-%'
       ) OR EXISTS (
           SELECT 1 FROM memory.memory_namespace
           WHERE namespace_id LIKE 'ns-rehearsal-%'
       ) OR to_regclass('memory.rehearsal_owner_current_assertion') IS NOT NULL
       OR to_regclass('memory.rehearsal_friend_current_assertion') IS NOT NULL THEN
        RAISE EXCEPTION 'fictional identity/lifecycle rows survived rollback';
    END IF;
END
$rollback_verify$;
