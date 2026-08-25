\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'dev runtime hardening may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'hardening requires the synthetic-only dev database';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM myuna_identity.principal
        WHERE principal_kind <> 'test' OR principal_id <> 'principal-synthetic'
    ) OR EXISTS (
        SELECT 1
        FROM memory.memory_namespace
        WHERE namespace_kind <> 'test' OR namespace_id <> 'ns-synthetic-dev'
    ) OR EXISTS (
        SELECT 1 FROM myuna_identity.account_binding
    ) THEN
        RAISE EXCEPTION 'real identity data exists; refusing synthetic dev hardening';
    END IF;
END
$guard$;

SET ROLE myuna_dev_owner;

ALTER TABLE memory.memory_namespace
    ADD CONSTRAINT memory_namespace_id_owner_unique
        UNIQUE (namespace_id, owner_principal_id);

ALTER TABLE myuna_identity.account_binding
    ADD COLUMN namespace_id text;

ALTER TABLE myuna_identity.account_binding
    ADD CONSTRAINT account_binding_id_format_check
        CHECK (binding_id ~ '^binding-[a-z0-9][a-z0-9._-]{2,127}$'),
    ADD CONSTRAINT account_binding_namespace_owner_fk
        FOREIGN KEY (namespace_id, principal_id)
        REFERENCES memory.memory_namespace(namespace_id, owner_principal_id),
    ADD CONSTRAINT account_binding_verified_namespace_check
        CHECK (binding_status <> 'verified' OR namespace_id IS NOT NULL);

CREATE VIEW memory.synthetic_dev_current_assertion
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.current_assertion AS assertion
WHERE assertion.namespace_id = 'ns-synthetic-dev';

CREATE VIEW memory.synthetic_dev_proactive_candidate
WITH (security_barrier = true)
AS
SELECT assertion.*
FROM memory.proactive_candidate AS assertion
WHERE assertion.namespace_id = 'ns-synthetic-dev';

COMMENT ON VIEW memory.synthetic_dev_current_assertion IS
    'Fail-closed synthetic-only dev read surface; namespace is not request-controlled.';
COMMENT ON VIEW memory.synthetic_dev_proactive_candidate IS
    'Fail-closed synthetic-only dev proactive read surface.';

INSERT INTO myuna_admin.schema_migration (
    migration_version,
    migration_sha256,
    notes
)
VALUES (
    :'migration_version',
    :'migration_sha256',
    jsonb_build_object(
        'stage', 'identity-gate-v1',
        'synthetic_only', true,
        'real_data_inserted', false,
        'runtime_role', 'myuna_dev_app',
        'runtime_access', 'synthetic-read-only',
        'identity_text_trust', false
    )
);

RESET ROLE;

REVOKE ALL ON SCHEMA myuna_admin, myuna_identity FROM PUBLIC, myuna_dev_app;
REVOKE CREATE ON SCHEMA memory, extensions FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL TABLES IN SCHEMA myuna_admin FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL TABLES IN SCHEMA myuna_identity FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL TABLES IN SCHEMA memory FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA myuna_admin FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA myuna_identity FROM PUBLIC, myuna_dev_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA memory FROM PUBLIC, myuna_dev_app;

ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA myuna_admin
    REVOKE ALL ON TABLES FROM PUBLIC, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA myuna_identity
    REVOKE ALL ON TABLES FROM PUBLIC, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA memory
    REVOKE ALL ON TABLES FROM PUBLIC, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA myuna_admin
    REVOKE ALL ON SEQUENCES FROM PUBLIC, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA myuna_identity
    REVOKE ALL ON SEQUENCES FROM PUBLIC, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA memory
    REVOKE ALL ON SEQUENCES FROM PUBLIC, myuna_dev_app;

GRANT USAGE ON SCHEMA memory, extensions TO myuna_dev_app;
GRANT SELECT ON TABLE
    memory.synthetic_dev_current_assertion,
    memory.synthetic_dev_proactive_candidate
TO myuna_dev_app;
