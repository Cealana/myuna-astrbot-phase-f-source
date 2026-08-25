\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'Telegram owner channel migration may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM myuna_identity.principal AS principal
        JOIN memory.memory_namespace AS namespace
          ON namespace.owner_principal_id = principal.principal_id
        JOIN myuna_identity.account_binding AS binding
          ON binding.principal_id = principal.principal_id
         AND binding.namespace_id = namespace.namespace_id
        WHERE principal.principal_id = 'principal-owner-cealana'
          AND principal.principal_kind = 'owner'
          AND principal.authority_level = 'owner'
          AND principal.principal_status = 'active'
          AND namespace.namespace_id = 'ns-owner-cealana-private'
          AND namespace.namespace_status = 'active'
          AND binding.binding_id = 'binding-astrbot-qq-owner-cealana'
          AND binding.channel_kind = 'astrbot_qq'
          AND binding.binding_status = 'verified'
          AND binding.verified_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'active canonical Owner identity prerequisite is missing';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM myuna_identity.account_binding
        WHERE binding_id = 'binding-astrbot-telegram-owner-cealana'
           OR channel_kind = 'astrbot_telegram'
    ) THEN
        RAISE EXCEPTION 'Telegram binding data already exists; refusing foundation migration';
    END IF;
END
$guard$;

SELECT 'CREATE ROLE myuna_telegram_gateway_app LOGIN NOINHERIT NOSUPERUSER '
       'NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'myuna_telegram_gateway_app'
)
\gexec

ALTER ROLE myuna_telegram_gateway_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3;
REVOKE ALL ON DATABASE myuna_dev FROM myuna_telegram_gateway_app;
GRANT CONNECT ON DATABASE myuna_dev TO myuna_telegram_gateway_app;

SET ROLE myuna_dev_owner;

ALTER TABLE myuna_identity.account_binding
    DROP CONSTRAINT account_binding_channel_kind_check;
ALTER TABLE myuna_identity.account_binding
    ADD CONSTRAINT account_binding_channel_kind_check CHECK (
        channel_kind IN (
            'local',
            'astrbot_qq',
            'astrbot_telegram',
            'web',
            'api'
        )
    ) NOT VALID;
ALTER TABLE myuna_identity.account_binding
    VALIDATE CONSTRAINT account_binding_channel_kind_check;

ALTER TABLE gateway_runtime.inbound_event
    DROP CONSTRAINT inbound_event_channel_kind_check;
ALTER TABLE gateway_runtime.inbound_event
    ADD CONSTRAINT inbound_event_channel_kind_check CHECK (
        channel_kind IN ('astrbot_qq', 'astrbot_telegram')
    ) NOT VALID;
ALTER TABLE gateway_runtime.inbound_event
    VALIDATE CONSTRAINT inbound_event_channel_kind_check;

CREATE FUNCTION gateway_runtime.claim_telegram_inbound_event(
    p_channel_instance text,
    p_event_id text,
    p_nonce_fingerprint text,
    p_payload_sha256 text,
    p_occurred_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
    SELECT gateway_runtime.claim_inbound_event(
        'astrbot_telegram',
        p_channel_instance,
        p_event_id,
        p_nonce_fingerprint,
        p_payload_sha256,
        p_occurred_at,
        p_expires_at
    );
$function$;

CREATE FUNCTION gateway_runtime.record_telegram_inbound_outcome(
    p_channel_instance text,
    p_event_id text,
    p_outcome text,
    p_outcome_code text
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
    SELECT gateway_runtime.record_inbound_outcome(
        'astrbot_telegram',
        p_channel_instance,
        p_event_id,
        p_outcome,
        p_outcome_code
    );
$function$;

CREATE FUNCTION gateway_runtime.resolve_verified_telegram_owner_binding(
    p_account_fingerprint text
)
RETURNS TABLE (
    binding_id text,
    principal_id text,
    namespace_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime, myuna_identity, memory
AS $function$
    SELECT
        binding.binding_id,
        binding.principal_id,
        binding.namespace_id
    FROM myuna_identity.account_binding AS binding
    JOIN myuna_identity.principal AS principal
      ON principal.principal_id = binding.principal_id
    JOIN memory.memory_namespace AS namespace
      ON namespace.namespace_id = binding.namespace_id
     AND namespace.owner_principal_id = binding.principal_id
    WHERE binding.channel_kind = 'astrbot_telegram'
      AND binding.account_fingerprint = p_account_fingerprint
      AND binding.binding_status = 'verified'
      AND binding.verified_at IS NOT NULL
      AND principal.principal_kind = 'owner'
      AND principal.authority_level = 'owner'
      AND principal.principal_status = 'active'
      AND namespace.namespace_status = 'active'
      AND binding.binding_id = 'binding-astrbot-telegram-owner-cealana'
      AND binding.principal_id = 'principal-owner-cealana'
      AND binding.namespace_id = 'ns-owner-cealana-private';
$function$;

COMMENT ON FUNCTION gateway_runtime.claim_telegram_inbound_event(
    text, text, text, text, timestamptz, timestamptz
) IS
    'Telegram-only durable event claim; channel kind is not caller-controlled.';
COMMENT ON FUNCTION gateway_runtime.record_telegram_inbound_outcome(
    text, text, text, text
) IS
    'Telegram-only event outcome update; channel kind is not caller-controlled.';
COMMENT ON FUNCTION gateway_runtime.resolve_verified_telegram_owner_binding(text) IS
    'Exact Telegram Owner binding lookup by HMAC fingerprint; raw IDs and prompts are never accepted.';

REVOKE ALL ON SCHEMA gateway_runtime FROM myuna_telegram_gateway_app;
GRANT USAGE ON SCHEMA gateway_runtime TO myuna_telegram_gateway_app;
REVOKE ALL ON ALL TABLES IN SCHEMA gateway_runtime
FROM myuna_telegram_gateway_app;
REVOKE ALL ON FUNCTION gateway_runtime.claim_telegram_inbound_event(
    text, text, text, text, timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION gateway_runtime.record_telegram_inbound_outcome(
    text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION gateway_runtime.resolve_verified_telegram_owner_binding(text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gateway_runtime.claim_telegram_inbound_event(
    text, text, text, text, timestamptz, timestamptz
) TO myuna_telegram_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.record_telegram_inbound_outcome(
    text, text, text, text
) TO myuna_telegram_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.resolve_verified_telegram_owner_binding(text)
TO myuna_telegram_gateway_app;

INSERT INTO myuna_admin.schema_migration (
    migration_version,
    migration_sha256,
    notes
)
VALUES (
    :'migration_version',
    :'migration_sha256',
    jsonb_build_object(
        'stage', 'telegram-owner-channel-foundation-v1',
        'identity_rows_changed', false,
        'raw_account_id_stored', false,
        'group_chat', false,
        'memory_read', false,
        'memory_write', false,
        'tools', false,
        'telegram_runtime_role', 'myuna_telegram_gateway_app'
    )
);

RESET ROLE;
