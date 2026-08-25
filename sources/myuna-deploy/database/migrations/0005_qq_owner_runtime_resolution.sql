\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'QQ owner runtime migration may run only in myuna_dev';
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
          AND binding.metadata ->> 'verification' = 'qq-private-challenge'
          AND binding.metadata ->> 'finalization_approval_digest' =
              '38929e450d7cba0c083fec93b1e6c30570c672530609b1cb61c335730310f947'
          AND binding.metadata ->> 'verification_evidence_sha256' =
              '559be2a23b11c5c12064bda7d7bd0e2f0a02d268c91e7ffe1c12477c34657a29'
    ) THEN
        RAISE EXCEPTION 'verified owner binding prerequisite is missing';
    END IF;
END
$guard$;

SET ROLE myuna_dev_owner;

CREATE FUNCTION gateway_runtime.resolve_verified_binding(
    p_channel_kind text,
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
    WHERE binding.channel_kind = p_channel_kind
      AND binding.account_fingerprint = p_account_fingerprint
      AND binding.binding_status = 'verified'
      AND binding.verified_at IS NOT NULL
      AND principal.principal_kind = 'owner'
      AND principal.authority_level = 'owner'
      AND principal.principal_status = 'active'
      AND namespace.namespace_status = 'active'
      AND binding.binding_id = 'binding-astrbot-qq-owner-cealana'
      AND binding.principal_id = 'principal-owner-cealana'
      AND binding.namespace_id = 'ns-owner-cealana-private';
$function$;

COMMENT ON FUNCTION gateway_runtime.resolve_verified_binding(text, text) IS
    'Exact verified owner lookup by HMAC fingerprint; never accepts display names, prompts, or raw message text.';

REVOKE ALL ON FUNCTION gateway_runtime.resolve_verified_binding(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gateway_runtime.resolve_verified_binding(text, text)
TO myuna_gateway_app;

INSERT INTO myuna_admin.schema_migration (
    migration_version,
    migration_sha256,
    notes
)
VALUES (
    :'migration_version',
    :'migration_sha256',
    jsonb_build_object(
        'stage', 'qq-owner-private-runtime-v1',
        'raw_account_id_stored', false,
        'group_chat', false,
        'memory_read', false,
        'memory_write', false,
        'tools', false,
        'external_listener', false,
        'owner_binding', 'binding-astrbot-qq-owner-cealana'
    )
);

RESET ROLE;
