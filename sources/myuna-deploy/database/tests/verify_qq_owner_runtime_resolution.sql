\set ON_ERROR_STOP on

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM pg_proc AS procedure
JOIN pg_namespace AS namespace
  ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'gateway_runtime'
  AND procedure.proname = 'resolve_verified_binding'
  AND pg_get_function_identity_arguments(procedure.oid) = 'p_channel_kind text, p_account_fingerprint text'
  AND procedure.prosecdef;

SELECT 1 / CASE WHEN has_function_privilege(
    'myuna_gateway_app',
    'gateway_runtime.resolve_verified_binding(text,text)',
    'EXECUTE'
) THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN NOT has_table_privilege(
    'myuna_gateway_app',
    'myuna_identity.account_binding',
    'SELECT'
) THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding AS binding
CROSS JOIN LATERAL gateway_runtime.resolve_verified_binding(
    binding.channel_kind,
    binding.account_fingerprint
) AS resolved
WHERE binding.binding_id = 'binding-astrbot-qq-owner-cealana'
  AND resolved.binding_id = binding.binding_id
  AND resolved.principal_id = binding.principal_id
  AND resolved.namespace_id = binding.namespace_id;
