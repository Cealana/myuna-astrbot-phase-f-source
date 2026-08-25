\set ON_ERROR_STOP on

SELECT 1 / CASE WHEN count(*) = 1 THEN 1 ELSE 0 END
FROM myuna_admin.schema_migration
WHERE migration_version = '0006_telegram_owner_channel_foundation';

SELECT 1 / CASE WHEN to_regrole('myuna_telegram_gateway_app') IS NOT NULL
    THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN
    to_regprocedure(
        'gateway_runtime.claim_telegram_inbound_event(text,text,text,text,timestamp with time zone,timestamp with time zone)'
    ) IS NOT NULL
    AND to_regprocedure(
        'gateway_runtime.record_telegram_inbound_outcome(text,text,text,text)'
    ) IS NOT NULL
    AND to_regprocedure(
        'gateway_runtime.resolve_verified_telegram_owner_binding(text)'
    ) IS NOT NULL
    THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN
    has_function_privilege(
        'myuna_telegram_gateway_app',
        'gateway_runtime.claim_telegram_inbound_event(text,text,text,text,timestamptz,timestamptz)',
        'EXECUTE'
    )
    AND has_function_privilege(
        'myuna_telegram_gateway_app',
        'gateway_runtime.record_telegram_inbound_outcome(text,text,text,text)',
        'EXECUTE'
    )
    AND has_function_privilege(
        'myuna_telegram_gateway_app',
        'gateway_runtime.resolve_verified_telegram_owner_binding(text)',
        'EXECUTE'
    )
    AND NOT has_table_privilege(
        'myuna_telegram_gateway_app',
        'gateway_runtime.inbound_event',
        'SELECT,INSERT,UPDATE,DELETE'
    )
    AND NOT has_table_privilege(
        'myuna_telegram_gateway_app',
        'myuna_identity.account_binding',
        'SELECT,INSERT,UPDATE,DELETE'
    )
    THEN 1 ELSE 0 END;

SELECT 1 / CASE WHEN count(*) = 0 THEN 1 ELSE 0 END
FROM myuna_identity.account_binding
WHERE channel_kind = 'astrbot_telegram';
