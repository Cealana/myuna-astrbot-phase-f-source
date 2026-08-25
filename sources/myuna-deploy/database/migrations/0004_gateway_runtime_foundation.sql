\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'gateway runtime foundation may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'gateway foundation requires the synthetic-only dev database';
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
        RAISE EXCEPTION 'real identity data exists; refusing gateway foundation migration';
    END IF;
END
$guard$;

SELECT 'CREATE ROLE myuna_gateway_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
       'NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'myuna_gateway_app')
\gexec

ALTER ROLE myuna_gateway_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5;
REVOKE ALL ON DATABASE myuna_dev FROM myuna_gateway_app;
GRANT CONNECT ON DATABASE myuna_dev TO myuna_gateway_app;

SET ROLE myuna_dev_owner;

CREATE SCHEMA gateway_runtime AUTHORIZATION myuna_dev_owner;

CREATE TABLE gateway_runtime.inbound_event (
    channel_kind text NOT NULL CHECK (channel_kind = 'astrbot_qq'),
    channel_instance text NOT NULL CHECK (
        channel_instance ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    ),
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    nonce_fingerprint text NOT NULL CHECK (nonce_fingerprint ~ '^[0-9a-f]{64}$'),
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    processing_state text NOT NULL DEFAULT 'received' CHECK (
        processing_state IN ('received', 'accepted', 'rejected', 'failed', 'completed')
    ),
    outcome_code text CHECK (
        outcome_code IS NULL OR outcome_code ~ '^[a-z][a-z0-9._-]{2,63}$'
    ),
    completed_at timestamptz,
    PRIMARY KEY (channel_kind, channel_instance, event_id),
    UNIQUE (channel_kind, channel_instance, nonce_fingerprint),
    CHECK (expires_at > received_at),
    CHECK ((processing_state = 'completed') = (completed_at IS NOT NULL))
);

COMMENT ON TABLE gateway_runtime.inbound_event IS
    'Operational idempotency only; never stores raw account IDs, nonce, signature, or message text.';

CREATE TABLE gateway_runtime.outbound_delivery (
    delivery_id text PRIMARY KEY CHECK (
        delivery_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    ),
    channel_kind text NOT NULL,
    channel_instance text NOT NULL,
    source_event_id text NOT NULL,
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
    destination_ciphertext bytea NOT NULL CHECK (
        octet_length(destination_ciphertext) BETWEEN 16 AND 4096
    ),
    payload_ciphertext bytea NOT NULL CHECK (
        octet_length(payload_ciphertext) BETWEEN 16 AND 262144
    ),
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    delivery_status text NOT NULL DEFAULT 'queued' CHECK (
        delivery_status IN ('queued', 'leased', 'retry', 'delivered', 'dead_letter')
    ),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_owner text CHECK (
        lease_owner IS NULL OR lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
    ),
    lease_until timestamptz,
    last_failure_code text CHECK (
        last_failure_code IS NULL OR last_failure_code ~ '^[a-z][a-z0-9._-]{2,63}$'
    ),
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (channel_kind, channel_instance, source_event_id)
        REFERENCES gateway_runtime.inbound_event(channel_kind, channel_instance, event_id),
    CHECK (
        (delivery_status = 'leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR (delivery_status <> 'leased' AND lease_owner IS NULL AND lease_until IS NULL)
    ),
    CHECK ((delivery_status = 'delivered') = (delivered_at IS NOT NULL))
);

COMMENT ON TABLE gateway_runtime.outbound_delivery IS
    'Encrypted operational outbox; destination and response payload must be encrypted by the adapter.';

CREATE INDEX gateway_outbox_available_idx
    ON gateway_runtime.outbound_delivery (delivery_status, available_at, created_at)
    WHERE delivery_status IN ('queued', 'retry');

CREATE FUNCTION gateway_runtime.claim_inbound_event(
    p_channel_kind text,
    p_channel_instance text,
    p_event_id text,
    p_nonce_fingerprint text,
    p_payload_sha256 text,
    p_occurred_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
DECLARE
    inserted_rows integer;
    v_now timestamptz := clock_timestamp();
BEGIN
    IF p_expires_at <= v_now
       OR p_expires_at > v_now + interval '10 minutes'
       OR p_occurred_at < v_now - interval '10 minutes'
       OR p_occurred_at > v_now + interval '2 minutes' THEN
        RAISE EXCEPTION 'gateway event clock window rejected';
    END IF;

    INSERT INTO gateway_runtime.inbound_event (
        channel_kind,
        channel_instance,
        event_id,
        nonce_fingerprint,
        payload_sha256,
        occurred_at,
        expires_at
    )
    VALUES (
        p_channel_kind,
        p_channel_instance,
        p_event_id,
        p_nonce_fingerprint,
        p_payload_sha256,
        p_occurred_at,
        p_expires_at
    )
    ON CONFLICT DO NOTHING;

    GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    RETURN inserted_rows = 1;
END
$function$;

CREATE FUNCTION gateway_runtime.record_inbound_outcome(
    p_channel_kind text,
    p_channel_instance text,
    p_event_id text,
    p_outcome text,
    p_outcome_code text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
DECLARE
    updated_rows integer;
BEGIN
    IF p_outcome NOT IN ('accepted', 'rejected', 'failed') THEN
        RAISE EXCEPTION 'unsupported inbound outcome';
    END IF;
    IF p_outcome_code !~ '^[a-z][a-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'invalid outcome code';
    END IF;

    UPDATE gateway_runtime.inbound_event AS inbound
    SET processing_state = p_outcome,
        outcome_code = p_outcome_code
    WHERE inbound.channel_kind = p_channel_kind
      AND inbound.channel_instance = p_channel_instance
      AND inbound.event_id = p_event_id
      AND inbound.processing_state = 'received';

    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    RETURN updated_rows = 1;
END
$function$;

CREATE FUNCTION gateway_runtime.enqueue_outbound(
    p_delivery_id text,
    p_channel_kind text,
    p_channel_instance text,
    p_source_event_id text,
    p_trace_id text,
    p_destination_ciphertext bytea,
    p_payload_ciphertext bytea,
    p_payload_sha256 text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
DECLARE
    inserted_rows integer;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM gateway_runtime.inbound_event AS inbound
        WHERE inbound.channel_kind = p_channel_kind
          AND inbound.channel_instance = p_channel_instance
          AND inbound.event_id = p_source_event_id
          AND inbound.processing_state = 'accepted'
    ) THEN
        RAISE EXCEPTION 'outbound source event is not accepted';
    END IF;

    INSERT INTO gateway_runtime.outbound_delivery (
        delivery_id,
        channel_kind,
        channel_instance,
        source_event_id,
        trace_id,
        destination_ciphertext,
        payload_ciphertext,
        payload_sha256
    )
    VALUES (
        p_delivery_id,
        p_channel_kind,
        p_channel_instance,
        p_source_event_id,
        p_trace_id,
        p_destination_ciphertext,
        p_payload_ciphertext,
        p_payload_sha256
    )
    ON CONFLICT (delivery_id) DO NOTHING;

    GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    RETURN inserted_rows = 1;
END
$function$;

CREATE FUNCTION gateway_runtime.claim_outbound(
    p_worker_id text,
    p_lease_seconds integer DEFAULT 60
)
RETURNS TABLE (
    delivery_id text,
    channel_kind text,
    channel_instance text,
    source_event_id text,
    trace_id text,
    destination_ciphertext bytea,
    payload_ciphertext bytea,
    payload_sha256 text,
    attempt_count integer,
    lease_until timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
BEGIN
    IF p_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN
        RAISE EXCEPTION 'invalid worker id';
    END IF;
    IF p_lease_seconds NOT BETWEEN 10 AND 300 THEN
        RAISE EXCEPTION 'lease duration is outside the accepted range';
    END IF;

    RETURN QUERY
    WITH candidate AS (
        SELECT queued.delivery_id AS selected_delivery_id
        FROM gateway_runtime.outbound_delivery AS queued
        WHERE queued.delivery_status IN ('queued', 'retry')
          AND queued.available_at <= clock_timestamp()
        ORDER BY queued.available_at, queued.created_at, queued.delivery_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    ),
    claimed AS (
        UPDATE gateway_runtime.outbound_delivery AS delivery
        SET delivery_status = 'leased',
            lease_owner = p_worker_id,
            lease_until = clock_timestamp() + make_interval(secs => p_lease_seconds),
            attempt_count = delivery.attempt_count + 1,
            updated_at = clock_timestamp()
        FROM candidate
        WHERE delivery.delivery_id = candidate.selected_delivery_id
        RETURNING delivery.*
    )
    SELECT
        claimed.delivery_id,
        claimed.channel_kind,
        claimed.channel_instance,
        claimed.source_event_id,
        claimed.trace_id,
        claimed.destination_ciphertext,
        claimed.payload_ciphertext,
        claimed.payload_sha256,
        claimed.attempt_count,
        claimed.lease_until
    FROM claimed;
END
$function$;

CREATE FUNCTION gateway_runtime.mark_outbound_delivered(
    p_delivery_id text,
    p_worker_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
DECLARE
    updated_rows integer;
BEGIN
    UPDATE gateway_runtime.outbound_delivery AS delivery
    SET delivery_status = 'delivered',
        lease_owner = NULL,
        lease_until = NULL,
        delivered_at = clock_timestamp(),
        last_failure_code = NULL,
        updated_at = clock_timestamp()
    WHERE delivery.delivery_id = p_delivery_id
      AND delivery.delivery_status = 'leased'
      AND delivery.lease_owner = p_worker_id;

    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    RETURN updated_rows = 1;
END
$function$;

CREATE FUNCTION gateway_runtime.mark_outbound_retry(
    p_delivery_id text,
    p_worker_id text,
    p_failure_code text,
    p_retry_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gateway_runtime
AS $function$
DECLARE
    resulting_status text;
BEGIN
    IF p_failure_code !~ '^[a-z][a-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'invalid failure code';
    END IF;
    IF p_retry_seconds NOT BETWEEN 1 AND 3600 THEN
        RAISE EXCEPTION 'retry delay is outside the accepted range';
    END IF;

    UPDATE gateway_runtime.outbound_delivery AS delivery
    SET delivery_status = CASE
            WHEN delivery.attempt_count >= 5 THEN 'dead_letter'
            ELSE 'retry'
        END,
        lease_owner = NULL,
        lease_until = NULL,
        last_failure_code = p_failure_code,
        available_at = clock_timestamp() + make_interval(secs => p_retry_seconds),
        updated_at = clock_timestamp()
    WHERE delivery.delivery_id = p_delivery_id
      AND delivery.delivery_status = 'leased'
      AND delivery.lease_owner = p_worker_id
    RETURNING delivery.delivery_status INTO resulting_status;

    RETURN resulting_status;
END
$function$;

REVOKE ALL ON SCHEMA gateway_runtime FROM PUBLIC, myuna_gateway_app, myuna_dev_app;
REVOKE ALL ON ALL TABLES IN SCHEMA gateway_runtime
    FROM PUBLIC, myuna_gateway_app, myuna_dev_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA gateway_runtime
    FROM PUBLIC, myuna_gateway_app, myuna_dev_app;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA gateway_runtime
    FROM PUBLIC, myuna_gateway_app, myuna_dev_app;

ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA gateway_runtime
    REVOKE ALL ON TABLES FROM PUBLIC, myuna_gateway_app, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA gateway_runtime
    REVOKE ALL ON SEQUENCES FROM PUBLIC, myuna_gateway_app, myuna_dev_app;
ALTER DEFAULT PRIVILEGES FOR ROLE myuna_dev_owner IN SCHEMA gateway_runtime
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, myuna_gateway_app, myuna_dev_app;

GRANT USAGE ON SCHEMA gateway_runtime TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.claim_inbound_event(
    text, text, text, text, text, timestamptz, timestamptz
) TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.record_inbound_outcome(
    text, text, text, text, text
) TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.enqueue_outbound(
    text, text, text, text, text, bytea, bytea, text
) TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.claim_outbound(text, integer)
    TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.mark_outbound_delivered(text, text)
    TO myuna_gateway_app;
GRANT EXECUTE ON FUNCTION gateway_runtime.mark_outbound_retry(text, text, text, integer)
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
        'stage', 'gateway-runtime-foundation-v1',
        'synthetic_only', true,
        'real_data_inserted', false,
        'runtime_role', 'myuna_gateway_app',
        'runtime_access', 'security-definer-functions-only',
        'plaintext_operational_content', false,
        'astrbot_connected', false
    )
);

RESET ROLE;

REVOKE ALL ON SCHEMA myuna_admin, myuna_identity, memory
    FROM myuna_gateway_app;
REVOKE ALL ON ALL TABLES IN SCHEMA myuna_admin, myuna_identity, memory
    FROM myuna_gateway_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA myuna_admin, myuna_identity, memory
    FROM myuna_gateway_app;
