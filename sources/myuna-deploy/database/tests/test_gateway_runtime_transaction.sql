\set ON_ERROR_STOP on

BEGIN;
\ir rehearse_gateway_runtime_body.sql
ROLLBACK;

DO $rollback_verify$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM gateway_runtime.inbound_event
        WHERE channel_instance = 'gateway-test-instance'
    ) OR EXISTS (
        SELECT 1
        FROM gateway_runtime.outbound_delivery
        WHERE delivery_id = 'delivery-gateway-test-0001'
    ) THEN
        RAISE EXCEPTION 'gateway transaction rehearsal did not roll back cleanly';
    END IF;
END
$rollback_verify$;
