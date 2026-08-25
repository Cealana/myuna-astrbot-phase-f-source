SET ROLE myuna_gateway_app;

SELECT 1 / gateway_runtime.claim_inbound_event(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0001',
    repeat('1', 64),
    repeat('2', 64),
    clock_timestamp(),
    clock_timestamp() + interval '5 minutes'
)::integer AS first_event_claimed;

SELECT 1 / (NOT gateway_runtime.claim_inbound_event(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0001',
    repeat('1', 64),
    repeat('2', 64),
    clock_timestamp(),
    clock_timestamp() + interval '5 minutes'
))::integer AS duplicate_event_rejected;

SELECT 1 / (NOT gateway_runtime.claim_inbound_event(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0002',
    repeat('1', 64),
    repeat('3', 64),
    clock_timestamp(),
    clock_timestamp() + interval '5 minutes'
))::integer AS reused_nonce_rejected;

SELECT 1 / gateway_runtime.record_inbound_outcome(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0001',
    'accepted',
    'synthetic.accepted'
)::integer AS inbound_accepted;

SELECT 1 / gateway_runtime.enqueue_outbound(
    'delivery-gateway-test-0001',
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0001',
    'trace-gateway-test-0001',
    decode(repeat('ab', 16), 'hex'),
    decode(repeat('cd', 16), 'hex'),
    repeat('4', 64)
)::integer AS outbound_enqueued;

SELECT 1 / (
    (SELECT count(*) FROM gateway_runtime.claim_outbound('worker-test-1', 60)) = 1
)::integer AS outbound_claimed;

SELECT 1 / (NOT gateway_runtime.mark_outbound_delivered(
    'delivery-gateway-test-0001',
    'worker-test-wrong'
))::integer AS wrong_worker_rejected;

SELECT 1 / gateway_runtime.mark_outbound_delivered(
    'delivery-gateway-test-0001',
    'worker-test-1'
)::integer AS outbound_delivered;

SELECT 1 / gateway_runtime.claim_inbound_event(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0003',
    repeat('5', 64),
    repeat('6', 64),
    clock_timestamp(),
    clock_timestamp() + interval '5 minutes'
)::integer AS retry_event_claimed;

SELECT 1 / gateway_runtime.record_inbound_outcome(
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0003',
    'accepted',
    'synthetic.accepted'
)::integer AS retry_event_accepted;

SELECT 1 / gateway_runtime.enqueue_outbound(
    'delivery-gateway-test-0002',
    'astrbot_qq',
    'gateway-test-instance',
    'event-gateway-test-0003',
    'trace-gateway-test-0002',
    decode(repeat('ef', 16), 'hex'),
    decode(repeat('12', 16), 'hex'),
    repeat('7', 64)
)::integer AS retry_outbound_enqueued;

SELECT 1 / (
    (SELECT count(*) FROM gateway_runtime.claim_outbound('worker-test-2', 60)) = 1
)::integer AS retry_outbound_claimed;

SELECT 1 / (
    gateway_runtime.mark_outbound_retry(
        'delivery-gateway-test-0002',
        'worker-test-2',
        'synthetic.retry',
        1
    ) = 'retry'
)::integer AS outbound_retry_scheduled;

RESET ROLE;
