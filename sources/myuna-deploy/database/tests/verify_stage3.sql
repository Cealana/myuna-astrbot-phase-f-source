\set ON_ERROR_STOP on

DO $verify$
DECLARE
    qwen_vectors integer;
    stage3_anchors integer;
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'verification may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev'
       OR current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'database is not synthetic dev';
    END IF;

    SELECT count(*) INTO qwen_vectors
    FROM memory.memory_embedding
    WHERE provider_id = 'local-cpu'
      AND model_id = 'Qwen/Qwen3-Embedding-0.6B'
      AND model_revision = '97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3'
      AND dimensions = 1024;
    IF qwen_vectors <> 35 THEN
        RAISE EXCEPTION 'unexpected Qwen vector count: %', qwen_vectors;
    END IF;

    SELECT count(*) INTO stage3_anchors
    FROM memory.memory_anchor
    WHERE anchor_id LIKE 'stage3-anchor-%';
    IF stage3_anchors <> 6 THEN
        RAISE EXCEPTION 'unexpected Stage 3 anchor count: %', stage3_anchors;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM memory.memory_anchor
        WHERE assertion_id = 's2-first-music-box' AND anchor_kind = 'first'
    ) THEN
        RAISE EXCEPTION 'first music-box annotation is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM memory.memory_anchor
        WHERE assertion_id = 's2-paper-boat-quote' AND anchor_kind = 'exact_quote'
    ) THEN
        RAISE EXCEPTION 'paper-boat quote annotation is missing';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.current_assertion WHERE assertion_id = 's2-bookshop-old'
    ) OR NOT EXISTS (
        SELECT 1 FROM memory.current_assertion WHERE assertion_id = 's2-bookshop-corrected'
    ) THEN
        RAISE EXCEPTION 'correction-chain filtering failed';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.proactive_candidate WHERE assertion_id = 's2-rain-umbrella'
    ) THEN
        RAISE EXCEPTION 'suppressed memory leaked into proactive view';
    END IF;
    IF (
        SELECT count(*) FROM memory.memory_access_audit
        WHERE metadata @> '{"synthetic": true, "strategy_version": "structured-hybrid-v0.1"}'::jsonb
    ) <> 24 THEN
        RAISE EXCEPTION 'unexpected Stage 3 synthetic audit count';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_access_audit
        WHERE metadata ? 'query_text'
           OR query_fingerprint !~ '^[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'audit contains query plaintext or invalid fingerprint';
    END IF;
    IF has_table_privilege(
        'myuna_dev_app', 'memory.memory_assertion', 'UPDATE,DELETE,TRUNCATE'
    ) THEN
        RAISE EXCEPTION 'append-only role gained destructive privileges';
    END IF;
END
$verify$;

SELECT
    (SELECT count(*) FROM memory.memory_anchor WHERE anchor_id LIKE 'stage3-anchor-%')
        AS stage3_anchors,
    (SELECT count(*) FROM memory.memory_embedding WHERE provider_id = 'local-cpu')
        AS qwen_vectors,
    (SELECT count(*) FROM myuna_admin.dataset_load
     WHERE dataset_id = 'synthetic-zh-stage3-annotations-v1') AS dataset_receipts,
    (SELECT count(*) FROM memory.memory_access_audit
     WHERE metadata @> '{"synthetic": true, "strategy_version": "structured-hybrid-v0.1"}'::jsonb)
        AS stage3_audits;
