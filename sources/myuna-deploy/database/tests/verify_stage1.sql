\set ON_ERROR_STOP on

DO $verify$
DECLARE
    assertion_total integer;
    source_total integer;
    event_total integer;
    embedding_total integer;
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'verification may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'database environment marker is not dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'database is not marked synthetic-only';
    END IF;

    SELECT count(*) INTO assertion_total FROM memory.memory_assertion;
    SELECT count(*) INTO source_total FROM memory.memory_source;
    SELECT count(*) INTO event_total FROM memory.memory_event;
    SELECT count(*) INTO embedding_total FROM memory.memory_embedding;

    IF assertion_total <> 10009 OR source_total <> 10009 OR event_total <> 10009 THEN
        RAISE EXCEPTION 'unexpected fact counts: assertions %, sources %, events %',
            assertion_total, source_total, event_total;
    END IF;
    IF embedding_total <> 100 THEN
        RAISE EXCEPTION 'unexpected synthetic embedding count: %', embedding_total;
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.memory_source WHERE source_kind = 'operational_record'
    ) THEN
        RAISE EXCEPTION 'operational record leaked into personal memory';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.current_assertion WHERE assertion_id = 'mem-old-bookshop'
    ) THEN
        RAISE EXCEPTION 'superseded assertion remains current';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM memory.current_assertion WHERE assertion_id = 'mem-corrected-bookshop'
    ) THEN
        RAISE EXCEPTION 'corrected assertion is not current';
    END IF;
    IF EXISTS (
        SELECT 1 FROM memory.proactive_candidate WHERE assertion_id = 'mem-rain-walk'
    ) THEN
        RAISE EXCEPTION 'suppressed assertion leaked into proactive candidates';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM memory.current_assertion WHERE assertion_id = 'mem-rain-walk'
    ) THEN
        RAISE EXCEPTION 'suppressed assertion is not available on demand';
    END IF;
    IF NOT has_table_privilege(
        'myuna_dev_app', 'memory.memory_assertion', 'SELECT,INSERT'
    ) THEN
        RAISE EXCEPTION 'application role lacks required select/insert privilege';
    END IF;
    IF has_table_privilege(
        'myuna_dev_app', 'memory.memory_assertion', 'UPDATE,DELETE,TRUNCATE'
    ) THEN
        RAISE EXCEPTION 'application role has mutation privileges beyond append-only contract';
    END IF;
    IF (SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = 'myuna_dev_app') THEN
        RAISE EXCEPTION 'dev application role unexpectedly has a password';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'vector'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'
    ) THEN
        RAISE EXCEPTION 'required extensions are missing';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_indexes
        WHERE schemaname = 'memory'
          AND indexdef ~* '(hnsw|ivfflat)'
    ) THEN
        RAISE EXCEPTION 'approximate vector index was created before scale justified it';
    END IF;
END
$verify$;

SELECT assertion_id, assertion_text
FROM memory.current_assertion
ORDER BY extensions.similarity(assertion_text, '旧书店银杏路') DESC
LIMIT 3;

SELECT assertion_id, embedding <-> '[0.1,0.1,0.1,0.1]'::extensions.vector AS l2_distance
FROM memory.memory_embedding
WHERE provider_id = 'synthetic'
  AND model_id = 'synthetic-test-4d'
ORDER BY embedding <-> '[0.1,0.1,0.1,0.1]'::extensions.vector
LIMIT 3;

SELECT
    (SELECT count(*) FROM memory.memory_source) AS sources,
    (SELECT count(*) FROM memory.memory_event) AS events,
    (SELECT count(*) FROM memory.memory_assertion) AS assertions,
    (SELECT count(*) FROM memory.memory_embedding) AS embeddings,
    (SELECT extversion FROM pg_extension WHERE extname = 'vector') AS vector_version,
    current_setting('server_version') AS postgresql_version;
