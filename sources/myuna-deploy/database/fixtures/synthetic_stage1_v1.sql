\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'synthetic fixture may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'myuna.synthetic_only must be on';
    END IF;
END
$guard$;

SET ROLE myuna_dev_owner;

CREATE TEMPORARY TABLE stage0_fixture (
    memory_id text PRIMARY KEY,
    source_kind text NOT NULL,
    memory_kind text NOT NULL,
    memory_status text NOT NULL,
    confirmation_level text NOT NULL,
    memory_text text NOT NULL,
    exact_quote text,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    timezone_name text NOT NULL,
    time_precision text NOT NULL,
    time_phrase text,
    scope text[] NOT NULL,
    importance numeric(4, 3) NOT NULL,
    tags text[] NOT NULL,
    do_not_surface_proactively boolean NOT NULL,
    expires_at timestamptz,
    supersedes_id text,
    policy_reasons text[] NOT NULL
) ON COMMIT DROP;

INSERT INTO stage0_fixture VALUES
(
    'mem-baseline-drink', 'conversation', 'preference', 'confirmed',
    'user_confirmed', '她通常喜欢茉莉花茶作为日常饮料。', NULL,
    '2042-05-01 19:20:00+08', '2042-05-01 19:21:00+08', 'Asia/Shanghai',
    'minute', '晚上七点二十分', ARRAY['global'], 0.700, ARRAY['baseline'],
    false, NULL, NULL, ARRAY['user_confirmed']
),
(
    'mem-current-drink', 'conversation', 'current_state', 'provisional',
    'observed', '她今天暂时更喜欢咖啡作为饮料。', NULL,
    '2042-05-09 09:10:00+08', '2042-05-09 09:11:00+08', 'Asia/Shanghai',
    'minute', '早上九点十分', ARRAY['day:2042-05-09'], 0.800, ARRAY['temporary'],
    false, '2042-05-10 09:11:00+08', NULL,
    ARRAY['temporary_current_state', 'reconfirm_after_ttl']
),
(
    'mem-first-comet', 'conversation', 'anchor', 'confirmed',
    'user_confirmed', '她第一次在纸上画下虚构的蓝色彗星。', NULL,
    '2042-04-03 21:36:00+08', '2042-04-03 21:38:00+08', 'Asia/Shanghai',
    'minute', '晚上九点三十六分', ARRAY['global'], 1.000, ARRAY['first'],
    false, NULL, NULL, ARRAY['user_confirmed']
),
(
    'mem-paper-boat-quote', 'conversation', 'anchor', 'confirmed',
    'user_confirmed', '她把一句特别的话写在虚构的纸船旁边。',
    '只要灯还亮着，就还能找到回来的路。',
    '2042-04-08 00:14:00+08', '2042-04-08 00:15:00+08', 'Asia/Shanghai',
    'minute', '半夜十二点十四分', ARRAY['global'], 1.000, ARRAY['exact-quote'],
    false, NULL, NULL, ARRAY['user_confirmed']
),
(
    'mem-rain-walk', 'conversation', 'episodic', 'suppressed',
    'observed', '虚构人物在雨天散步时把伞落在了蓝桥旁。', NULL,
    '2042-04-10 17:40:00+08', '2042-04-10 17:42:00+08', 'Asia/Shanghai',
    'minute', '傍晚五点四十分', ARRAY['global'], 0.500, ARRAY['suppressed'],
    true, NULL, NULL, ARRAY['colloquial_forget_is_not_deletion']
),
(
    'mem-lighthouse-evening', 'conversation', 'episodic', 'confirmed',
    'user_confirmed', '虚构人物在夜航灯塔下读完了一封信。', NULL,
    '2042-04-14 20:00:00+08', '2042-04-15 00:10:00+08', 'Asia/Shanghai',
    'part_of_day', '晚上', ARRAY['global'], 0.800, ARRAY['time-anchor'],
    false, NULL, NULL, ARRAY['user_confirmed']
),
(
    'mem-old-bookshop', 'conversation', 'semantic', 'confirmed',
    'user_confirmed', '虚构旧书店位于银杏路七号。', NULL,
    '2042-04-15 14:00:00+08', '2042-04-15 14:02:00+08', 'Asia/Shanghai',
    'minute', '下午两点', ARRAY['global'], 0.600, ARRAY['superseded'],
    false, NULL, NULL, ARRAY['user_confirmed']
),
(
    'mem-corrected-bookshop', 'conversation', 'semantic', 'confirmed',
    'user_confirmed', '更正：虚构旧书店位于银杏路九号。', NULL,
    '2042-04-15 14:08:00+08', '2042-04-15 14:09:00+08', 'Asia/Shanghai',
    'minute', '下午两点零八分', ARRAY['global'], 0.800, ARRAY['correction'],
    false, NULL, 'mem-old-bookshop', ARRAY['user_confirmed']
),
(
    'mem-inferred-music', 'model_inference', 'preference', 'provisional',
    'model_inferred', '模型推测虚构人物也许偏爱弦乐。', NULL,
    '2042-04-16 16:00:00+08', '2042-04-16 16:01:00+08', 'Asia/Shanghai',
    'minute', '下午四点', ARRAY['global'], 0.300, ARRAY['model-inference'],
    false, NULL, NULL, ARRAY['model_inference_cannot_self_confirm']
);

INSERT INTO memory.memory_source (
    source_id, source_kind, source_reference, captured_at, metadata
)
SELECT
    'source-' || memory_id,
    source_kind,
    'synthetic://stage0/' || memory_id,
    recorded_at,
    jsonb_build_object('synthetic', true, 'dataset', 'synthetic-zh-stage1-v1')
FROM stage0_fixture
ON CONFLICT (source_id) DO NOTHING;

INSERT INTO memory.memory_event (
    event_id, source_id, event_text, occurred_at, recorded_at, timezone_name,
    time_precision, time_phrase, exact_quote, metadata
)
SELECT
    'event-' || memory_id,
    'source-' || memory_id,
    memory_text,
    occurred_at,
    recorded_at,
    timezone_name,
    time_precision,
    time_phrase,
    exact_quote,
    jsonb_build_object('synthetic', true, 'dataset', 'synthetic-zh-stage1-v1')
FROM stage0_fixture
ON CONFLICT (event_id) DO NOTHING;

INSERT INTO memory.memory_assertion (
    assertion_id, source_id, event_id, memory_kind, memory_status,
    confirmation_level, assertion_text, scope, importance, tags,
    do_not_surface_proactively, expires_at, supersedes_id, schema_version,
    policy_version, policy_reasons, metadata
)
SELECT
    memory_id,
    'source-' || memory_id,
    'event-' || memory_id,
    memory_kind,
    memory_status,
    confirmation_level,
    memory_text,
    scope,
    importance,
    tags,
    do_not_surface_proactively,
    expires_at,
    supersedes_id,
    1,
    'memory-policy-v0.1',
    policy_reasons,
    jsonb_build_object('synthetic', true, 'dataset', 'synthetic-zh-stage1-v1')
FROM stage0_fixture
ORDER BY supersedes_id NULLS FIRST
ON CONFLICT (assertion_id) DO NOTHING;

INSERT INTO memory.memory_anchor (
    anchor_id, assertion_id, anchor_kind, title, preservation_note
)
VALUES
(
    'anchor-first-comet', 'mem-first-comet', 'first', '第一次画下蓝色彗星',
    '保留详细时间与原始事件文字'
),
(
    'anchor-paper-boat-quote', 'mem-paper-boat-quote', 'exact_quote', '纸船旁的特别原话',
    '逐字引用不可被派生摘要覆盖'
)
ON CONFLICT (anchor_id) DO NOTHING;

INSERT INTO memory.memory_revision (
    revision_id, previous_assertion_id, new_assertion_id, revision_kind, reason, actor
)
VALUES (
    'revision-bookshop-address', 'mem-old-bookshop', 'mem-corrected-bookshop',
    'correction', '合成数据中的地址更正案例', 'synthetic-fixture'
)
ON CONFLICT (revision_id) DO NOTHING;

INSERT INTO memory.memory_policy_action (
    action_id, assertion_id, action_kind, reversible, reason, actor, effective_at, receipt
)
VALUES (
    'action-suppress-rain-walk', 'mem-rain-walk', 'suppress', true,
    '口语忘了吧仅降低主动呈现，不执行删除', 'synthetic-fixture',
    '2042-04-10 17:42:00+08', '{"synthetic": true}'::jsonb
)
ON CONFLICT (action_id) DO NOTHING;

INSERT INTO memory.memory_source (
    source_id, source_kind, source_reference, captured_at, metadata
)
SELECT
    format('source-synthetic-bulk-%s', lpad(number::text, 6, '0')),
    'conversation',
    format('synthetic://bulk/%s', number),
    timestamptz '2042-01-01 08:00:00+08' + (number % 365) * interval '1 day',
    jsonb_build_object(
        'synthetic', true,
        'dataset', 'synthetic-zh-stage1-v1',
        'sequence', number
    )
FROM generate_series(1, 10000) AS series(number)
ON CONFLICT (source_id) DO NOTHING;

INSERT INTO memory.memory_event (
    event_id, source_id, event_text, occurred_at, recorded_at, timezone_name,
    time_precision, time_phrase, metadata
)
SELECT
    format('event-synthetic-bulk-%s', lpad(number::text, 6, '0')),
    format('source-synthetic-bulk-%s', lpad(number::text, 6, '0')),
    format(
        '纯合成记忆 %s：虚构人物在第 %s 号合成街区记录了一枚蓝色纸星。',
        number,
        number % 97
    ),
    timestamptz '2042-01-01 08:00:00+08' + (number % 365) * interval '1 day',
    timestamptz '2042-01-01 08:01:00+08' + (number % 365) * interval '1 day',
    'Asia/Shanghai',
    'minute',
    CASE number % 4
        WHEN 0 THEN '早上'
        WHEN 1 THEN '下午'
        WHEN 2 THEN '傍晚'
        ELSE '晚上'
    END,
    jsonb_build_object(
        'synthetic', true,
        'dataset', 'synthetic-zh-stage1-v1',
        'sequence', number
    )
FROM generate_series(1, 10000) AS series(number)
ON CONFLICT (event_id) DO NOTHING;

INSERT INTO memory.memory_assertion (
    assertion_id, source_id, event_id, memory_kind, memory_status,
    confirmation_level, assertion_text, scope, importance, tags,
    schema_version, policy_version, policy_reasons, metadata
)
SELECT
    format('synthetic-bulk-%s', lpad(number::text, 6, '0')),
    format('source-synthetic-bulk-%s', lpad(number::text, 6, '0')),
    format('event-synthetic-bulk-%s', lpad(number::text, 6, '0')),
    CASE number % 4
        WHEN 0 THEN 'episodic'
        WHEN 1 THEN 'semantic'
        WHEN 2 THEN 'preference'
        ELSE 'anchor'
    END,
    CASE WHEN number % 3 = 0 THEN 'confirmed' ELSE 'provisional' END,
    CASE WHEN number % 3 = 0 THEN 'user_confirmed' ELSE 'observed' END,
    format(
        '纯合成记忆 %s：虚构人物在第 %s 号合成街区记录了一枚蓝色纸星。',
        number,
        number % 97
    ),
    ARRAY[format('synthetic-topic:%s', number % 20)],
    (number % 101)::numeric / 100,
    ARRAY['synthetic', format('topic-%s', number % 20)],
    1,
    'memory-policy-v0.1',
    ARRAY['synthetic_bulk_fixture'],
    jsonb_build_object(
        'synthetic', true,
        'dataset', 'synthetic-zh-stage1-v1',
        'sequence', number
    )
FROM generate_series(1, 10000) AS series(number)
ON CONFLICT (assertion_id) DO NOTHING;

INSERT INTO memory.memory_embedding (
    assertion_id, provider_id, model_id, model_revision, dimensions,
    content_sha256, embedding
)
SELECT
    assertion_id,
    'synthetic',
    'synthetic-test-4d',
    'v1',
    4,
    repeat(md5(assertion_text), 2),
    format(
        '[%s,%s,%s,%s]',
        ((metadata ->> 'sequence')::integer % 10)::numeric / 10,
        ((metadata ->> 'sequence')::integer % 7)::numeric / 7,
        ((metadata ->> 'sequence')::integer % 5)::numeric / 5,
        ((metadata ->> 'sequence')::integer % 3)::numeric / 3
    )::extensions.vector
FROM memory.memory_assertion
WHERE metadata ->> 'dataset' = 'synthetic-zh-stage1-v1'
  AND (metadata ->> 'sequence')::integer BETWEEN 1 AND 100
ON CONFLICT (assertion_id, provider_id, model_id, model_revision) DO NOTHING;

INSERT INTO myuna_admin.dataset_load (
    dataset_id, dataset_sha256, synthetic_only, assertion_count, notes
)
SELECT
    'synthetic-zh-stage1-v1',
    :'dataset_sha256',
    true,
    count(*)::integer,
    jsonb_build_object(
        'canonical_cases', 9,
        'bulk_cases', 10000,
        'vectors', 100,
        'vector_semantics', 'none'
    )
FROM memory.memory_assertion
WHERE metadata ->> 'dataset' = 'synthetic-zh-stage1-v1'
ON CONFLICT (dataset_id) DO NOTHING;

RESET ROLE;
