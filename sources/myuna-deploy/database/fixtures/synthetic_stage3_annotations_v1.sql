\set ON_ERROR_STOP on

DO $guard$
BEGIN
    IF current_database() <> 'myuna_dev' THEN
        RAISE EXCEPTION 'Stage 3 annotations may run only in myuna_dev';
    END IF;
    IF current_setting('myuna.environment', true) IS DISTINCT FROM 'dev' THEN
        RAISE EXCEPTION 'myuna.environment must be dev';
    END IF;
    IF current_setting('myuna.synthetic_only', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'myuna.synthetic_only must be on';
    END IF;
    IF (
        SELECT count(*) FROM memory.memory_assertion
        WHERE assertion_id IN (
            's2-first-comet', 's2-paper-boat-quote', 's2-map-quote',
            's2-first-music-box', 's2-festival-time', 's2-seaglass'
        )
    ) <> 6 THEN
        RAISE EXCEPTION 'required Stage 2 synthetic assertions are missing';
    END IF;
END
$guard$;

SET ROLE myuna_dev_owner;

INSERT INTO memory.memory_anchor (
    anchor_id, assertion_id, anchor_kind, title, preservation_note
)
VALUES
(
    'stage3-anchor-first-comet', 's2-first-comet', 'first',
    '第一次画下蓝色彗星', '保留首次事件、地点和分钟级时间'
),
(
    'stage3-anchor-paper-boat-quote', 's2-paper-boat-quote', 'exact_quote',
    '纸船旁的回家原话', '检索原话时优先，不由派生摘要覆盖'
),
(
    'stage3-anchor-map-quote', 's2-map-quote', 'exact_quote',
    '地图背面的方向原话', '检索原话时优先，不由派生摘要覆盖'
),
(
    'stage3-anchor-first-music-box', 's2-first-music-box', 'first',
    '第一次独自修好音乐盒', '区分第一次独立维修和后续维修'
),
(
    'stage3-anchor-festival-time', 's2-festival-time', 'first',
    '第一次夏灯节共同合影', '保留首次事件和分钟级时间'
),
(
    'stage3-anchor-first-seaglass', 's2-seaglass', 'first',
    '第一次捡到海玻璃', '保留颜色、形状和首次语义'
)
ON CONFLICT (anchor_id) DO NOTHING;

INSERT INTO myuna_admin.dataset_load (
    dataset_id, dataset_sha256, synthetic_only, assertion_count, notes
)
VALUES (
    'synthetic-zh-stage3-annotations-v1',
    :'dataset_sha256',
    true,
    0,
    jsonb_build_object(
        'stage', 'memory-stage-3',
        'annotation_kind', 'memory_anchor',
        'annotated_assertions', 6,
        'new_assertions', 0
    )
);

RESET ROLE;

