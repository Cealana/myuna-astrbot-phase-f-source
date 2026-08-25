# Memory Stage 3 hybrid retrieval contract

状态：Synthetic implementation checkpoint  
策略版本：`structured-hybrid-v0.1`

## 固定顺序

```text
确定性硬过滤
→ semantic / lexical 候选召回
→ 结构化重排
→ 可解释 trace
```

向量相似度不能恢复已被过滤的记录，也不能改变确认状态、修正链、过期时间、作用域或主动抑制规则。

`suppressed` 记录在主动检索时由硬过滤排除；用户明确询问时可以进入候选，并且不再接受额外分数惩罚。普通 anchor 只有很小的先验，显著提升必须由匹配的 `first` 或 `exact_quote` 意图触发。

## 结构化重排意图

- `first`：只有 `memory_anchor.anchor_kind=first` 才获得第一次加权。
- `exact_quote`：只有 exact-quote anchor 或保留的逐字引用才获得原话加权。
- `time`：根据时间精度提升 minute/exact 或 part-of-day 记录。
- `current`：提升仍在有效作用域和 TTL 内的 current-state。
- `baseline`：提升用户确认的长期偏好基线。
- `correction`：提升具有 `supersedes_id` 的修正后记录；旧记录仍必须先被过滤。

所有加权都返回到 `RetrievalHit.score_components`；模型身份、查询意图、候选来源、过滤计数和策略权重写入 `RetrievalTrace`。

## 依赖边界

Core 只包含无第三方依赖的意图识别和重排规则。PostgreSQL、pgvector、Qwen、云端 embedding 或未来远程节点均通过适配器接入。正式服务启用前仍需独立完成权限、并发、缓存、审计和降级设计。
