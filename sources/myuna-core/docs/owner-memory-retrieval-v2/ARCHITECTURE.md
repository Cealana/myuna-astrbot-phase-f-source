# Owner Memory Retrieval v2 架构

## 调用链

```text
Myuna Core
  -> v2 Protocol request (query only; no recent/deep decision)
  -> Query Planner
  -> Boundary Filter
  -> Field Scorer
  -> Diversity and Selection Policy
  -> v2 Protocol response
  -> Core Adapter validation
  -> read-only Prompt context
```

## 单一职责

### Query Planner

只回答：这是当前上下文、历史回忆、稳定政策还是原话检索？应使用近期还是全时段？

它不读取记忆记录、不计算候选分数、不接触数据库，也不生成自然语言回答。

### Boundary Filter

只回答：这条记录是否允许进入候选集合？固定要求为：

- `ns-owner-cealana-private`；
- `sensitivity=normal`；
- `confirmation_level=user_confirmed`；
- 状态为 `confirmed` 或 `provisional`；
- `recent` 时位于 3 天窗口内。

### Field Scorer

只回答：允许参与的记录与查询有多少证据重合？

- 优先使用明确的 tags/subtype；
- 旧记录没有可识别标签时才允许从正文推断概念；
- 长问句使用概念覆盖与双向字段相似度，不再只计算整句覆盖；
- 单个宽泛类型概念不能独立触发注入。

### Selection Policy

只回答：哪些已评分候选最终进入上下文？

- 近期最多 1 条；
- 深度最多 3 条；
- 次选项必须与查询的具体主题有重合；
- 近重复候选被过滤；
- 未达到证据门槛时返回空，不用高重要度弥补无关内容。

### Protocol

只负责机器合同、长度限制和内容安全错误。v2 请求不接受 Core 指定的 `mode`，
防止 Core 与 Worker 产生两套分类结果。

### Core Adapter

只验证返回数据、确保记录仍为 normal/user-confirmed，并把正文投影为不含内部 ID 的
只读 Prompt 上下文。它不重新排名，也不自行放宽结果。

## 为什么目前不启用广泛 fallback

v2 的引擎保留一次受限 fallback 的结构，但候选策略没有从“出现长期记忆等宽泛词语”
自动授权 fallback。明确回忆与稳定政策问题会直接规划为 `deep`；普通消息保持
`recent`。这样运维问题如“长期记忆数据库端口是多少”不会扫描 Owner 历史。

未来如需启用 fallback，应先增加独立 Golden，并为授权信号建立确定性合同。

## 与 v1 的兼容边界

- 数据库安全视图和只读 DB 角色可以复用。
- v1 Socket 请求中的 `mode` 字段不能继续复用。
- v2 应使用平行 Socket 和独立策略版本部署，不覆盖在线 v1。
- Core 必须一次性切换到 v2 Adapter；不能同时调用 v1/v2 并混合候选正文。
- 回滚时只恢复 Core 的 Socket/策略绑定，不修改记忆数据。
