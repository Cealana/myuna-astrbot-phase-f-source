# Memory Stage 0 Contract

状态：Implemented for development and synthetic evaluation  
契约版本：`memory-v0.1`  
Schema 版本：`1`  
策略版本：`memory-policy-v0.1`

## 1. 目的与边界

Stage 0 用来验证 Myuna 记忆系统的语义边界、升级接口和测试方法。它不建立正式数据库，不处理真实对话，不下载 embedding，也不向 Myuna 运行时开放写入能力。

当前内存存储会在进程结束时消失，只允许用于单元测试和合成评测。后续 PostgreSQL 实现必须通过同一个 `MemoryStore` 契约接入，不能让上层逻辑依赖 SQL、pgvector 或某一 embedding 模型。

## 2. 分域原则

```text
Myuna Definition        -> 她是谁，以及如何表达
Personal Memory         -> 她与用户共同经历、确认与保留的内容
Operational Records     -> 服务、Minecraft、系统、审计和备份记录
Model Context           -> 一次请求中临时提供给模型的上下文
```

`operational_record` 永远不能经默认策略进入 Personal Memory。Myuna 可以在获得权限后查询运行记录，但表达必须是“我查看了记录”，不能伪装成“我记得”。

## 3. 记录语义

每条可保留记录至少包含：

- 稳定 `memory_id`、`schema_version`、`policy_version`。
- 来源 ID、来源类型、可追踪引用和捕获时间。
- `occurred_at` 与 `recorded_at` 两个带时区时间。
- IANA 时区名称、时间精度和自然语言时间短语。
- 原始语义文本，以及可选的逐字引用 `exact_quote`。
- 类型、状态、确认等级、作用域、重要度、敏感级别和标签。
- 临时状态的到期时间。
- 修正链 `supersedes_id`，不原地覆盖旧记录。
- 策略原因码和不主动提起标志。

重要的“第一次”、特别的话和时间锚点使用 `anchor`，不会被周度压缩覆盖；未来的压缩结果只能作为派生层，原始细节仍保留在归档层。

## 4. 默认策略矩阵

| 输入情况 | Stage 0 行为 |
|---|---|
| 用户明确确认 | `confirmed` |
| 普通观察或候选 | `provisional` |
| 模型自行推断 | 只能 `provisional` |
| 当前想法/状态 | 有作用域的 `provisional`，默认 24 小时后复核 |
| “忘了吧”等口语 | 保留但 `suppressed`，不主动提起 |
| “不要添加到记忆”等明确指令 | `exclude`，不进入长期存储 |
| “这是测试 / 不需要记忆” | `session_only` |
| 服务器运行记录 | 转交外部记录域，不进入个人记忆 |

“忘了吧”不是删除命令。未来真正删除需要独立、明确且可审计的 tombstone/purge 流程；物理清除与可撤销隐藏也必须分开授权。

## 5. 检索语义

Stage 0 检索顺序：

1. 过滤错误数据域、失效状态、过期临时状态和不匹配作用域。
2. 应用修正链，旧版本仍在存储中，但不会作为当前事实返回。
3. 对中文做 Unicode 规范化、子串匹配和字符二元组重叠评分。
4. 叠加确认状态、当前作用域、锚点、逐字引用和重要度权重。
5. 返回命中项以及策略版本、过滤计数、查询特征和逐项原因。

已确认的长期基线通常高于未确认候选；但在同一有效作用域内，`current_state` 可以暂时高于基线。临时状态到期后不再覆盖基线，之后由复核流程决定续期、确认或归档。

Stage 0 的字符二元组只是可重复的基线，不是最终中文检索方案。Stage 1/2 会在同一评测集上比较 PostgreSQL 文本检索、`pg_trgm`、本地 embedding 和可选云端 embedding。

## 6. 扩展接口

以下协议已经独立定义：

- `MemorySourceAdapter`
- `CandidateExtractor`
- `MemoryPolicy`
- `MemoryStore`
- `ArchiveStore`
- `Consolidator`
- `Retriever`
- `Reranker`
- `EmbeddingProvider`
- `MemoryRenderer`
- `PrivacyController`
- `MigrationRunner`
- `EvaluationHarness`

替换实现时应添加新模块并通过依赖注入注册，不能修改 Myuna Core 的人格逻辑来适配某个数据库或模型供应商。

## 7. 合成评测

`fixtures/memory/synthetic_zh_v1.jsonl` 中所有人、地点、事件和日期均为虚构测试数据。数据集覆盖：

- 已确认基线与临时状态覆盖。
- 第一次、特别引用和详细时间。
- 口语“忘了吧”与明确排除的差异。
- 测试会话不入库。
- 运维记录与个人记忆隔离。
- 修正链与旧事实隐藏。
- 模型推断不得自行升级为确认事实。

真实对话样本只有在用户另行选择范围并批准后，才允许进入 Stage 3 的隔离评测。

## 8. 下一阶段门槛

进入 Stage 1 前需要再次确认：

1. PostgreSQL 数据目录、备份、恢复和权限设计。
2. 数据库 schema、索引与迁移回滚脚本。
3. 个人记忆、外部运行记录和审计表的物理隔离。
4. 加密、敏感字段和删除/tombstone 规则。
5. 只在开发环境导入合成数据的防误用保护。

Stage 1 可以安装 PostgreSQL + pgvector + pg_trgm，但仍不得自动导入真实聊天记录。
