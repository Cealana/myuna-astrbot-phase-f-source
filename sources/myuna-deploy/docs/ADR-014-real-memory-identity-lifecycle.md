# ADR-014：真实记忆身份、生命周期与不可召回归档

状态：Approved design / implementation gated  
日期：2026-07-16  
上游契约：`real-memory-contract-v1`

## 决策

1. 使用 gateway 验证的不可变 `principal_id`，不从消息正文推断身份。
2. 每个主体使用独立 `namespace_id`；owner namespace 优先实施，朋友 namespace 后续另开 gate。
3. 采用约 1 天离线整理、3 天轻量复核、7 天巩固、30 天低活跃的配置化生命周期。
4. 普通删除采用 90 天可撤销 tombstone。
5. 明确“不进入记忆”的内容保存在 Core 无权读取的 sealed archive；明确“不留任何副本”才完全不保存。
6. 原因、背景和条件使用独立 rationale 链，不把模型推测混入事实正文。
7. 日常聊天默认检索最近 1–3 天；显式回忆请求才允许深度档案检索。
8. 本地整理模型只生成 proposal，不能确认、删除、读取 sealed archive 或产生外部副作用。

## 身份安全

账号绑定保存 `channel + HMAC(server_secret, external_account_id)`，显示名称只作 UI 元数据。gateway 将已验证 principal/namespace 作为受保护请求字段注入；Core 拒绝消息正文覆盖这些字段。

第二个真实 principal 上线前必须完成：

- 数据库级 namespace 强制过滤；
- Core query namespace 必填；
- owner/friend 跨 namespace 负向测试；
- prompt injection、冒名和转发文本测试；
- owner-only 管理动作验证。

## Sealed archive

建议路径：

```text
/srv/myuna-private-archive/no-recall/<principal-id>/<yyyy>/<mm>/
```

最终实现必须使用独立 `myuna-archive` OS 账户、`0700` 目录、逐对象加密和只写入口。`myuna` Core 账户不在 archive 组中。数据库仅保存不含正文的 receipt、哈希、时间和删除状态。

在密钥保存与恢复方案批准前，不创建真实 archive 内容。

## 当前限制

- Windows 管理接口拒绝了本轮 BitLocker 状态查询，因此尚不能证明 C/D 盘已静态加密。
- 当前数据库仍带 `myuna.synthetic_only=on`，不得导入真实数据。
- AstrBot/QQ 尚未提供可验证账号绑定。
- 本地 4B/8B 生成模型尚未验收；现有 embedding worker 不能承担自动整理。

## 回滚

本 ADR 对 dev schema 的实现只能是 additive migration。回滚关闭 feature flag 和真实写入路径，不删除历史事件。迁移前创建 PostgreSQL custom dump；任何 schema 回滚先在隔离恢复库演练。

