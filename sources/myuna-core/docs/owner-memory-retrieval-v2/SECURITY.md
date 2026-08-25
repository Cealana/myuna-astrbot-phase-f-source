# Owner Memory Retrieval v2 安全合同

## 固定不变量

- 数据 namespace 固定为 `ns-owner-cealana-private`。
- 只允许 `sensitivity=normal`。
- 只允许 `confirmation_level=user_confirmed`。
- 只读：`memory_write_performed=false`。
- 无模型：`model_called=false`。
- `restricted_included=false`。
- 近期最多 1 条，深度最多 3 条。
- 请求上限 256 字符 / 4096 bytes；响应上限 65536 bytes。
- 错误响应不回显查询或记忆正文。
- 审计投影只包含 fingerprint、意图、范围、分数、原因码和内部 memory ID。

## 双重校验

Worker 先应用边界；Core Adapter 再验证响应。即使未来 Worker 出现缺陷，Core 仍会拒绝：

- restricted 记录；
- 非用户确认记录；
- namespace、boundary 或 policy 不匹配；
- 重复/不一致的 hit ID；
- 超过范围上限的记录；
- 声称调用模型或写入记忆的响应。

## 当前没有获得授权的能力

- 自动记忆写入；
- restricted 检索；
- History Archive 检索；
- Shadow Memory 读取；
- 向量模型或云端模型调用；
- QQ 激活；
- systemd 安装；
- 数据库或网络修改。
