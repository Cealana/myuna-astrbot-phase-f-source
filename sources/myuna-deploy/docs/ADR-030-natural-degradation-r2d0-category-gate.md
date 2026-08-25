# ADR-030: Natural Degradation R2D-0 Category Gate

状态：candidate / repository-only / inactive

## 决策

在任何 Natural Degradation 文案进入真实 QQ 可见路径前，增加一个确定性的 category gate。

默认策略的 `enabled_categories` 必须为空，因此应用此候选本身不会改变任何生产回复。一个类别只有同时携带：

- 合格的 category-scoped R3D evidence receipt SHA-256；
- Owner 单独批准的 live activation plan digest；

才有资格进入后续可见策略。模块不会读取 R3D trace，也不会根据观察结果自动晋级。

## 边界

- 输入必须先通过现有 `myuna.safe-degradation.v1` 严格验证；
- 输出只能是 `legacy_unavailable` 或现有 typed `safe_degraded_reply`；
- 空 allowlist 对所有类别保留旧 fallback；
- `recovered` 通知不属于 R2D-0；
- QQ/OneBot 离线和 host/network 不可达无法从同一 QQ 通道发送，R2D-0 明确禁止启用；
- 不使用模型重写错误信息；
- 不读取消息、Prompt、模型输出、记忆、日志、凭据或账号信息；
- 不修改 Gateway、AstrBot、Core 或 systemd 的活动接线。

## 后续

真实 R3D 类别出现后，应先生成只读 evidence review。随后用新 digest 创建只包含一个类别的 narrow live activation；激活失败立即恢复旧 `owner-runtime-unavailable` 路径。

