# ADR-009：AstrBot 作为 Myuna 的 QQ 接口层

状态：用户已确认方向；仅记录架构边界，实施与配置延期
记录日期：2026-07-15（Asia/Shanghai）

## 决策

未来使用 AstrBot 作为 Myuna 接入 QQ 的 gateway/channel adapter。AstrBot
只负责 QQ 平台事件与 Myuna 内部消息协议之间的转换，不作为 Myuna Core、
人格系统、长期记忆系统、模型路由器或工具执行器。

```text
QQ
→ AstrBot / QQ Channel Adapter
→ 版本化的 Myuna Channel Gateway API
→ Myuna Core
→ Definition / Memory / Model Router / Policy
→ Myuna Core response
→ AstrBot
→ QQ
```

该决定不会把 Myuna 锁定到 QQ 或 AstrBot。未来 Web、移动端、语音、Discord
或其他平台应通过相同的 `ChannelAdapter` 边界接入。

## AstrBot 层可以负责

- 接收 QQ 私聊、群聊、回复关系、图片和其他平台事件。
- 将平台事件标准化为内部版本化消息 envelope。
- 将 Myuna 的结构化输出转换为 QQ 可发送的文本、回复和媒体动作。
- 维护 QQ 平台专用的账号、登录状态、连接、重连和发送限速。
- 执行事件去重、重放保护、群聊触发规则、白名单和平台级审计。
- 在用户以后配置时，保存 AstrBot 自身确实需要的平台配置。

## AstrBot 层不得负责

- 定义或修改 Myuna 的身份、人格、价值观和表达核心。
- 自己决定应写入、压缩、确认、纠正或删除哪些长期记忆。
- 直接选择 DeepSeek、OpenAI 或本地模型并绕过 Model Router。
- 持有云模型 API Key、数据库超级权限或 Windows 管理员权限。
- 直接调用高风险工具、修改服务器、防火墙、Minecraft 或数据库。
- 将 QQ 全量聊天记录无条件导入 Myuna 的个人记忆。
- 把群成员身份、群消息或媒体默认视为用户授权的个人记忆。

## 内部协议预留

实际 Schema 在实施前单独评审，但至少预留：

```text
schema_version
event_id
channel
channel_instance
actor_id
conversation_id
conversation_kind
timestamp
message_parts
reply_to
attachments
delivery_capabilities
consent_context
trace_id
```

- `channel` 对 QQ/AstrBot 使用稳定的适配器标识，而不是写进 Core 分支逻辑。
- QQ 原始账号与内部 actor ID 的映射属于 gateway 私有数据；Core 优先接收
  经过作用域隔离或伪名化的标识。
- 每个入站事件必须有可去重的 `event_id`，避免重连或重试造成重复回答、
  重复工具调用或重复记忆写入。
- 文本、图片、语音和文件使用统一 `message_parts` 扩展，而不是为 QQ 写一套
  不可复用的 Myuna Core 输入格式。
- 出站响应必须带 trace/delivery identity，发送失败与模型失败分开记录。

## 记忆与隐私边界

- QQ 只是消息来源之一，进入 QQ 的消息不会自动成为长期记忆。
- 私聊、群聊、他人发言、转发内容和媒体必须保留来源与参与者边界。
- 群聊默认采用更严格的记忆候选与主动回复策略；其他群成员的个人信息不能
  因用户在场就自动写入用户个人记忆。
- 平台原始事件可以按保留策略进入 gateway operational records；这类记录与
  Myuna 的个人记忆分离。Myuna 按权限查阅时应表达为“我查看了记录”，而不是
  “我记得”。
- 用户以后应能按 channel/conversation 范围关闭记忆候选、媒体处理或主动回复。

## 部署与权限边界

实施时优先采用独立服务边界，例如：

```text
myuna-gateway-astrbot
```

它应拥有独立的：

- 运行用户或容器身份。
- 配置、日志、缓存和秘密。
- cgroup 资源限制与重启策略。
- 健康检查和审计事件。
- 版本、回滚和升级路径。

Gateway 与 Core 优先通过 loopback、Unix Socket 或其他仅内部可达的认证接口通信。
不得为了 QQ 接入而直接公开 Myuna Core、PostgreSQL、Redis、模型路由器或管理接口。
实际端口、AstrBot 版本、QQ 连接实现、容器化方式和网络入口在部署阶段重新调查，
本 ADR 不提前写死。

## 实施顺序

AstrBot 不属于当前 DeepSeek API 门禁。建议顺序为：

1. 完成 DeepSeek 一次性真实 API 冒烟。
2. 形成并批准 Definition runtime release 与 Golden Conversations。
3. 建立一个平台无关的 Core conversation/channel contract。
4. 先通过本地 Mock Channel 验证身份、会话、限流、去重和记忆边界。
5. 再安装 AstrBot，并由用户完成 QQ 平台配置。
6. 先启用单用户私聊 dev 测试，再考虑群聊与媒体。
7. 通过安全、隐私、故障回退和卸载演练后才进入长期运行。

## 激活门禁

正式接入 QQ 前至少需要：

- 用户确认 AstrBot/QQ 的实际登录和合规风险。
- 明确允许的 QQ 账号、好友、群和触发方式。
- 独立 gateway secret 与 Core 身份认证方案。
- 入站事件去重、出站限流、消息长度和附件限制。
- 群聊隐私、记忆候选、图片路由和敏感内容策略。
- QQ 或 AstrBot 离线时不影响 Myuna Core 的其他入口。
- Gateway 被攻破时不能直接获得模型密钥、记忆数据库写权限或系统工具权限。
- 完整停止、禁用、撤销凭据和删除平台缓存的回滚说明。

在这些门禁完成前，AstrBot 只是一项已记录的未来接口，不安装、不启用、不分配端口。
