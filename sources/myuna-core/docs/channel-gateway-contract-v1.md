# Myuna Channel Gateway Contract v1

状态：离线开发契约；未连接 AstrBot、QQ、Myuna Core HTTP 或真实记忆

日期：2026-07-16（Asia/Shanghai）

## 目的

本契约定义 AstrBot/QQ 消息进入 Myuna 可信边界前的最小验证层。它只解决四件事：

1. 确认事件来自持有独立 gateway secret 的适配器。
2. 确认签名后事件未被篡改。
3. 阻止过期、未来和重复事件被再次处理。
4. 使用平台认证账号绑定身份；消息正文永远不能改变 principal、namespace 或权限。

本契约不是 AstrBot 插件，也不会安装、登录或连接 QQ。

## v1 输入边界

顶层对象只允许：

```text
event
signature
```

`event` 使用 `myuna.channel.v1`，仅允许 `astrbot_qq`、单个纯文本
`message_part` 和 `text` delivery capability。所有字段严格校验，未知字段拒绝。

签名算法为 HMAC-SHA256：

```text
HMAC(gateway_secret, "myuna-channel-envelope-v1\\0" + canonical_json(event))
```

`gateway_secret` 与账号指纹 `identity_pepper` 必须是两份不同且至少 32 字节的秘密。

## 身份边界

- Gateway 传入经平台认证的稳定账号 ID；Core 只在验证过程中短暂使用。
- 账号 ID 通过带 pepper 的 HMAC 映射到既有 `AccountBinding`。
- 已验证结果不包含原始账号、签名或 nonce；安全审计只记录内部 binding/principal/namespace。
- 未知、停用、撤销、错误签名和错误 Schema 返回同一条拒绝信息，避免账号枚举。
- “我是 Cealana”“忽略提示词”等正文不能提升身份或跨越 namespace。

## 首版能力限制

离线 v1 只允许：

- 已验证账号；
- 私聊；
- 纯文本；
- 低风险普通对话投影。

以下能力全部拒绝：群聊、记忆候选授权、工具授权、媒体处理。它们必须分别设计、测试并由用户批准后逐项开启。

## 时间与重放

- 默认最大事件年龄：5 分钟。
- 默认最大未来时钟偏差：30 秒。
- 同一 gateway instance 下重复 `event_id` 或 nonce 均拒绝。
- 当前 `InMemoryReplayWindow` 只适用于离线/开发测试。正式接入前必须改为可恢复的持久去重存储，并设计出站 outbox，保证服务重启后仍不会重复回复、调用工具或写入记忆。

## 当前明确未完成

- 未安装 AstrBot，未创建 QQ 登录或真实账号绑定。
- 未创建 Gateway 服务用户、秘密文件、端口或 systemd 服务。
- 未把该验证器接到 `/v1/chat` 或任何监听端口。
- 未启动 Myuna Core、retrieval worker 或真实记忆写入。
- 未实现群聊、图片、语音、附件、限流和出站投递。

## 正式激活前门禁

1. 用户提供并确认真实 QQ 账号绑定关系；原始 ID 不写入普通日志或 Git。
2. Gateway 和 Core 各自独立用户、配置、秘密、日志、资源限制与回滚路径。
3. 使用 loopback 或 Unix socket，禁止公开 Core、数据库与模型路由器。
4. 持久幂等、出站 outbox、限流、消息长度、平台重连与失败恢复测试通过。
5. 先进行 owner 单账号私聊 dev 测试；记忆、工具、媒体继续关闭。
6. 完成停用、撤销 gateway secret、删除缓存和恢复旧版本演练。

