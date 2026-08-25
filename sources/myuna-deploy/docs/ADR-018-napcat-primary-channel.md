# ADR-018：NapCat 主 QQ 通道与官方机器人备用通道

状态：用户已选择；dev 部署获准，真实 owner 激活仍需私聊挑战

记录日期：2026-07-16（Asia/Shanghai）

## 决策

Myuna 的首个 QQ 通道使用独立普通 QQ 账号，通过 NapCat 与 OneBot v11 接入
AstrBot。QQ 官方机器人保留为备用适配器，但不在本阶段同时登录或运行。

```text
Cealana 的个人 QQ
→ Myuna 的独立 QQ 账号
→ NapCat / OneBot v11
→ AstrBot channel adapter
→ Myuna signed gateway boundary
→ Myuna Core
```

Myuna 不使用 Cealana 的个人 QQ 登录。Cealana 的 QQ 只用于发送消息以及解析为
`principal-owner-cealana`；Myuna 的 QQ 是 channel instance，不是 owner principal。

## 选择原因

- 对少量好友而言，独立普通 QQ 账号更接近长期好友式交互。
- NapCat 提供稳定的数字 QQ sender ID，适合当前 HMAC 身份指纹契约。
- OneBot v11 的私聊、群聊和媒体接口较完整。
- AstrBot 与 Myuna Core 之间仍保留版本化、可替换的 adapter 边界。

## 已接受风险

NapCat 依赖 NTQQ 客户端能力，不是腾讯官方机器人 API。QQ 或 NapCat 更新可能造成
登录、协议或媒体兼容变化，也存在账号风控风险。因此：

- 只使用 Myuna 的独立账号，不使用 Cealana 主账号登录 NapCat。
- 初期只允许 Cealana 单人私聊，不做群发、批量加好友或高频主动消息。
- 镜像固定到已审核 digest，不自动追随 `latest`。
- 每次升级先备份登录状态和配置，再在 dev 中验证。
- 官方 QQ 机器人 adapter 保持可替换的备用方案。

## 身份激活门禁

手工输入数字 QQ ID 只能创建 `pending` 候选。正式 owner 绑定还必须满足：

1. NapCat 与 AstrBot 使用认证的内部 WebSocket 连接。
2. Cealana 从自己的 QQ 向 Myuna 独立账号发起私聊挑战。
3. 运行时事件的稳定 sender ID 计算出的指纹与本地候选一致。
4. 一次性挑战成功，且事件未重放、未过期。
5. 用户单独批准 pending 写入和 verified 转换。

消息正文、昵称、备注、群名片或“我是 Cealana”等文本永远不能改变 principal。

## 部署边界

- AstrBot WebUI 仅发布到 `127.0.0.1:6185`。
- NapCat WebUI 仅发布到 `127.0.0.1:6099`。
- OneBot `6199` 只存在于专用 Docker bridge，不发布到宿主机。
- AstrBot 不持有 DeepSeek/OpenAI 密钥，不直接访问 PostgreSQL，不拥有工具权限。
- 当前 Myuna Core、retrieval worker 与 signed gateway 保持 disabled/inactive。
- 本阶段不启用群聊、图片、长期记忆写入或主动消息。

## 回滚

停止 `myuna-astrbot-qq-dev.service` 即可断开 QQ 通道，不影响 Minecraft、
PostgreSQL 或 Myuna 的其他入口。不要在未备份时删除 NapCat QQ 登录状态目录。

