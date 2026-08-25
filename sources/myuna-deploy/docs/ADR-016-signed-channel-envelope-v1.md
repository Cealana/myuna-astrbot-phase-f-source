# ADR-016：Channel Gateway 签名、身份解析与重放边界 v1

状态：离线契约与 Mock 测试已实现；真实 AstrBot/QQ 激活延期

记录日期：2026-07-16（Asia/Shanghai）

## 背景

ADR-009 确定 AstrBot 只作为 QQ 接口层，ADR-015 确定平台账号必须经过可信
gateway 身份解析。本 ADR 记录这两项决策的第一版可执行边界。

BitLocker、Secure Boot、TPM 与重启后服务恢复检查已经通过，但磁盘加密完成并不自动
授权接入真实 QQ、创建真实身份或开放 Core。当前仍遵循最小激活原则。

## 决策

Core 增加平台无关的 `myuna.channel.v1` 签名 envelope 验证器，第一种 channel 为
`astrbot_qq`。Gateway 和账号身份分别使用两份不同秘密：

- `gateway_secret`：验证消息来源和完整性的 HMAC-SHA256 密钥。
- `identity_pepper`：把平台稳定账号 ID 映射为不可逆账号指纹。

只有签名、时间窗口、Schema、对话种类、授权位、身份绑定和重放检查全部通过后，
才产生内部 `VerifiedChannelMessage`。

## v1 安全属性

- Schema 严格匹配；未知字段拒绝。
- 默认事件有效期 5 分钟，最大未来时钟偏差 30 秒。
- 同一 channel instance 下，重复 event ID 或 nonce 均拒绝。
- 账号由平台认证 ID 决定；正文中的名字、提示词或身份声明不参与身份解析。
- 未知、禁用、撤销、签名错误和格式错误使用同一条通用拒绝信息。
- 原始平台账号、签名、nonce 和账号指纹不进入普通审计输出。
- v1 只接受私聊纯文本；群聊、记忆、工具和媒体授权全部关闭。
- 当前 replay window 仅为进程内开发实现；正式激活必须使用持久幂等存储。

## 测试结论

Core 完整测试集共 95 项通过，其中 10 项是本次新增的 gateway 边界测试，覆盖：

- owner 正常解析；
- friend 在正文中冒充 owner 仍保持 friend 身份和 namespace；
- 消息篡改、错误 secret、过期和未来事件；
- event ID 与 nonce 重放；
- 未知和停用账号；
- 群聊和未批准 consent；
- 严格 Schema、秘密分离、审计脱敏和无身份 prompt 投影。

测试只使用合成账号与合成秘密，没有真实 QQ ID、真实身份绑定、真实记忆或外部调用。

## 当前未激活项

- 不安装、不启动 AstrBot。
- 不登录 QQ，不创建 owner/friend 真实账号绑定。
- 不建立 gateway secret、systemd 服务、容器、端口或防火墙规则。
- 不将验证器接到 Core HTTP，不启用 Core 或 retrieval worker。
- 不写入或导入真实长期记忆。

## 后续激活顺序

1. 用户确认 AstrBot 安装方式、QQ 登录方式和真实 owner 账号。
2. 建立独立 gateway 用户、凭据、持久幂等/outbox 与资源限制。
3. 在 loopback 或 Unix socket 上连接一个不含记忆与工具权限的 Core dev 入口。
4. 先以 owner 单账号私聊运行，检查断线、重连、重复投递、限流与回滚。
5. 用户逐项批准后，才考虑记忆候选、图片、多账号和群聊。

## 回滚

本阶段没有运行服务或真实数据。代码回滚只需将 Core 仓库恢复到本 ADR 对应提交的
前一个提交；Deploy 仓库仅删除本 ADR。因为未配置端口、服务和秘密，不需要修改
Windows 防火墙、systemd、QQ 或数据库。
