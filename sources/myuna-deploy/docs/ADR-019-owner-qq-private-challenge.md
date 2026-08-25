# ADR-019：QQ 私聊 owner 挑战与 AstrBot fail-closed 边界

状态：适配器可安装；真实身份写入、挑战激活与 verified 提升均需分开批准

记录日期：2026-07-16（Asia/Shanghai）

## 身份边界

AstrBot 管理用户名 `Cealana` 只用于登录本机 AstrBot WebUI，不能证明 QQ 消息发送者是
owner。Myuna 独立 QQ 账号是 channel endpoint；Cealana 的个人 QQ 账号必须通过隐藏录入、
HMAC 指纹和一次性私聊挑战才能形成 verified binding。

原始 QQ ID 不进入 Git、命令参数、Markdown、日志或数据库。数据库只保存由独立 identity
pepper 生成的 HMAC-SHA256 指纹。

## AstrBot 插件

`astrbot_plugin_myuna_gateway` 以高于内置 handler 的优先级截断全部 AIOCQHTTP/OneBot
事件，并立即执行：

- `event.should_call_llm(False)`；
- `event.stop_event()`。

群聊被静默丢弃。私聊只允许纯文字，并转换为签名的 `myuna.channel.v1` 信封。插件使用
只读挂载的 channel signing credential 和只读 Unix socket 目录；它没有 PostgreSQL
socket、Myuna Core endpoint、provider 配置、记忆权限或工具权限。

AstrBot 官方事件 API 将 `get_sender_id()` 定义为发送者 ID 接口，并提供私聊、平台适配器
过滤及停止后续事件传播的能力：

- https://docs.astrbot.app/dev/star/guides/listen-message-event.html
- https://docs.astrbot.app/dev/star/resources/astr_message_event.html

## Challenge runner

`myuna-channel-gateway-dev.socket` 由 systemd 创建
`/run/myuna-gateway/challenge.sock`，socket 本身为 `root:myuna-gateway 0660`。父目录不可由
AstrBot 容器改写，容器只能连接现有 socket。

Runner 以 `myuna-gateway` 运行，通过 systemd `LoadCredential=` 读取 channel signing key
与 identity pepper。它使用与当前 Myuna Core 相同的只读 `channel_gateway.py` 和
`identity.py` 快照验证：

1. schema、签名与 5 分钟时间窗；
2. private/text-only；
3. memory、tools、media consent 全部为 false；
4. durable event/nonce replay claim；
5. 发送者 HMAC 指纹与 pending binding 一致；
6. 私聊文字与一次性挑战码一致。

Gateway 数据库角色仍只能调用已审核的 `SECURITY DEFINER` 函数，不能读取 identity、
memory 或任何业务表。Operational table 只保存不透明 event ID、nonce 指纹、payload
hash、时间和通用结果代码，不保存 QQ ID、消息正文、签名或原始 nonce。

## 三道独立批准

1. 提交 `pending` principal、namespace、binding，并生成一次性挑战码；
2. 用户从已隐藏录入的个人 QQ 向 Myuna QQ 发送挑战码；
3. 核对挑战证据后，单独批准将 principal/namespace 置为 active、binding 置为 verified。

第二步成功不能自动执行第三步。第三步前 Myuna Core、长期记忆、模型与工具仍不接入 QQ。

Pending 写入使用固定批准 digest 的本机交互工具；工具必须创建并校验提交前/后逻辑备份，
并把校验副本同步至 C 盘关键备份目录。操作说明见
`docs/OWNER_QQ_PENDING_APPLY_GUIDE.md`。

## 合成演练

安装后可在真实 identity 行仍为 0 且所有挑战门禁文件不存在时运行：

```bash
sudo /srv/myuna/repos/deploy/scripts/rehearse_owner_challenge_adapter.py
```

该演练只生成虚构账号和随机挑战码，实际经过 systemd socket、签名验证、PostgreSQL
durable replay claim 和 evidence 写入，然后停止服务并删除合成 operational row、门禁文件和
evidence。它不得读取或推断真实 QQ ID。

## 当前 fail-closed 状态

仅安装适配器时：

- 插件会阻止 AstrBot 调用任何模型；
- socket unit 和 service 均 disabled/inactive；
- activation marker 与 challenge config 不存在；
- 真实 identity 行仍为 0；
- 私聊只会收到“身份验证尚未开放”的固定回复。

## 回滚

```bash
sudo systemctl stop myuna-channel-gateway-dev.socket myuna-channel-gateway-dev.service
sudo rm -f /etc/myuna-gateway/activation-approved
sudo docker compose \
  --env-file /etc/myuna-gateway/astrbot-napcat-dev.env \
  -f /srv/myuna/repos/deploy/channels/astrbot-qq/compose.dev.yml \
  up -d --no-deps --force-recreate astrbot
```

删除 pending/verified identity 行属于独立数据库变更，必须使用对应备份和审核脚本；不得用
容器重建代替身份数据回滚。
