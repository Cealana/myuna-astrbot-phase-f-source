# AstrBot + NapCat dev 操作说明

本栈是 Myuna 的 QQ 接口层，不是人格、模型路由器或记忆数据库。

## 固定版本

- AstrBot `v4.26.6`：`sha256:7546bddf1040419a455dd1ca683a5e9cf84436bbd85de17c7ac626d3af7affe4`
- NapCat `v4.18.9`：`sha256:32891e1f5aa654ef84fb4fcfb1724b4d844a26c2fcb11519945e64e22d13e766`

升级必须修改 digest、记录变更并先完成 dev 回归；禁止自动使用 `latest`。

## 目录

```text
/srv/myuna/channels/astrbot-qq/dev/
├── astrbot-data/
├── napcat-config/
├── napcat-qq/
├── shared-media/
└── backups/
```

运行秘密位于 `/etc/myuna-gateway/secrets/`，不进入 Git、聊天、命令参数或普通备份。

## 启停

```bash
sudo systemctl start myuna-astrbot-qq-dev.service
sudo /srv/myuna/repos/deploy/scripts/channel_stack_status.sh
sudo systemctl stop myuna-astrbot-qq-dev.service
```

初始阶段 unit 保持 disabled；Windows/WSL 重启后不会自动登录 QQ，直到用户完成测试并
单独批准开机启动。

## 本地 WebUI

- AstrBot：`http://127.0.0.1:6185`
- NapCat：`http://127.0.0.1:6099/webui`

AstrBot 初始用户名是 `astrbot`。把仅在首次日志中出现的初始密码复制到本地
Windows 剪贴板：

```bash
/srv/myuna/repos/deploy/scripts/copy_channel_secret_to_clipboard.sh astrbot-initial
```

登录后立即修改管理密码；不要把初始密码发送到聊天。

NapCat WebUI token 不应打印。需要时在本机 WSL root 终端执行：

```bash
/srv/myuna/repos/deploy/scripts/copy_channel_secret_to_clipboard.sh napcat-webui
```

配置 AstrBot 的 OneBot v11 adapter 时，使用以下命令把相同的内部连接 token 复制到
Windows 剪贴板：

```bash
/srv/myuna/repos/deploy/scripts/copy_channel_secret_to_clipboard.sh onebot
```

粘贴后应立即用普通文本覆盖剪贴板。

## 首次配置顺序

1. 启动 unit，打开 AstrBot WebUI，登录后立即修改初始管理密码。
2. 在 AstrBot 创建 OneBot v11 adapter：监听容器内 `0.0.0.0:6199`，配置内部 token。
3. 打开 NapCat WebUI，使用 Myuna 的独立 QQ 账号扫码登录。
4. 确认 NapCat 反向 WebSocket 已连接 `ws://astrbot:6199/ws`。
5. 只由 Cealana 发起一条指定私聊挑战；不要添加朋友或群聊测试。
6. 验证 sender ID 指纹后，再进行 pending owner 绑定审批。

AstrBot 在本阶段不得配置 DeepSeek/OpenAI provider；所有正式模型调用仍由 Myuna
Model Router 管理。

## 日常控制

```bash
sudo systemctl start myuna-astrbot-qq-dev.service
sudo systemctl stop myuna-astrbot-qq-dev.service
sudo docker logs --tail 100 myuna-astrbot-dev
sudo docker logs --tail 100 myuna-napcat-dev
```

日志可能含平台事件元数据。不要把完整日志直接粘贴到聊天，先使用脱敏检查工具。

## 备份

备份前先停止 unit，再备份以下目录：

- `astrbot-data`
- `napcat-config`
- `napcat-qq`

QQ 登录状态属于敏感凭据，只进入加密备份；普通 C 盘工程备份不得包含它。

## 紧急断开与回滚

```bash
sudo systemctl stop myuna-astrbot-qq-dev.service
```

确认 6099/6185 不再监听。只有在明确决定卸载时才执行 Compose `down`；不要使用
`down -v`，不要删除 channel 目录，也不要删除 QQ 登录状态。
