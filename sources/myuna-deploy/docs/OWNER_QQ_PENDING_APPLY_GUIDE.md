# Owner QQ pending 写入与一次性挑战操作说明

本操作已绑定到用户明确批准的：

```text
e2658ee4e54a665b55007820d8c733cf3720fde60a3c24a1c12c8a4df6fe1dee
```

脚本只允许创建以下状态：

- `principal-owner-cealana`：`pending`；
- `ns-owner-cealana-private`：`pending`；
- `binding-astrbot-qq-owner-cealana`：`pending`。

它不会把任何记录设为 `active` 或 `verified`，也不会启动 Myuna Core、长期记忆、模型或
工具。

## 本机执行

在服务器本机管理员 PowerShell 中进入 WSL root：

```powershell
wsl.exe -d Server-Ubuntu --user root
```

然后运行：

```bash
/srv/myuna/repos/deploy/scripts/apply_owner_binding_pending.py \
  --approved-plan-digest e2658ee4e54a665b55007820d8c733cf3720fde60a3c24a1c12c8a4df6fe1dee
```

脚本要求隐藏输入 Cealana 的个人 QQ 号两次。输入不会显示，也不得把 QQ 号放进聊天、
命令参数、截图或日志。

脚本会依次：

1. 核对 Core、retrieval 和 challenge gateway 均未运行；
2. 核对 AstrBot/NapCat 健康；
3. 核对真实 identity 行仍为 0；
4. 核对隐藏输入生成的 plan digest 与批准值完全一致；
5. 在 D 盘 WSL 虚拟磁盘内的 `/var/backups/postgresql/` 创建并验证提交前 PostgreSQL
   custom-format backup；
6. 提交三条 `pending` 记录；
7. 生成一小时有效的一次性挑战码，但不打印；
8. 只启动 challenge Unix socket；
9. 创建并验证提交后 backup；
10. 将两份 backup 的校验副本写入 C 盘关键备份目录。

任一步骤在成功结束前失败时，脚本会停止 challenge socket、删除挑战文件，并只按批准
digest 删除刚创建的三条 `pending` 记录。它不会使用 `DROP`、`TRUNCATE` 或数据库整体
恢复作为普通失败回滚。

## 发送一次性挑战

脚本成功后，不要把输出中的任何秘密发给 Codex；正常输出本身不包含 QQ 号或挑战码。

在同一个 WSL root 终端执行：

```bash
/srv/myuna/repos/deploy/scripts/copy_channel_secret_to_clipboard.sh owner-challenge
```

然后在 QQ 中打开 Cealana 个人账号与 Myuna 独立 QQ 账号的私聊，只粘贴这一段挑战码，
不要添加前后文字，并且只发送一次。

成功时 Myuna QQ 固定回复：

```text
身份验证消息已安全接收；本阶段未调用模型、记忆或工具。
```

随后用普通文本覆盖 Windows 剪贴板，并只告诉 Codex“挑战成功”，不要发送挑战码、QQ
号、截图或原始日志。

若收到“未通过验证”或“尚未开放”，不要连续重试；停止并让 Codex检查门禁状态。挑战码
一小时后失效。
