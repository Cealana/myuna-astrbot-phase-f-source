# Owner QQ 身份预览操作说明

本工具只生成事务预览，最终一定 ROLLBACK。不要把 QQ 号发到聊天、Markdown、命令参数
或截图中。

## 使用时间

在 Codex 完成 Gateway foundation 验证，并明确告诉你可以录入后再执行。执行时应在
服务器本机的管理员 PowerShell 中打开 Ubuntu：

```powershell
wsl.exe -d Server-Ubuntu --user root
```

进入 Ubuntu 后运行：

```bash
/srv/myuna/repos/deploy/scripts/preview_owner_binding.py
```

工具会要求隐藏输入同一个 QQ ID 两次。屏幕不会显示输入内容。

## 正常结果

- 显示固定的 principal、namespace、binding ID。
- 只显示账号 HMAC 指纹的前后各 8 位。
- 显示三个 `rows_after_rollback` 均为 0。
- 最后一行明确说明没有提交真实 binding。

如果任何服务正在运行、两次输入不同、账号格式异常、secret 权限异常、数据库约束冲突
或输出可能泄漏完整指纹，工具都会拒绝。

## 预览之后

把屏幕上的 `plan_digest` 和三个 rollback 计数告诉 Codex即可，不要提供 QQ ID 或完整
fingerprint。Codex 会核对数据库仍为零真实身份，然后准备单独的 pending 写入审批。
