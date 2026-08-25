# Myuna NapCat 卡死登录恢复工具 v1

用途：清理 `QQ is logined`、QQ 已离线但 NapCat/OneBot 仍保持空壳连接等状态。

安全边界：

- 只重启 `myuna-napcat-dev` 容器；
- 不重启 AstrBot 或 Myuna Core；
- 不删除 `/app/.config/QQ`、`/app/napcat/config` 或任何会话文件；
- 执行前验证两个持久化 bind mount；
- 如果 QQ 已在线，执行结果为 no-op；
- 默认 30 分钟冷却，防止反复重启触发 QQ 风控；
- 安全验证或二维码仍必须由用户完成；
- 输出和事件记录不包含 QQ 号、WebUI 密钥、二维码或消息。

Windows 双击入口：

```text
C:\Server-Admin\Myuna\Recover-Myuna-QQ.cmd
```

只读检查：

```text
wsl.exe -d Server-Ubuntu --user root -- python3 /srv/myuna/repos/deploy/scripts/recover_napcat_stuck_login.py
```

执行恢复：

```text
wsl.exe -d Server-Ubuntu --user root -- python3 /srv/myuna/repos/deploy/scripts/recover_napcat_stuck_login.py --execute
```

退出码：

- `0`：已在线、无需操作，或自动恢复成功；
- `2`：NapCat 卡死状态已清理，但需要人工扫码/安全验证；
- `1`：安全前置条件不满足，失败关闭。
