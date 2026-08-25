# Server BU 每日备份控制说明

## 日常行为

- Windows 计划任务 `MyunaServer-Daily-USB-Backup` 每天 05:30 运行。
- 若 U 盘缺失、盘符不是 `E:`、设备身份不一致、健康异常或剩余空间低于 5 GiB，任务会失败关闭，不会改写其他盘。
- 成功快照位于 `E:\Myuna-Server-Backup\snapshots\<UTC 时间>`。
- 每个快照包含五个 `.gpg` 加密载荷、`MANIFEST.json`、`SHA256SUMS` 和 `COMPLETE`。
- 清单和校验值不含消息正文、账号标识、Token、密码或恢复密钥。

## 手动执行

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Server-Control\Backup-MyunaServerToUsb.ps1"
```

查看最近结果：

```powershell
Get-Content "C:\Server-Admin\Myuna\backups\usb-daily\LAST_SUCCESS.json"
Get-ScheduledTaskInfo -TaskName "MyunaServer-Daily-USB-Backup"
```

## 恢复密钥

恢复密钥不在 U 盘上。服务器内副本位于：

`C:\Server-Critical-Backup\Myuna\usb-backup\archive-passphrase-v1.txt`

该目录继承已关闭，只允许当前 Windows 用户、SYSTEM 与 Administrators 访问；C 盘本身由 BitLocker 保护。请把密钥再保存到一台可信设备或密码管理器。不要把它与 U 盘放在一起，也不要发送到聊天中。

## 手工恢复检查

在隔离目录中使用 GnuPG 解密：

```text
gpg --batch --pinentry-mode loopback --passphrase-file <密钥文件> --decrypt --output <恢复文件> <载荷.gpg>
```

- PostgreSQL 载荷先运行 `pg_restore --list`；正式恢复前创建空演练数据库。
- `.tar.gz` 载荷先运行 `tar -tzf`，确认目录与清单相符后再解压。
- Minecraft 载荷先比较清单中的 SHA-256，再在服务器停服状态下恢复。
- 不要把快照直接覆盖到正式环境；先恢复到隔离目录并核对。
