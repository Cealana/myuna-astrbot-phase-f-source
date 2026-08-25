# Selected Core Upgrade inactive transaction installer v1

该安装器只把已通过纯合同验证的 selected-to-selected 事务安装到独立内容寻址目录，并写入非敏感回执。它不复用旧 R4C transaction、Executor 或 activation Journal。

安装器不会调用 systemd、不会选择 Core release、不会读取 Secret，也不会启动 QQ 或 Telegram。目标树、activation plan 与安装批准摘要必须全部精确匹配；已有目录只有逐字节一致时才允许幂等复核。

本阶段为 repository-only 合同。安装 `0c58d329...` 事务需要新的明确审批。
