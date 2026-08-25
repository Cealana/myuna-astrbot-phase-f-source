# Selected Core Upgrade Sandbox Backend v1

该合同提供一个明确拒绝真实根目录 `/` 的 sandbox-only 文件系统与 systemd 形状后端。所有文件替换只能发生在测试传入的临时根目录中，服务生命周期只能通过注入式 Fake Runner 执行，目标 Core release 只能通过注入式 Fake Verifier 验证。

候选覆盖 binding、selector drop-in、`qq.env` 和 Telegram credential drop-in 的精确替换与回滚，以及 Gateway/Core 状态恢复和 daemon-reload 计数。

该模块不包含 subprocess、真实 systemctl、网络、数据库、Secret、QQ、Telegram、模型或记忆实现，不能用于 live 激活。真实后端、安装和激活必须属于后续独立合同与审批。
