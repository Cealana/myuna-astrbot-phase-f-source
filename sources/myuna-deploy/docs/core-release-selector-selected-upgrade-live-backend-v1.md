# Selected Core Upgrade fixed live backend v1

该模块将 selected-to-selected 升级状态机连接到固定的 Core/QQ Gateway unit 与固定四文件目标。所有 systemctl 动作、unit、路径、loopback 健康端点和 verifier 调用均为代码内 allowlist；调用者不能提供命令、unit、路径或 Shell。

本阶段仅将实现与测试加入仓库。没有 CLI 入口、没有安装、没有执行器 release，也不会调用该后端。内容寻址打包、inactive 安装、只读 live preflight 和最终 activation 均须独立审批。

后端只允许变更：Core binding、selector drop-in、`qq.env`、Telegram credential drop-in，以及固定 Core/QQ Gateway 生命周期。目标验证包括不可变 release 证据、systemd WorkingDirectory、loopback `/healthz`/`/readyz` 和 Selector `verify-active`。
