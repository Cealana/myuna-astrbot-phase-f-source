# Future System Modularity Review

状态：`deferred_backlog`，不是执行授权。

Owner 提议未来重新遍历现有服务器与 Myuna 设计，检查是否存在类似“多个责任混在一个
模块、出错后难以定位”的结构。开始该审查前必须明确通知 Owner；届时可以考虑切换到
Ultra 推理强度。

建议审查顺序：

1. QQ/AstrBot/NapCat：账号在线状态、OneBot 链路、WebUI 状态与恢复动作分离。
2. Reply Contract：供应商调用、格式解析、修复、能力守卫和连续性兜底继续保持分层。
3. Turn Manager：消息聚合、等待窗口、自然静默和最终回复决策分离。
4. Model Router：任务分类、预算、供应商健康与最终路由分离。
5. Memory：Archive、Owner Memory、写入候选、复核、检索和 Prompt 注入分离。
6. Recovery Controller：观察、诊断、自动修复、需要 Owner 的动作与通知分离。
7. Minecraft：服务生命周期、备份、隧道网络和游戏规则管理分离。
8. OpenClaw：外部入口、审批、策略、执行 Playbook 和审计分离。

该审查不得因为被记录在此文件中而自动启动、修改服务或提高权限。
